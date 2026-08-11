// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "eip-8130/Keystore.sol";
import {DefaultAccount} from "eip-8130/accounts/DefaultAccount.sol";
import {Scopes} from "eip-8130/libraries/Scopes.sol";

struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// @notice Example ERC-4337-compatible account for EIP-8130: {DefaultAccount} plus `validateUserOp`, reproducing
///         the 8130 authorization semantics (scope + policy) so an account works on non-8130 chains via a bundler +
///         EntryPoint, identically to native dispatch.
///
///         The EntryPoint is authorized like any other caller: a revocable TRUSTED_EXECUTOR actor in the Keystore
///         (see {DefaultAccount}). A signed account change swaps it for a different address at any time, even on
///         non-upgradeable accounts, and supports any EntryPoint version since the account's CREATE2 address never
///         depends on it.
///
///         ERC-7562: authorizing the caller and authenticating the op both read the account's own associated
///         storage in the Keystore, keeping both within the same validation-phase storage category.
///
///         Bootstrapping: the EntryPoint must already be a TRUSTED_EXECUTOR actor before its first call (gated by
///         `_isAuthorizedCaller`). Seed it into the initial actor set at `createAccount` for a counterfactual
///         account's first op to work out of the box; otherwise register it later via a signed account change.
contract BackwardsCompatible4337Account is DefaultAccount {
    /// @dev Signature discriminator for validation-phase account changes: when `userOp.signature` starts with this
    ///      32-byte magic, it decodes as `abi.encode(magic, Keystore.SignedAccountChanges[] changeSets, bytes opAuth)`
    ///      and each change set is applied in order (e.g. rotating the controlling key to a P-256 actor) before the
    ///      op is authenticated. Each set is a self-describing {Keystore.SignedAccountChanges} (channel + sequence +
    ///      changes + signature) bound to this account by the Keystore, so applying it only ever mutates this
    ///      account's own config — it never authorizes the op itself. The trailing `opAuth` (a plain
    ///      `authenticator || data` blob) must still sign for this exact `userOpHash`, and may come from a key the
    ///      changes just added/rotated to. A signature without the magic prefix is itself treated as the plain
    ///      `opAuth` blob, preserving the base behaviour.
    bytes32 internal constant SIGNED_ACCOUNT_CHANGES_MAGIC = keccak256("ERC4337Account.signedAccountChanges.v1");

    constructor(address keystore) DefaultAccount(keystore) {}

    // ══════════════════════════════════════════════
    //  ERC-4337
    // ══════════════════════════════════════════════

    /// @notice Validates a UserOperation signature via the Keystore. Signature format follows 8130 authenticator
    ///         conventions (authenticator_type || data), and optionally carries signed account changes applied
    ///         during validation (see {SIGNED_ACCOUNT_CHANGES_MAGIC}).
    ///
    /// @dev Reverts with UnauthorizedCaller when the caller is neither the account nor a TRUSTED_EXECUTOR actor
    ///      (typically the EntryPoint).
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();

        validationData = _validateSignature(userOp, userOpHash, missingAccountFunds) ? 0 : 1;

        if (missingAccountFunds != 0) {
            assembly {
                pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0))
            }
        }
    }

    /// @notice Validates `userOp` by authenticating it as a plain authenticator blob over `userOpHash` and
    ///         enforcing the verified actor's scope. A signature carrying signed account changes additionally
    ///         applies them during validation before the op itself is authenticated.
    /// @dev Signed-account-changes path: each set is applied via `applySignedAccountChanges` (empty batch rejected).
    ///      Every slot it writes is keyed by `account`, so under ERC-7562 it's the account's own associated
    ///      storage — allowed by STO-021 for an existing account; only a combined create+change op falls under
    ///      STO-022, requiring the Keystore factory to be staked.
    ///
    ///      Op authentication (both paths) enforces the verified actor's scope:
    ///        - the actor must be unrestricted (scope 0x00) or hold {Scopes.SENDER} to authorize the calls;
    ///        - a self-funded op (`missingAccountFunds != 0`) additionally requires {Scopes.SELF_PAYER}.
    ///      This reduced 4337 bridge does not replicate the native-dispatch policy-target gate: a Scopes.POLICY
    ///      actor without Scopes.SENDER is rejected here by construction (see {_authorize}), and this repo does not
    ///      implement protocol-side lane/exclusivity checks for actors that combine Scopes.POLICY with Scopes.SENDER.
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        internal
        returns (bool)
    {
        bytes calldata signature = userOp.signature;
        bytes memory opAuth = signature;

        if (signature.length >= 32 && bytes32(signature[:32]) == SIGNED_ACCOUNT_CHANGES_MAGIC) {
            Keystore.SignedAccountChanges[] memory changeSets;
            (, changeSets, opAuth) = abi.decode(signature, (bytes32, Keystore.SignedAccountChanges[], bytes));

            if (changeSets.length == 0) return false;

            // Each set is a self-describing Keystore batch bound to address(this) (see SIGNED_ACCOUNT_CHANGES_MAGIC
            // above), so it only ever mutates this account's own config.
            for (uint256 i; i < changeSets.length; i++) {
                try KEYSTORE.applySignedAccountChanges(address(this), changeSets[i]) {}
                catch {
                    return false;
                }
            }
        }

        // Applying changes never authorizes the op; `opAuth` must still sign for this `userOpHash`.
        (bool valid, uint16 scope) = _authenticate(userOpHash, opAuth);
        if (!valid) return false;

        // Authentication only proves WHO signed; authorization decides whether that actor may drive THIS op.
        return _authorize(scope, missingAccountFunds);
    }

    /// @notice Authenticates `auth` over `hash` via the Keystore, resolving the signing actor's scope. This answers
    ///         only "who signed", never "may they do this" — see {_authorize}.
    /// @return valid True if `auth` is a valid signature from a live actor of this account.
    /// @return scope The verified actor's scope (0x00 = unrestricted owner).
    function _authenticate(bytes32 hash, bytes memory auth) internal view returns (bool valid, uint16 scope) {
        // actorId and the policy gate are protocol-side / policy-manager concerns this reduced 4337 bridge does not
        // replicate: a Scopes.POLICY actor is rejected below by the Scopes.SENDER check (see {_authorize}), since
        // this repo does not implement protocol-side lane/exclusivity checks or the policy-commitment gate. The
        // userOpHash is already replay-safe (it binds chainId + EntryPoint + sender), so the op is authenticated
        // directly rather than through the account-scoped signature envelope.
        try KEYSTORE.authenticateActor(address(this), hash, auth) returns (bytes32, uint16 s) {
            return (true, s);
        } catch {
            return (false, 0);
        }
    }

    /// @notice Decides whether an already-authenticated actor may drive this UserOperation, from its scope.
    ///         Split out from {_authenticate} so the two concerns — who signed vs. what they may do — are
    ///         independently reviewable and overridable.
    /// @dev Enforces:
    ///        - scope 0x00 is an unrestricted owner; any other actor must hold {Scopes.SENDER} to authorize the calls;
    ///        - a self-funded op (`missingAccountFunds != 0`) additionally requires {Scopes.SELF_PAYER}.
    ///      A Scopes.POLICY actor without Scopes.SENDER fails the check below by construction — this reduced 4337
    ///      bridge does not give policy-gated actors special call-target enforcement (that is native-dispatch,
    ///      protocol-side behavior out of scope for this repo). An actor combining Scopes.POLICY | Scopes.SENDER is
    ///      authorized here exactly like any other SENDER-scoped actor.
    /// @param scope The verified actor's scope (0x00 = unrestricted owner).
    /// @param missingAccountFunds The prefund the account owes the EntryPoint; non-zero means a self-funded op.
    function _authorize(uint16 scope, uint256 missingAccountFunds) internal view virtual returns (bool) {
        // scope 0x00 = unrestricted owner; otherwise the actor must explicitly hold the required scopes.
        if (scope != 0) {
            if (scope & Scopes.SENDER == 0) return false;
            if (missingAccountFunds != 0 && scope & Scopes.SELF_PAYER == 0) return false;
        }
        return true;
    }
}
