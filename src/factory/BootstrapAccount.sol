// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Receiver} from "solady/accounts/Receiver.sol";

import {AccountConfiguration} from "eip-8130/AccountConfiguration.sol";
import {IBootstrap} from "./IBootstrap.sol";

/// @notice Reference implementation for accounts deployed via `SetDelegateFactory`.
///
///         Self-contained bootstrap (no changes to AccountConfiguration required):
///           - `bootstrap` is the account's own entrypoint. It sets a transient (EIP-1153) latch, drives
///             `AccountConfiguration.importAccount` on itself, then clears the latch — all in one call frame.
///           - While the latch is set (i.e. only during that nested `importAccount`), the ERC-1271 callback is in
///             BOOTSTRAP mode and validates the presented digest against the typed actors hash (and chainId) the
///             factory passed in. The latch lives in transient storage, so it is scoped to the bootstrap
///             transaction and cannot leak into normal operation; it is also cleared explicitly once import returns.
///           - In every other context (latch unset) the implementation defers `isValidSignature` to
///             `AccountConfiguration.verifySignature` for normal operation.
///
///         Why the signature need not be checked in BOOTSTRAP mode: the account has no key. The factory's atomic
///         `SETDELEGATE → bootstrap` sequence makes front-running impossible, and the SETDELEGATE address
///         derivation binds the address to `(factory, salt)` where `salt` already commits to the actor set. The
///         implementation just confirms the import digest AccountConfiguration computed matches the actors the
///         factory primed.
///
///         Minimal reference; production accounts add execution, caller authorization, asset receive hooks, etc.
contract BootstrapAccount is IBootstrap, Receiver {
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    /// @dev Matches `AccountConfiguration.ACTOR_INITIALIZATION_TYPEHASH`.
    bytes32 internal constant _ACTOR_INITIALIZATION_TYPEHASH = keccak256(
        "ActorInitialization(bytes32 salt,uint256 chainId,Actor[] initialActors)Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint8 scope,uint48 expiry)"
    );

    bytes4 internal constant _ERC1271_MAGIC = 0x1626ba7e;
    bytes4 internal constant _ERC1271_INVALID = 0xffffffff;

    /// @notice Transient (EIP-1153) bootstrap latch. Non-zero ONLY for the duration of the `bootstrap` call frame
    ///         (i.e. across the nested `importAccount`). When set, it is the typed actors hash that, combined with
    ///         `address(this)` and `_bootstrapChainId`, reconstructs the expected `ActorInitialization` digest.
    ///         Auto-clears at end of tx and is cleared explicitly after import, so the BOOTSTRAP branch is
    ///         reachable exactly once.
    bytes32 internal transient _bootstrapActorsHash;

    /// @notice Transient chainId paired with `_bootstrapActorsHash` for the import digest (0 = multichain).
    uint256 internal transient _bootstrapChainId;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
    }

    // ══════════════════════════════════════════════
    //  BOOTSTRAP
    // ══════════════════════════════════════════════

    /// @notice Atomically prime + self-import. Called by the factory in the same tx frame as `SETDELEGATE`.
    ///         Sets the transient latch, has AccountConfiguration register the actors (whose ERC-1271 callback
    ///         lands on the BOOTSTRAP branch below), then clears the latch. After `importAccount` succeeds the
    ///         account is initialized, so a second call reverts inside `importAccount` and the BOOTSTRAP branch
    ///         is never reachable again.
    /// @param  actorsHash    `keccak256(actorHash_0 || actorHash_1 || ... )`, matching the inner hash of the
    ///                        `ActorInitialization` digest AccountConfiguration computes for the same actor set.
    /// @param  chainId       Replay domain for `importAccount`: 0 = multichain, else the current chain.
    /// @param  initialActors The actor set to import. MUST match `actorsHash`.
    function bootstrap(bytes32 actorsHash, uint256 chainId, AccountConfiguration.InitialActor[] calldata initialActors)
        external
    {
        _bootstrapActorsHash = actorsHash;
        _bootstrapChainId = chainId;
        ACCOUNT_CONFIGURATION.importAccount(address(this), chainId, initialActors, "");
        _bootstrapActorsHash = bytes32(0);
        _bootstrapChainId = 0;
    }

    // ══════════════════════════════════════════════
    //  ERC-1271
    // ══════════════════════════════════════════════

    /// @notice Signature validation.
    ///         BOOTSTRAP mode (transient latch set): the presented `hash` must equal the canonical
    ///         `ActorInitialization` digest reconstructed from the latched actors hash and chainId. The
    ///         `signature` argument is ignored; binding comes from the factory's atomic sequence and the
    ///         address derivation.
    ///         NORMAL mode (latch unset): defer to AccountConfiguration.verifySignature (operational actors).
    function isValidSignature(bytes32 hash, bytes calldata signature) external view virtual returns (bytes4) {
        bytes32 actorsHash = _bootstrapActorsHash;
        if (actorsHash != bytes32(0)) {
            return hash == _expectedImportDigest(actorsHash, _bootstrapChainId) ? _ERC1271_MAGIC : _ERC1271_INVALID;
        }
        // signature is `authenticator(20) || data` per EIP-8130 for the canonical path.
        return ACCOUNT_CONFIGURATION.verifySignature(address(this), hash, signature) ? _ERC1271_MAGIC : _ERC1271_INVALID;
    }

    /// @notice The digest this account expects in BOOTSTRAP mode for a given actor set and chainId. Exposed for
    ///         off-chain tooling; the on-chain check uses the transient latch primed by `bootstrap`.
    function expectedImportDigest(bytes32 actorsHash, uint256 chainId) external view returns (bytes32) {
        return _expectedImportDigest(actorsHash, chainId);
    }

    // ══════════════════════════════════════════════
    //  INTERNALS
    // ══════════════════════════════════════════════

    function _expectedImportDigest(bytes32 actorsHash, uint256 chainId) internal view returns (bytes32) {
        return
            keccak256(abi.encode(_ACTOR_INITIALIZATION_TYPEHASH, bytes32(bytes20(address(this))), chainId, actorsHash));
    }
}
