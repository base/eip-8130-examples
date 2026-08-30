// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore, IKeystoreImport} from "eip-8130/Keystore.sol";
import {DefaultAccount} from "eip-8130/accounts/DefaultAccount.sol";
import {Scopes} from "eip-8130/libraries/Scopes.sol";

import {IBootstrap} from "./IBootstrap.sol";

/// @notice Reference implementation for accounts deployed via {SetDelegateFactory}.
///
///         Extends {DefaultAccount} so a factory-imported account can `execute` / `executeBatch` and
///         ERC-1271-sign after bootstrap. Import itself needs no owner key:
///           - `bootstrap` writes the actor set into a one-shot storage latch, calls
///             `KEYSTORE.importAccount(chainId, "")` (account is `msg.sender`), then clears the latch.
///           - {IKeystoreImport.getImportActors} returns that transient set so the Keystore — not the
///             factory — chooses who is installed.
///           - While the latch is set, ERC-1271 confirms {Keystore.computeImportDigest}. After import it
///             uses the inherited {DefaultAccount} path (`validateSignature` + {Scopes.isOperator}).
///
///         Binding is structural: SETDELEGATE address derivation commits to `(factory, salt)` and the
///         salt already commits to the actor set. The 1271 callback only checks the digest the Keystore
///         computed matches that set.
contract BootstrapAccount is DefaultAccount, IBootstrap, IKeystoreImport {
    /// @notice Actor-set encoding (`abi.encode(InitialActor[])`). Non-empty ONLY across the nested
    ///         `importAccount` inside {bootstrap}. Regular storage (transient cannot hold `bytes`);
    ///         cleared before {bootstrap} returns, and a revert unwinds it.
    bytes private _bootstrapActorsEnc;

    /// @notice ChainId paired with {_bootstrapActorsEnc} (0 = multichain) for the import digest.
    uint256 private _bootstrapChainId;

    constructor(address keystore) DefaultAccount(keystore) {}

    /// @inheritdoc IBootstrap
    function bootstrap(bytes32 actorsHash, uint256 chainId, Keystore.InitialActor[] calldata initialActors) external {
        if (actorsHash != _actorsHash(initialActors)) revert ActorsHashMismatch();
        _bootstrapActorsEnc = abi.encode(initialActors);
        _bootstrapChainId = chainId;
        KEYSTORE.importAccount(chainId, "");
        _bootstrapActorsEnc = "";
        _bootstrapChainId = 0;
    }

    /// @dev The Keystore reads this during {importAccount}; empty outside the bootstrap window.
    function getImportActors() external view returns (Keystore.InitialActor[] memory) {
        return _importActors();
    }

    /// @inheritdoc DefaultAccount
    /// @dev BOOTSTRAP: confirm {computeImportDigest}. NORMAL: inherited operational ERC-1271.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4) {
        Keystore.InitialActor[] memory actors = _importActors();
        if (actors.length != 0) {
            return hash == KEYSTORE.computeImportDigest(address(this), _bootstrapChainId, actors)
                ? ERC1271_MAGIC_VALUE
                : ERC1271_INVALID;
        }
        try KEYSTORE.validateSignature(address(this), hash, signature) returns (bytes32, uint16 scope) {
            return Scopes.isOperator(scope) ? ERC1271_MAGIC_VALUE : ERC1271_INVALID;
        } catch {
            return ERC1271_INVALID;
        }
    }

    error ActorsHashMismatch();

    function _importActors() internal view returns (Keystore.InitialActor[] memory actors) {
        bytes memory raw = _bootstrapActorsEnc;
        if (raw.length == 0) return actors;
        return abi.decode(raw, (Keystore.InitialActor[]));
    }

    /// @dev Inner hash of {Keystore.computeImportDigest}: expiry forced to 0, policyData hashed.
    function _actorsHash(Keystore.InitialActor[] calldata initialActors) internal pure returns (bytes32) {
        bytes32 typehash = keccak256(
            "Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint48 expiry,uint16 scope)"
        );
        bytes32 configTypehash = keccak256("ActorConfig(address authenticator,uint48 expiry,uint16 scope)");
        bytes32[] memory perActor = new bytes32[](initialActors.length);
        for (uint256 i; i < initialActors.length; i++) {
            bytes32 configHash = keccak256(
                abi.encode(configTypehash, initialActors[i].authenticator, uint48(0), initialActors[i].scope)
            );
            perActor[i] = keccak256(
                abi.encode(typehash, initialActors[i].actorId, configHash, keccak256(initialActors[i].policyData))
            );
        }
        return keccak256(abi.encodePacked(perActor));
    }
}
