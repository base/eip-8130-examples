// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore, IKeystoreImport} from "eip-8130/Keystore.sol";
import {DefaultAccount} from "eip-8130/accounts/DefaultAccount.sol";
import {Scopes} from "eip-8130/libraries/Scopes.sol";

import {TransientActors} from "./TransientActors.sol";

/// @notice Account whose constructor runs (real initcode) and whose actor set is never stored.
///
///         The one extra function is {completeImport}: it takes actors as calldata, checks they match
///         the immutable {ACTORS_HASH} baked by the constructor, stashes them in transient storage,
///         and calls {Keystore.importAccount}. Keystore then STATICCALLs {getImportActors} (no args) —
///         those reads hit the stash, not SSTORE.
///
///         {completeImport} is permissionless and hash-bound: anyone may finish an un-imported
///         account, but only with the committed actor set. A failed import reverts the call (stash
///         included). After success Keystore is initialized and a retry reverts {AlreadyInitialized}.
contract InitcodeAccount is DefaultAccount, IKeystoreImport {
    /// @notice keccak256(abi.encode(initialActors)) — the only actor commitment on this contract.
    bytes32 public immutable ACTORS_HASH;

    error ActorsHashMismatch();
    error AlreadyImported();

    constructor(address keystore, bytes32 actorsHash) DefaultAccount(keystore) {
        if (actorsHash == bytes32(0)) revert ActorsHashMismatch();
        ACTORS_HASH = actorsHash;
    }

    /// @notice The extra function. `actors` stay in calldata; the Keystore sees them via {getImportActors}.
    function completeImport(uint256 chainId, Keystore.InitialActor[] calldata actors) external {
        if (KEYSTORE.getChangeSequences(address(this)).localSequence != 0) revert AlreadyImported();
        if (keccak256(abi.encode(actors)) != ACTORS_HASH) revert ActorsHashMismatch();
        TransientActors.store(actors, chainId);
        KEYSTORE.importAccount(chainId, "");
        TransientActors.clear();
    }

    /// @inheritdoc IKeystoreImport
    function getImportActors() external view returns (Keystore.InitialActor[] memory actors) {
        (actors,) = TransientActors.load();
    }

    /// @inheritdoc DefaultAccount
    function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4) {
        (Keystore.InitialActor[] memory actors, uint256 chainId) = TransientActors.load();
        if (actors.length != 0) {
            return hash == KEYSTORE.computeImportDigest(address(this), chainId, actors)
                ? ERC1271_MAGIC_VALUE
                : ERC1271_INVALID;
        }
        try KEYSTORE.validateSignature(address(this), hash, signature) returns (bytes32, uint16 scope) {
            return Scopes.isOperator(scope) ? ERC1271_MAGIC_VALUE : ERC1271_INVALID;
        } catch {
            return ERC1271_INVALID;
        }
    }
}
