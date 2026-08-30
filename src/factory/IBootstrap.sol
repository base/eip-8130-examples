// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "eip-8130/Keystore.sol";

/// @notice Minimal interface a SETDELEGATE-factory implementation must expose for atomic bootstrap.
///
///         A bootstrap-aware implementation:
///           - Exposes `bootstrap(actorsHash, chainId, initialActors)` that the factory calls in the same tx
///             frame as `SETDELEGATE`. It stores the actor set in a one-shot latch, drives
///             `Keystore.importAccount` on itself (the account is `msg.sender`), then clears the latch.
///           - Implements {IKeystoreImport.getImportActors} so the Keystore reads the actor set from code,
///             not from the import caller.
///           - In ERC-1271, while the latch is set, confirms {Keystore.computeImportDigest}; otherwise
///             defers to {DefaultAccount.isValidSignature}.
interface IBootstrap {
    /// @notice Prime the bootstrap latch and atomically import the actor set.
    /// @param actorsHash    Inner hash of the EIP-8130 `ActorInitialization` digest:
    ///                       `keccak256(actorHash_0 || ... || actorHash_n)`.
    /// @param chainId       Replay domain passed to `importAccount`: 0 = multichain, else the current chain.
    /// @param initialActors Actor set {getImportActors} will return. MUST correspond to `actorsHash`.
    function bootstrap(bytes32 actorsHash, uint256 chainId, Keystore.InitialActor[] calldata initialActors) external;
}
