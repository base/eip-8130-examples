// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Derives the home chain's Keystore *storage root*, given a trusted L1 state root. This is the recursive
///         seam: an L1-home prover reads the Keystore account straight from the L1 state; an L2-home prover first
///         proves the L2's state commitment on L1 (output root / confirmed node), recovers the L2 state root, then
///         reads the Keystore account there.
///
///         {HomeChainProver} keeps a chainId => IChainProver registry (the "chain id to bridge mapping") and does
///         the final actor-config storage proof against the returned root.
interface IChainProver {
    /// @notice Returns the storage root of `keystore` on the home chain.
    ///
    /// @dev MUST revert on a malformed/failed proof.
    ///
    /// @param l1StateRoot A trusted L1 state root (supplied by {HomeChainProver} via its L1 state oracle).
    /// @param keystore    The Keystore address on the home chain (deterministic CREATE2, same on every chain).
    /// @param proof       Chain-specific proof bytes (see each implementation).
    ///
    /// @return storageRoot The Keystore account's storage root on the home chain.
    function proveKeystoreStorageRoot(bytes32 l1StateRoot, address keystore, bytes calldata proof)
        external
        view
        returns (bytes32 storageRoot);
}
