// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Supplies a trusted L1 state root to {HomeChainProver} from the *local* chain. On an OP-stack L2 this
///         wraps the `L1Block` predeploy; other environments plug in their own source (beacon roots, a bridge, …).
interface IL1StateOracle {
    /// @notice Returns a trusted, recent L1 state root.
    /// @dev MAY consume `headerProof` (e.g. an RLP L1 header checked against a trusted L1 block hash). MUST revert
    ///      if a trusted L1 state root cannot be established.
    function l1StateRoot(bytes calldata headerProof) external view returns (bytes32);
}
