// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IL1StateOracle} from "./IL1StateOracle.sol";
import {StateProofLib} from "./StateProofLib.sol";

/// @notice Minimal view of the OP-stack `L1Block` predeploy at 0x42..0015.
interface IL1Block {
    /// @notice The most recent L1 block hash ingested by the sequencer.
    function hash() external view returns (bytes32);
}

/// @notice L1 state oracle for OP-stack local chains (Base, Optimism, …): derive the L1 state root from an RLP L1
///         header verified against the `L1Block` predeploy's committed L1 block hash.
///
///         headerProof = the RLP-encoded L1 block header (`keccak256(header)` must equal `L1Block.hash()`).
contract L1BlockStateOracle is IL1StateOracle {
    /// @notice The canonical OP-stack `L1Block` predeploy address.
    IL1Block public constant L1_BLOCK = IL1Block(0x4200000000000000000000000000000000000015);

    /// @notice The supplied header does not hash to the L1 block hash the predeploy commits to.
    error StaleOrInvalidL1Header();

    /// @inheritdoc IL1StateOracle
    function l1StateRoot(bytes calldata headerProof) external view returns (bytes32) {
        if (keccak256(headerProof) != L1_BLOCK.hash()) revert StaleOrInvalidL1Header();
        return StateProofLib.headerStateRoot(headerProof);
    }
}
