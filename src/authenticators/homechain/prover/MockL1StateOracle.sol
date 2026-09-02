// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IL1StateOracle} from "./IL1StateOracle.sol";

/// @notice Test/demo L1 state oracle: returns a settable L1 state root, ignoring `headerProof`. Stands in for the
///         {L1BlockStateOracle} so tests can supply a state root that matches their fixtures.
contract MockL1StateOracle is IL1StateOracle {
    bytes32 public stateRoot;

    function setStateRoot(bytes32 stateRoot_) external {
        stateRoot = stateRoot_;
    }

    /// @inheritdoc IL1StateOracle
    function l1StateRoot(bytes calldata /* headerProof */ ) external view returns (bytes32) {
        return stateRoot;
    }
}
