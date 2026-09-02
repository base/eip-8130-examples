// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IChainProver} from "./IChainProver.sol";
import {StateProofLib} from "./StateProofLib.sol";

/// @notice Home chain is Arbitrum: recover the L2 state root from a confirmed node the rollup commits on L1, then
///         read the Keystore account against that L2 state root.
///
///         Recursion (all against the trusted `l1StateRoot`):
///           1. Prove the rollup account on L1        -> its storageRoot.
///           2. Prove `confirmDataSlot` in that storage-> the confirmed node's confirmData.
///           3. Check keccak256(l2BlockHash ‖ sendRoot) == confirmData, where l2BlockHash = keccak256(l2Header).
///           4. Extract l2StateRoot from `l2Header` and prove the Keystore account against it.
///
///         `ROLLUP` is the L1 Arbitrum rollup contract (the trust anchor, fixed per home chain).
///
///         proof = abi.encode(
///             bytes[]  rollupAccountProof,
///             bytes32  confirmDataSlot,
///             bytes[]  rollupStorageProof,
///             bytes32  sendRoot,
///             bytes    l2Header,
///             bytes[]  keystoreAccountProof
///         )
///
///         NOTE (example simplification): the caller supplies which `confirmDataSlot` to read and the code does not
///         enforce that the node is the latest confirmed one. A production build must constrain the node/slot.
contract ArbitrumChainProver is IChainProver {
    /// @notice L1 Arbitrum rollup contract that commits confirmed nodes for this L2.
    address public immutable ROLLUP;

    /// @notice The proven confirmData did not match keccak256(l2BlockHash ‖ sendRoot).
    error ConfirmDataMismatch();

    constructor(address rollup) {
        ROLLUP = rollup;
    }

    /// @inheritdoc IChainProver
    function proveKeystoreStorageRoot(bytes32 l1StateRoot, address keystore, bytes calldata proof)
        external
        view
        returns (bytes32 storageRoot)
    {
        (
            bytes[] memory rollupAccountProof,
            bytes32 confirmDataSlot,
            bytes[] memory rollupStorageProof,
            bytes32 sendRoot,
            bytes memory l2Header,
            bytes[] memory keystoreAccountProof
        ) = abi.decode(proof, (bytes[], bytes32, bytes[], bytes32, bytes, bytes[]));

        // 1-2. Read the confirmed node's confirmData from the L1 rollup storage.
        bytes32 rollupStorageRoot = StateProofLib.accountStorageRoot(l1StateRoot, ROLLUP, rollupAccountProof);
        bytes32 confirmData = bytes32(StateProofLib.storageWord(rollupStorageRoot, confirmDataSlot, rollupStorageProof));

        // 3. Bind the confirmData to the L2 block header.
        bytes32 l2BlockHash = keccak256(l2Header);
        if (StateProofLib.arbitrumConfirmData(l2BlockHash, sendRoot) != confirmData) {
            revert ConfirmDataMismatch();
        }

        // 4. Extract the L2 state root from the header and read the Keystore account against it.
        bytes32 l2StateRoot = StateProofLib.headerStateRoot(l2Header);
        return StateProofLib.accountStorageRoot(l2StateRoot, keystore, keystoreAccountProof);
    }
}
