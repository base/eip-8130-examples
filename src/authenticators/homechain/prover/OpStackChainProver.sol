// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IChainProver} from "./IChainProver.sol";
import {StateProofLib} from "./StateProofLib.sol";

/// @notice Home chain is an OP-stack L2 (Optimism, Base): recover the L2 state root from an output root that the
///         L2 commits on L1, then read the Keystore account against that L2 state root.
///
///         Recursion (all against the trusted `l1StateRoot`):
///           1. Prove the output-oracle account on L1  -> its storageRoot.
///           2. Prove `outputRootSlot` in that storage -> the committed outputRoot.
///           3. Check keccak256(version ‖ l2StateRoot ‖ messagePasserStorageRoot ‖ l2BlockHash) == outputRoot.
///           4. Prove the Keystore account against `l2StateRoot` -> its storageRoot.
///
///         `OUTPUT_ORACLE` is the L1 address that commits this L2's outputs (e.g. the chain's `L2OutputOracle` or
///         dispute-game/anchor contract) — the trust anchor, fixed per home chain.
///
///         proof = abi.encode(
///             bytes[]  oracleAccountProof,
///             bytes32  outputRootSlot,
///             bytes[]  oracleStorageProof,
///             bytes32  version,
///             bytes32  l2StateRoot,
///             bytes32  messagePasserStorageRoot,
///             bytes32  l2BlockHash,
///             bytes[]  keystoreAccountProof
///         )
///
///         NOTE (example simplification): the caller supplies which `outputRootSlot` to read and the code does not
///         enforce output finalization / a specific output index. A production build must constrain both so a stale
///         or non-finalized output cannot be presented.
contract OpStackChainProver is IChainProver {
    /// @notice L1 contract that commits this L2's output roots.
    address public immutable OUTPUT_ORACLE;

    /// @notice The proven output root did not match the supplied (version, l2StateRoot, msgPasser, l2BlockHash).
    error OutputRootMismatch();

    constructor(address outputOracle) {
        OUTPUT_ORACLE = outputOracle;
    }

    /// @inheritdoc IChainProver
    function proveKeystoreStorageRoot(bytes32 l1StateRoot, address keystore, bytes calldata proof)
        external
        view
        returns (bytes32 storageRoot)
    {
        (
            bytes[] memory oracleAccountProof,
            bytes32 outputRootSlot,
            bytes[] memory oracleStorageProof,
            bytes32 version,
            bytes32 l2StateRoot,
            bytes32 messagePasserStorageRoot,
            bytes32 l2BlockHash,
            bytes[] memory keystoreAccountProof
        ) = abi.decode(proof, (bytes[], bytes32, bytes[], bytes32, bytes32, bytes32, bytes32, bytes[]));

        // 1-2. Read the committed output root from the L1 output oracle's storage.
        bytes32 oracleStorageRoot = StateProofLib.accountStorageRoot(l1StateRoot, OUTPUT_ORACLE, oracleAccountProof);
        bytes32 outputRoot = bytes32(StateProofLib.storageWord(oracleStorageRoot, outputRootSlot, oracleStorageProof));

        // 3. Bind the output root to the claimed L2 state root.
        if (StateProofLib.opOutputRoot(version, l2StateRoot, messagePasserStorageRoot, l2BlockHash) != outputRoot) {
            revert OutputRootMismatch();
        }

        // 4. Read the Keystore account against the proven L2 state root.
        return StateProofLib.accountStorageRoot(l2StateRoot, keystore, keystoreAccountProof);
    }
}
