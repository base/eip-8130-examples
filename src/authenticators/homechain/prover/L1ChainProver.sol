// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IChainProver} from "./IChainProver.sol";
import {StateProofLib} from "./StateProofLib.sol";

/// @notice Home chain is L1 (Ethereum): read the Keystore account directly from the L1 state root. No recursion.
///
///         proof = abi.encode(bytes[] keystoreAccountProof)  // eth_getProof account proof nodes
contract L1ChainProver is IChainProver {
    /// @inheritdoc IChainProver
    function proveKeystoreStorageRoot(bytes32 l1StateRoot, address keystore, bytes calldata proof)
        external
        pure
        returns (bytes32 storageRoot)
    {
        bytes[] memory keystoreAccountProof = abi.decode(proof, (bytes[]));
        return StateProofLib.accountStorageRoot(l1StateRoot, keystore, keystoreAccountProof);
    }
}
