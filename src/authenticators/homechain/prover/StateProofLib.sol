// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {RLP} from "openzeppelin/utils/RLP.sol";
import {Memory} from "openzeppelin/utils/Memory.sol";
import {TrieProof} from "openzeppelin/utils/cryptography/TrieProof.sol";

/// @notice Shared Merkle-Patricia-trie helpers for the home-chain provers, built on OpenZeppelin's {TrieProof}
///         and {RLP}. Everything here is real MPT verification against the eth_getProof format — no stubs.
///
///         Storage layout it targets (the `base/eip-8130` {Keystore}):
///           - `_actors` is storage base slot 0 (`mapping(bytes32 actorId => mapping(address account => ActorRecord))`).
///           - `ActorRecord.config` is at offset 0 and packs, via standard Solidity storage packing,
///             `authenticator` (low 160 bits) ‖ `expiry` (next 48) ‖ `scope` (next 16).
library StateProofLib {
    using RLP for bytes;
    using RLP for Memory.Slice;

    /// @dev Storage base slot of the Keystore's `_actors` mapping (first declared state variable).
    uint256 internal constant ACTORS_BASE_SLOT = 0;

    /// @dev Storage slot of `_actors[actorId][account].config` (config is at record offset 0).
    function actorConfigSlot(bytes32 actorId, address account) internal pure returns (bytes32) {
        bytes32 inner = keccak256(abi.encode(actorId, ACTORS_BASE_SLOT)); // _actors[actorId]
        return keccak256(abi.encode(account, inner)); // [account] -> ActorRecord, .config at +0
    }

    /// @dev Ethereum secure-trie path for an account: keccak256(address).
    function accountKey(address account) internal pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encodePacked(account)));
    }

    /// @dev Ethereum secure-trie path for a storage slot: keccak256(slot).
    function storageKey(bytes32 slot) internal pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encode(slot)));
    }

    /// @dev Verifies an account inclusion proof against `stateRoot` and returns the account's storageRoot.
    ///      The account leaf is RLP([nonce, balance, storageRoot, codeHash]). Reverts on an invalid proof.
    function accountStorageRoot(bytes32 stateRoot, address account, bytes[] memory accountProof)
        internal
        pure
        returns (bytes32)
    {
        bytes memory account_ = TrieProof.traverse(stateRoot, accountKey(account), accountProof);
        Memory.Slice[] memory fields = account_.decodeList();
        return fields[2].readBytes32();
    }

    /// @dev Verifies a storage inclusion proof against `storageRoot` and returns the raw slot word.
    ///      The storage leaf is RLP(slotValue) with leading zeros trimmed. Reverts on an invalid proof.
    function storageWord(bytes32 storageRoot, bytes32 slot, bytes[] memory storageProof)
        internal
        pure
        returns (uint256)
    {
        bytes memory value = TrieProof.traverse(storageRoot, storageKey(slot), storageProof);
        return value.decodeUint256();
    }

    /// @dev Decodes a packed {Keystore.ActorConfig} slot word (standard Solidity packing).
    function decodeActorConfig(uint256 word) internal pure returns (address authenticator, uint48 expiry, uint16 scope) {
        authenticator = address(uint160(word));
        expiry = uint48(word >> 160);
        scope = uint16(word >> 208);
    }

    /// @dev Extracts `stateRoot` (field index 3) from an RLP-encoded block header.
    function headerStateRoot(bytes memory header) internal pure returns (bytes32) {
        Memory.Slice[] memory fields = header.decodeList();
        return fields[3].readBytes32();
    }

    /// @dev OP-stack output root preimage: keccak256(version ‖ stateRoot ‖ messagePasserStorageRoot ‖ blockHash).
    function opOutputRoot(bytes32 version, bytes32 stateRoot, bytes32 messagePasserStorageRoot, bytes32 blockHash)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(version, stateRoot, messagePasserStorageRoot, blockHash));
    }

    /// @dev Arbitrum confirmed-node commitment: keccak256(blockHash ‖ sendRoot).
    function arbitrumConfirmData(bytes32 blockHash, bytes32 sendRoot) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(blockHash, sendRoot));
    }
}
