// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {MerkleProof} from "openzeppelin/utils/cryptography/MerkleProof.sol";

import {IAuthenticator} from "eip-8130/interfaces/IAuthenticator.sol";
import {ActorId} from "eip-8130/libraries/ActorId.sol";

/// @notice A committed-set ("merkle root") session authenticator — the churn tier of the two-tier keystore model
///         (see this folder's README). One `actorId = root` slot commits a whole set of session keys off-chain;
///         a per-tx membership proof redeems one leaf, and that leaf's own fresh signature authorizes the tx.
///
///         actorId = the committed merkle root.
///                 Register the root ONCE as a normal actor bound to this authenticator, with a BOUNDED
///                 (non-admin) scope and a short expiry — never `scope == 0`. It is the on-chain anchor for the
///                 set: rotating the set is re-registering the root (an admin op), so a compromised leaf can
///                 never fork the anchor, and the keystore caps every leaf by the root actor's own expiry.
///
///         leaf    = keccak256(SESSION_LEAF_TYPEHASH ‖ signerId ‖ subAuthenticator ‖ sessionExpiry)
///                 The committer binds each session key's identity, scheme, and (per-leaf) expiry into the tree.
///
///         data    = subAuthenticator (20) ‖ sessionExpiry (6) ‖ subSigLen (2) ‖ subSig (subSigLen) ‖ proof (tail)
///                 subAuthenticator == address(1) is the built-in K1 sentinel (subSig = r‖s‖v, 65 bytes); any
///                 other address is an {IAuthenticator} contract (P256, WebAuthn, …). `proof` is the packed
///                 merkle co-path (a multiple of 32 bytes), OZ-commutative-hashed to the root.
///
///         Security (why a proof alone is never enough): membership is provenance, not authentication. This
///         authenticator ALSO requires a fresh `hash`-bound `subSig` from the leaf key on every call and folds
///         that recovered identity into the leaf — so a public, replayable proof can never authorize a tx by
///         itself, and a leaf can only reach the root the committer actually built (second-preimage resistance).
contract MerkleSessionAuthenticator is IAuthenticator {
    using ActorId for address;

    /// @notice The built-in secp256k1 sentinel (Keystore K1_AUTHENTICATOR). Not a contract — verified via ecrecover.
    address internal constant K1_AUTHENTICATOR = address(1);

    /// @notice Domain tag for a committed session leaf. Separates a membership leaf from any tx digest.
    bytes32 public constant SESSION_LEAF_TYPEHASH =
        keccak256("MerkleSessionLeaf(bytes32 signerId,address subAuthenticator,uint48 sessionExpiry)");

    /// @notice Fixed prefix: subAuthenticator(20) ‖ sessionExpiry(6) ‖ subSigLen(2).
    uint256 internal constant PREFIX_LEN = 28;

    /// @notice `data` is shorter than the fixed prefix, the subSig slice overruns, or `proof` is not a whole
    ///         number of 32-byte siblings.
    error InvalidDataLength();

    /// @notice The leaf's sub-authenticator points back at this contract; only one hop is permitted.
    error RecursiveDelegation();

    /// @notice An {encode} sub-signature blob is longer than the 2-byte length prefix can express.
    error SubSigTooLong();

    /// @notice Authenticates `hash` as a member of the committed set, returning that set's root.
    ///
    /// @dev Reverts with InvalidDataLength / RecursiveDelegation on malformed input. Returns bytes32(0) (fail
    ///      closed) when the leaf has expired or its fresh signature does not recover the leaf identity. On
    ///      success returns the merkle root; the Keystore then binds it to this authenticator and applies the
    ///      root actor's own liveness (expiry) — so an unregistered/forged root simply fails the bind.
    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        if (data.length < PREFIX_LEN) revert InvalidDataLength();

        address subAuthenticator = address(bytes20(data[0:20]));
        uint48 sessionExpiry = uint48(bytes6(data[20:26]));
        uint256 subSigLen = uint256(uint16(bytes2(data[26:PREFIX_LEN])));

        uint256 subSigEnd = PREFIX_LEN + subSigLen;
        if (data.length < subSigEnd) revert InvalidDataLength();
        if (subAuthenticator == address(this)) revert RecursiveDelegation();

        // 1. Per-leaf expiry — a lapsed session key cannot ride the set even with a valid proof.
        if (sessionExpiry != 0 && block.timestamp > sessionExpiry) return bytes32(0);

        // 2. Fresh signature over `hash` by the leaf key (this is the authentication; the proof is only provenance).
        bytes32 signerId = _recover(hash, subAuthenticator, data[PREFIX_LEN:subSigEnd]);
        if (signerId == bytes32(0)) return bytes32(0);

        // 3. Fold the recovered leaf through the co-path to the committed root.
        bytes32 leaf = keccak256(abi.encode(SESSION_LEAF_TYPEHASH, signerId, subAuthenticator, sessionExpiry));
        actorId = MerkleProof.processProof(_proof(data[subSigEnd:]), leaf);
    }

    /// @notice The committed leaf for a session key. Off-chain tooling builds the tree from these.
    function leafHash(bytes32 signerId, address subAuthenticator, uint48 sessionExpiry) public pure returns (bytes32) {
        return keccak256(abi.encode(SESSION_LEAF_TYPEHASH, signerId, subAuthenticator, sessionExpiry));
    }

    /// @notice Builds the `data` blob {authenticate} expects. Structural only — it does not run the sub-scheme.
    function encode(address subAuthenticator, uint48 sessionExpiry, bytes calldata subSig, bytes32[] calldata proof)
        external
        pure
        returns (bytes memory)
    {
        if (subSig.length > type(uint16).max) revert SubSigTooLong();
        return abi.encodePacked(subAuthenticator, sessionExpiry, uint16(subSig.length), subSig, proof);
    }

    /// @dev Recovers the actorId a fresh `hash` signature authorizes. K1 uses ecrecover; any other authenticator
    ///      is an {IAuthenticator} contract at its deterministic address. Returns bytes32(0) on any failure so the
    ///      caller fails closed without reverting.
    function _recover(bytes32 hash, address subAuthenticator, bytes calldata subSig) private view returns (bytes32) {
        if (subAuthenticator == K1_AUTHENTICATOR) {
            if (subSig.length != 65) return bytes32(0);
            (address recovered, ECDSA.RecoverError err,) =
                ECDSA.tryRecover(hash, uint8(subSig[64]), bytes32(subSig[0:32]), bytes32(subSig[32:64]));
            if (err != ECDSA.RecoverError.NoError || recovered == address(0)) return bytes32(0);
            return recovered.fromAddress();
        }

        try IAuthenticator(subAuthenticator).authenticate(hash, subSig) returns (bytes32 id) {
            return id;
        } catch {
            return bytes32(0);
        }
    }

    /// @dev Decodes the packed co-path tail into sibling words. Reverts if it is not a multiple of 32 bytes.
    function _proof(bytes calldata packed) private pure returns (bytes32[] memory proof) {
        if (packed.length % 32 != 0) revert InvalidDataLength();
        uint256 n = packed.length / 32;
        proof = new bytes32[](n);
        for (uint256 i; i < n; i++) {
            proof[i] = bytes32(packed[i * 32:i * 32 + 32]);
        }
    }
}
