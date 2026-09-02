// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Keystore} from "eip-8130/Keystore.sol";
import {IAuthenticator} from "eip-8130/interfaces/IAuthenticator.sol";

/// @notice Keystore-bounded M-of-N authenticator. Each signer is another 8130 account; each
///         vouch is one hop through {Keystore.authenticateActor}, matching {DelegateAuthenticator}.
///
///         actorId = keccak256(threshold (1) || signerCount (1)
///                           || signer_0 (20) || ... || signer_n (20))
///                 Signers MUST be sorted ascending by address.
///
///         data  = threshold (1) || signerCount (1) || signers (signerCount × 20)
///                 || sigCount (1)
///                 || [signer (20) || authLen (2) || nestedAuth (authLen)] × sigCount
///                 nestedAuth = authenticator(20) || authenticator-specific data
///                 Provided signers MUST be a strictly ascending subset of the committee.
///
///         Each nested actor MUST be the admin (scope == 0x00) of its signer account.
///         Nested authenticator MUST NOT be this contract (one hop only).
///
///         Heterogeneous committees are the point: signer A can be K1, signer B P256 / WebAuthn,
///         signer C whatever that account has registered — this contract never inspects the scheme.
///
///         `threshold` and `signerCount` are each a single byte (committee capped at 255), and both are
///         committed into `actorId`. Rotating the threshold or the member set yields a different `actorId`,
///         so the change must be re-authorized on the account (there is no in-place membership mutation).
contract KeystoreMultisigAuthenticator is IAuthenticator {
    /// @notice The Keystore system contract used to validate each nested (signer) signature.
    Keystore public immutable KEYSTORE;

    /// @notice `data` is shorter than the committee prefix + sigCount, a proof overruns the buffer,
    ///         a nested auth is shorter than 20 bytes, or trailing bytes remain after the proofs.
    error InvalidDataLength();

    /// @notice Threshold is 0 or greater than the committee size.
    error InvalidThreshold();

    /// @notice Committee addresses or provided-signer addresses are not strictly ascending.
    error UnsortedSigners();

    /// @notice The nested authenticator points back to this contract; only one hop is permitted.
    error RecursiveDelegation();

    /// @notice An {encode} committee or proof count exceeds 255 (the single-byte count width).
    error SignerCountOverflow();

    /// @notice {encode} received a different number of proof signers and nested auth blobs.
    error ProofLengthMismatch();

    /// @notice An {encode} nested auth blob is longer than the 2-byte length prefix can express.
    error NestedAuthTooLong();

    /// @notice Deploys the authenticator bound to a Keystore instance.
    /// @param keystore Address of the Keystore system contract.
    constructor(address keystore) {
        KEYSTORE = Keystore(keystore);
    }

    /// @notice Authenticates an M-of-N committee of 8130 accounts over `hash`.
    ///
    /// @dev Reverts with InvalidDataLength, InvalidThreshold, UnsortedSigners, or RecursiveDelegation
    ///      on malformed input. Returns bytes32(0) when a provided signer is not on the committee,
    ///      a nested auth fails, or a nested actor is non-admin. On success returns the committee
    ///      `actorId` (independent of which subset signed).
    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        if (data.length < 3) revert InvalidDataLength();

        uint256 threshold = uint256(uint8(data[0]));
        uint256 signerCount = uint256(uint8(data[1]));
        if (threshold == 0 || threshold > signerCount) revert InvalidThreshold();

        uint256 committeeEnd = 2 + signerCount * 20;
        if (data.length < committeeEnd + 1) revert InvalidDataLength();

        for (uint256 j = 1; j < signerCount; j++) {
            if (_addrAt(data, 2 + j * 20) <= _addrAt(data, 2 + (j - 1) * 20)) revert UnsortedSigners();
        }

        actorId = keccak256(data[:committeeEnd]);

        uint256 sigCount = uint256(uint8(data[committeeEnd]));
        // < threshold can never satisfy the committee; > signerCount can never be a strictly ascending subset.
        if (sigCount < threshold || sigCount > signerCount) return bytes32(0);

        uint256 off = committeeEnd + 1;
        uint256 signerIdx;
        address prev;

        for (uint256 i; i < sigCount; i++) {
            if (data.length < off + 22) revert InvalidDataLength();
            address signer = _addrAt(data, off);
            uint256 authLen = uint256(uint16(bytes2(data[off + 20:off + 22])));
            off += 22;
            if (authLen < 20 || data.length < off + authLen) revert InvalidDataLength();

            if (signer <= prev) revert UnsortedSigners();
            prev = signer;

            bool found;
            while (signerIdx < signerCount) {
                address member = _addrAt(data, 2 + signerIdx * 20);
                signerIdx++;
                if (member == signer) {
                    found = true;
                    break;
                }
                if (member > signer) return bytes32(0);
            }
            if (!found) return bytes32(0);

            if (address(bytes20(data[off:off + 20])) == address(this)) revert RecursiveDelegation();

            bytes calldata nestedAuth = data[off:off + authLen];
            off += authLen;

            try KEYSTORE.authenticateActor(signer, hash, nestedAuth) returns (bytes32, uint16 nestedScope) {
                if (nestedScope != 0) return bytes32(0);
            } catch {
                return bytes32(0);
            }
        }

        if (off != data.length) revert InvalidDataLength();
    }

    function _addrAt(bytes calldata data, uint256 off) private pure returns (address signer) {
        assembly {
            signer := shr(96, calldataload(add(data.offset, off)))
        }
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // ENCODING HELPERS (off-chain builders; call via eth_call)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice The `actorId` committed by a committee: keccak256(threshold ‖ N ‖ sorted signers). Register this
    ///         on an account (bound to this authenticator) to make the committee an actor.
    ///
    /// @dev Reverts with InvalidThreshold, SignerCountOverflow, or UnsortedSigners; `signers` MUST be strictly
    ///      ascending, matching what {authenticate} recomputes over the wire.
    function committeeActorId(uint8 threshold, address[] calldata signers) external pure returns (bytes32) {
        return keccak256(_committeePrefix(threshold, signers));
    }

    /// @notice Builds the `data` blob {authenticate} expects for a committee and a set of member proofs.
    ///
    /// @dev `proofSigners` MUST be a strictly ascending subset of `committee`, each paired with its nested auth
    ///      (authenticator(20) ‖ authenticator-specific data). Structural only: it does not run the nested
    ///      authenticators, so it neither needs `hash` nor guarantees the blob will authenticate — it guarantees
    ///      the blob is well-formed. Reverts with InvalidThreshold, SignerCountOverflow, UnsortedSigners,
    ///      ProofLengthMismatch, or NestedAuthTooLong.
    function encode(
        uint8 threshold,
        address[] calldata committee,
        address[] calldata proofSigners,
        bytes[] calldata nestedAuths
    ) external pure returns (bytes memory data) {
        if (proofSigners.length != nestedAuths.length) revert ProofLengthMismatch();
        if (proofSigners.length > type(uint8).max) revert SignerCountOverflow();

        data = abi.encodePacked(_committeePrefix(threshold, committee), uint8(proofSigners.length));

        address prev;
        for (uint256 i; i < proofSigners.length; i++) {
            if (proofSigners[i] <= prev) revert UnsortedSigners();
            prev = proofSigners[i];

            if (nestedAuths[i].length > type(uint16).max) revert NestedAuthTooLong();
            data = abi.encodePacked(data, proofSigners[i], uint16(nestedAuths[i].length), nestedAuths[i]);
        }
    }

    /// @dev Shared threshold(1) ‖ N(1) ‖ signers packing behind {committeeActorId} and {encode}, validating the
    ///      same committee invariants {authenticate} enforces so the two can never disagree.
    function _committeePrefix(uint8 threshold, address[] calldata signers) private pure returns (bytes memory prefix) {
        uint256 signerCount = signers.length;
        if (signerCount > type(uint8).max) revert SignerCountOverflow();
        if (threshold == 0 || threshold > signerCount) revert InvalidThreshold();

        prefix = abi.encodePacked(threshold, uint8(signerCount));
        address prev;
        for (uint256 i; i < signerCount; i++) {
            if (signers[i] <= prev) revert UnsortedSigners();
            prev = signers[i];
            prefix = abi.encodePacked(prefix, signers[i]);
        }
    }
}
