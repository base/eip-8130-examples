// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

import {IAuthenticator} from "eip-8130/interfaces/IAuthenticator.sol";
import {ActorId} from "eip-8130/libraries/ActorId.sol";

/// @notice An operator-minted session authenticator — the churn tier's "one grant, one key" form (see this
///         folder's README). A live OPERATOR (non-admin) actor signs a grant for a fresh session key; the tx is
///         authorized by that session key's own signature. No admin, no per-key registration, no keystore write.
///
///         actorId = the operator's actorId (the grant signer).
///                 Register the operator ONCE as a normal actor bound to this authenticator, with a BOUNDED
///                 (non-admin) scope and a short expiry — never `scope == 0`. Every session key it mints resolves
///                 to this same operator id, so:
///                   • scope is the operator's — a minted key can never exceed it, and never reaches admin;
///                   • the Keystore checks the operator's own expiry on every call, so revoking or expiring the
///                     operator instantly stops ALL of its sessions (cascading expiry — the whole subtree dies
///                     when the operator does), with no per-chain revocation.
///
///         grant   = keccak256(GRANT_TYPEHASH ‖ sessionId ‖ subAuthenticator ‖ sessionExpiry), signed by the
///                 operator. The domain tag keeps a grant from ever being read as a tx digest, and binds exactly
///                 the session key being minted (identity, scheme, and a per-session expiry ≤ the operator's).
///
///         data    = operatorAuthenticator (20) ‖ sessionExpiry (6) ‖ grantSigLen (2) ‖ grantSig (grantSigLen)
///                   ‖ subAuthenticator (20) ‖ subSigLen (2) ‖ subSig (subSigLen)
///                 Each of operator/sub authenticator is address(1) (built-in K1, sig = r‖s‖v, 65 bytes) or an
///                 {IAuthenticator} contract (P256, WebAuthn, …).
///
///         Security: install (the grant) and authenticate (the subSig over `hash`) are split, so neither alone
///         acts — a leaked grant is not a leaked key (an attacker can install the session but cannot sign for it).
contract OperatorSessionAuthenticator is IAuthenticator {
    using ActorId for address;

    /// @notice The built-in secp256k1 sentinel (Keystore K1_AUTHENTICATOR). Not a contract — verified via ecrecover.
    address internal constant K1_AUTHENTICATOR = address(1);

    /// @notice Domain tag for an operator session grant. Separates a grant from any tx digest.
    bytes32 public constant GRANT_TYPEHASH =
        keccak256("OperatorSessionGrant(bytes32 sessionId,address subAuthenticator,uint48 sessionExpiry)");

    /// @notice Fixed prefix before the grant sig: operatorAuthenticator(20) ‖ sessionExpiry(6) ‖ grantSigLen(2).
    uint256 internal constant PREFIX_LEN = 28;

    /// @notice Fixed sub-prefix after the grant sig: subAuthenticator(20) ‖ subSigLen(2).
    uint256 internal constant SUB_PREFIX_LEN = 22;

    /// @notice `data` is shorter than a fixed prefix or a signature slice overruns the buffer.
    error InvalidDataLength();

    /// @notice The operator or sub authenticator points back at this contract; only one hop is permitted.
    error RecursiveDelegation();

    /// @notice An {encode} signature blob is longer than the 2-byte length prefix can express.
    error SigTooLong();

    /// @notice Authenticates `hash` as an operator-minted session, returning the operator's actorId.
    ///
    /// @dev Reverts with InvalidDataLength / RecursiveDelegation on malformed input. Returns bytes32(0) (fail
    ///      closed) when the session has expired, the session signature does not recover the granted key, or the
    ///      grant does not recover an operator. On success returns the operator actorId; the Keystore then binds
    ///      it to this authenticator and applies the operator's own liveness — the cascading-expiry cap.
    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        if (data.length < PREFIX_LEN) revert InvalidDataLength();

        address operatorAuthenticator = address(bytes20(data[0:20]));
        uint48 sessionExpiry = uint48(bytes6(data[20:26]));
        uint256 grantSigLen = uint256(uint16(bytes2(data[26:PREFIX_LEN])));

        uint256 subPrefixStart = PREFIX_LEN + grantSigLen;
        if (data.length < subPrefixStart + SUB_PREFIX_LEN) revert InvalidDataLength();

        address subAuthenticator = address(bytes20(data[subPrefixStart:subPrefixStart + 20]));
        uint256 subSigLen = uint256(uint16(bytes2(data[subPrefixStart + 20:subPrefixStart + SUB_PREFIX_LEN])));

        uint256 subSigStart = subPrefixStart + SUB_PREFIX_LEN;
        if (data.length < subSigStart + subSigLen) revert InvalidDataLength();
        if (operatorAuthenticator == address(this) || subAuthenticator == address(this)) revert RecursiveDelegation();

        // 1. Per-session expiry — the operator can mint an even-shorter-lived key than its own window.
        if (sessionExpiry != 0 && block.timestamp > sessionExpiry) return bytes32(0);

        // 2. Fresh signature over `hash` by the session key (this is the authentication).
        bytes32 sessionId = _recover(hash, subAuthenticator, data[subSigStart:subSigStart + subSigLen]);
        if (sessionId == bytes32(0)) return bytes32(0);

        // 3. The operator's grant over exactly that session leaf (this is the provenance / install).
        bytes32 grant = keccak256(abi.encode(GRANT_TYPEHASH, sessionId, subAuthenticator, sessionExpiry));
        actorId = _recover(grant, operatorAuthenticator, data[PREFIX_LEN:subPrefixStart]);
    }

    /// @notice The grant digest the operator signs to mint a session key. Off-chain tooling signs this.
    function grantHash(bytes32 sessionId, address subAuthenticator, uint48 sessionExpiry)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(GRANT_TYPEHASH, sessionId, subAuthenticator, sessionExpiry));
    }

    /// @notice Builds the `data` blob {authenticate} expects. Structural only — it does not run either scheme.
    function encode(
        address operatorAuthenticator,
        uint48 sessionExpiry,
        bytes calldata grantSig,
        address subAuthenticator,
        bytes calldata subSig
    ) external pure returns (bytes memory) {
        if (grantSig.length > type(uint16).max || subSig.length > type(uint16).max) {
            revert SigTooLong();
        }
        return abi.encodePacked(
            operatorAuthenticator,
            sessionExpiry,
            uint16(grantSig.length),
            grantSig,
            subAuthenticator,
            uint16(subSig.length),
            subSig
        );
    }

    /// @dev Recovers the actorId a signature over `hash` authorizes. K1 uses ecrecover; any other authenticator is
    ///      an {IAuthenticator} contract at its deterministic address. Returns bytes32(0) on any failure so the
    ///      caller fails closed without reverting.
    function _recover(bytes32 hash, address authenticator, bytes calldata sig) private view returns (bytes32) {
        if (authenticator == K1_AUTHENTICATOR) {
            if (sig.length != 65) return bytes32(0);
            (address recovered, ECDSA.RecoverError err,) =
                ECDSA.tryRecover(hash, uint8(sig[64]), bytes32(sig[0:32]), bytes32(sig[32:64]));
            if (err != ECDSA.RecoverError.NoError || recovered == address(0)) return bytes32(0);
            return recovered.fromAddress();
        }

        try IAuthenticator(authenticator).authenticate(hash, sig) returns (bytes32 id) {
            return id;
        } catch {
            return bytes32(0);
        }
    }
}
