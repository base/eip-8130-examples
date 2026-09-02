// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

import {IAuthenticator} from "eip-8130/interfaces/IAuthenticator.sol";
import {ActorId} from "eip-8130/libraries/ActorId.sol";

import {IHomeChainConfigProver} from "./IHomeChainConfigProver.sol";

/// @notice A cross-chain {DelegateAuthenticator}: honor, on this chain, a key that is authorized as ADMIN of an
///         account on a remote "home" chain. Where {DelegateAuthenticator} reads the vouching config from the
///         local Keystore (one call), this proves it from the home chain (one {IHomeChainConfigProver} hop).
///
///         actorId = keccak256(homeChainId (32) || homeAccount (20))
///                 The stable identity of "whoever is admin of `homeAccount` on `homeChainId`" — independent of
///                 which home admin key signs (mirrors the committee id in the Keystore multisig).
///
///         data  = homeChainId (32) || homeAccount (20) || nestedAuthLen (2)
///                 || nestedAuth (nestedAuthLen) || proof (tail)
///                 nestedAuth = homeAuthenticator (20) || scheme signature over `hash`
///                              homeAuthenticator == address(1) is the built-in K1 sentinel (r‖s‖v, 65 bytes);
///                              any other address is an {IAuthenticator} contract (P256, WebAuthn, …) called
///                              locally at its deterministic CREATE2 address.
///                 proof      = {IHomeChainConfigProver}-specific bytes.
///
///         Security: the proof only attests slowly-changing home state, so a fresh `hash`-bound signature is ALSO
///         required each call (like the nested signature in {DelegateAuthenticator}) — the proof alone can never
///         authorize an arbitrary `hash`.
///
///         Intended pattern ("sync + expire"): register this actorId as an admin on the L2, then use the
///         proof-carrying admin only to authorize a cheap short-lived (e.g. 1-week) operator via a Keystore
///         change. Day-to-day transactions use that operator with no proof; when it lapses, re-authorize with a
///         fresh home proof.
contract HomeChainAuthenticator is IAuthenticator {
    using ActorId for address;

    /// @notice The built-in secp256k1 sentinel (Keystore K1_AUTHENTICATOR). Not a contract — verified via ecrecover.
    address internal constant K1_AUTHENTICATOR = address(1);

    /// @notice The offset at which `nestedAuth` begins: homeChainId(32) || homeAccount(20) || nestedAuthLen(2).
    uint256 internal constant PREFIX_LEN = 54;

    /// @notice The home-chain config prover (state-proof verifier). See {IHomeChainConfigProver}.
    IHomeChainConfigProver public immutable PROVER;

    /// @notice `data` is shorter than the fixed prefix, the nested-auth slice overruns the buffer, or the nested
    ///         auth is shorter than its 20-byte authenticator prefix.
    error InvalidDataLength();

    /// @notice The nested authenticator points back to this contract; only one hop is permitted.
    error RecursiveDelegation();

    /// @notice An {encode} nested auth blob is longer than the 2-byte length prefix can express.
    error NestedAuthTooLong();

    /// @notice Deploys the authenticator bound to a home-chain config prover.
    /// @param prover Address of the {IHomeChainConfigProver} implementation.
    constructor(address prover) {
        PROVER = IHomeChainConfigProver(prover);
    }

    /// @notice Authenticates `hash` as the home account's admin, given a home-config proof and a fresh signature.
    ///
    /// @dev Reverts with InvalidDataLength or RecursiveDelegation on malformed input. Returns bytes32(0) when the
    ///      signature does not recover a home actor, the proof fails, or the proven home config is not a live
    ///      admin bound to the presented authenticator. On success returns the home actorId.
    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        if (data.length < PREFIX_LEN) revert InvalidDataLength();

        uint256 homeChainId = uint256(bytes32(data[0:32]));
        address homeAccount = address(bytes20(data[32:52]));
        uint256 nestedLen = uint256(uint16(bytes2(data[52:PREFIX_LEN])));

        uint256 nestedEnd = PREFIX_LEN + nestedLen;
        if (nestedLen < 20 || data.length < nestedEnd) revert InvalidDataLength();

        bytes calldata nestedAuth = data[PREFIX_LEN:nestedEnd];
        bytes calldata proof = data[nestedEnd:];

        address homeAuthenticator = address(bytes20(nestedAuth[0:20]));
        if (homeAuthenticator == address(this)) revert RecursiveDelegation();

        // 1. Verify the fresh signature over `hash` LOCALLY, recovering the home actorId it authorizes.
        bytes32 signerActorId = _recover(hash, homeAuthenticator, nestedAuth[20:]);
        if (signerActorId == bytes32(0)) return bytes32(0);

        // 2. Prove that on the home chain, that actor is a live ADMIN bound to the same authenticator.
        if (!_provenAdmin(homeChainId, homeAccount, signerActorId, homeAuthenticator, proof)) {
            return bytes32(0);
        }

        actorId = homeActorId(homeChainId, homeAccount);
    }

    /// @notice The actorId committed by a home chain + account. Register this on the L2 account (bound to this
    ///         authenticator) to accept the home account's admins.
    function homeActorId(uint256 homeChainId, address homeAccount) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(homeChainId, homeAccount));
    }

    /// @notice Builds the `data` blob {authenticate} expects.
    ///
    /// @dev `nestedAuth` is homeAuthenticator(20) ‖ scheme signature; `proof` is prover-specific. Structural
    ///      only — it does not run the scheme or the prover. Reverts with InvalidDataLength or NestedAuthTooLong.
    function encode(uint256 homeChainId, address homeAccount, bytes calldata nestedAuth, bytes calldata proof)
        external
        pure
        returns (bytes memory)
    {
        if (nestedAuth.length < 20) revert InvalidDataLength();
        if (nestedAuth.length > type(uint16).max) revert NestedAuthTooLong();
        return abi.encodePacked(homeChainId, homeAccount, uint16(nestedAuth.length), nestedAuth, proof);
    }

    /// @dev Recovers the home actorId a fresh `hash` signature authorizes, verified locally. K1 uses ecrecover;
    ///      any other authenticator is an {IAuthenticator} contract at its deterministic address. Returns
    ///      bytes32(0) on any failure so the caller can fail closed without reverting.
    function _recover(bytes32 hash, address homeAuthenticator, bytes calldata schemeData)
        private
        view
        returns (bytes32)
    {
        if (homeAuthenticator == K1_AUTHENTICATOR) {
            if (schemeData.length != 65) return bytes32(0);
            (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(
                hash, uint8(schemeData[64]), bytes32(schemeData[0:32]), bytes32(schemeData[32:64])
            );
            if (err != ECDSA.RecoverError.NoError || recovered == address(0)) return bytes32(0);
            return recovered.fromAddress();
        }

        try IAuthenticator(homeAuthenticator).authenticate(hash, schemeData) returns (bytes32 id) {
            return id;
        } catch {
            return bytes32(0);
        }
    }

    /// @dev True iff the home chain proves `actorId` is a live admin (scope 0x00, unexpired) bound to
    ///      `homeAuthenticator`. Admin-only mirrors {DelegateAuthenticator} — an operator on the home chain must
    ///      not be able to vouch cross-chain. A reverting/failed proof fails closed.
    function _provenAdmin(
        uint256 homeChainId,
        address homeAccount,
        bytes32 actorId,
        address homeAuthenticator,
        bytes calldata proof
    ) private view returns (bool) {
        try PROVER.proveActorConfig(homeChainId, homeAccount, actorId, proof) returns (
            address authenticator, uint48 expiry, uint16 scope
        ) {
            if (authenticator == address(0)) return false; // not live on the home chain
            if (authenticator != homeAuthenticator) return false; // bound to a different scheme
            if (scope != 0) return false; // admin-only vouch
            if (expiry != 0 && expiry <= block.timestamp) return false; // expired
            return true;
        } catch {
            return false;
        }
    }
}
