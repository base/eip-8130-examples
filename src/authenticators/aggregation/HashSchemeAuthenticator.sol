// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IAuthenticator} from "eip-8130/interfaces/IAuthenticator.sol";

import {AGGREGATED, INLINE} from "./Types.sol";
import {IAggregationContext} from "./IAggregationContext.sol";

/// @notice Cheap stand-in for a native scheme authenticator (ML-DSA precompile, etc.).
///
///         actorId = keccak256(this ‖ pubkey)  — same derivation as the draft.
///         INLINE data:      0x00 ‖ pubkey(32) ‖ signature(32)
///         AGGREGATED data:  0x01 ‖ actorId(32)
///
///         "Native verify" is `signature == keccak256(hash ‖ pubkey)`. Swap this
///         contract for {AggregatableBLSAuthenticator} (or a future ML-DSA
///         authenticator) without changing {AggregationWrapper}.
contract HashSchemeAuthenticator is IAuthenticator {
    IAggregationContext public immutable CTX;

    error InvalidData();

    constructor(address ctx) {
        CTX = IAggregationContext(ctx);
    }

    function actorIdOf(bytes32 pubkey) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), pubkey));
    }

    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        if (data.length < 33) revert InvalidData();
        uint8 repr = uint8(data[0]);
        if (repr == INLINE) {
            if (data.length != 65) revert InvalidData();
            bytes32 pubkey = bytes32(data[1:33]);
            bytes32 signature = bytes32(data[33:65]);
            actorId = actorIdOf(pubkey);
            if (signature != keccak256(abi.encodePacked(hash, pubkey))) return bytes32(0);
        } else if (repr == AGGREGATED) {
            if (data.length != 33) revert InvalidData();
            actorId = bytes32(data[1:33]);
            if (!CTX.isFactProven(address(this), hash, actorId)) return bytes32(0);
        } else {
            revert InvalidData();
        }
    }
}
