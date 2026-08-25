// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {IAuthenticator} from "eip-8130/interfaces/IAuthenticator.sol";

import {BLS} from "solady/utils/ext/ithaca/BLS.sol";

import {BLSAggregate} from "../pure/BLSAggregate.sol";
import {AGGREGATED, INLINE} from "./Types.sol";
import {IAggregationContext} from "./IAggregationContext.sol";

/// @notice BLS scheme authenticator with the draft's INLINE / AGGREGATED representations.
///
///         actorId = keccak256(this ‖ pubKey_G1)
///         INLINE:     0x00 ‖ pubKey_G1(128) ‖ sig_G2(256)
///         AGGREGATED: 0x01 ‖ actorId(32)   — fact must be on {IAggregationContext}
contract AggregatableBLSAuthenticator is IAuthenticator {
    IAggregationContext public immutable CTX;

    error InvalidData();

    constructor(address ctx) {
        CTX = IAggregationContext(ctx);
    }

    function actorIdOf(bytes memory pubkey) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), pubkey));
    }

    function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId) {
        if (data.length < 33) revert InvalidData();
        uint8 repr = uint8(data[0]);
        if (repr == INLINE) {
            if (data.length != 385) revert InvalidData();
            bytes memory pkRaw = data[1:129];
            BLS.G2Point memory sig = BLSAggregate.decodeG2(data[129:385]);
            actorId = actorIdOf(pkRaw);
            if (!BLSAggregate.verifyOne(hash, BLSAggregate.decodeG1(pkRaw), sig)) return bytes32(0);
        } else if (repr == AGGREGATED) {
            if (data.length != 33) revert InvalidData();
            actorId = bytes32(data[1:33]);
            if (!CTX.isFactProven(address(this), hash, actorId)) return bytes32(0);
        } else {
            revert InvalidData();
        }
    }
}
