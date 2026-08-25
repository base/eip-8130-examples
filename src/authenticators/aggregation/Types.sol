// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @dev Representation byte from the signature-aggregation draft. Builder-chosen; not signed.
uint8 constant INLINE = 0x00;
uint8 constant AGGREGATED = 0x01;

uint8 constant DEP_SENDER = 0x00;
uint8 constant DEP_PAYER = 0x01;
uint8 constant DEP_THIRD = 0x02;

struct Dependency {
    uint8 kind;
    bytes32 hash;
    bytes32 actorId;
}
