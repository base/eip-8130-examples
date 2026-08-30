// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "eip-8130/Keystore.sol";

/// @notice Pack {Keystore.InitialActor}[] into EIP-1153 transient slots for one call frame.
///         Keystore's {getImportActors} is a no-arg STATICCALL, so the only way to feed it calldata
///         without SSTORE is to stash here before {importAccount} and read it back in that nested call.
library TransientActors {
    uint256 private constant _BASE = 0x81300000;

    error BadPolicyData();

    function store(Keystore.InitialActor[] calldata actors, uint256 chainId) internal {
        uint256 n = actors.length;
        assembly ("memory-safe") {
            tstore(_BASE, n)
            tstore(add(_BASE, 1), chainId)
        }
        for (uint256 i; i < n; i++) {
            bytes calldata pol = actors[i].policyData;
            if (pol.length != 0 && pol.length != 52) revert BadPolicyData();
            bytes32 id = actors[i].actorId;
            uint256 packed = uint256(uint160(actors[i].authenticator)) | (uint256(actors[i].scope) << 160)
                | (uint256(pol.length) << 176);
            bytes32 w0;
            bytes32 w1;
            if (pol.length == 52) {
                w0 = bytes32(pol[0:32]);
                w1 = bytes32(pol[32:52]);
            }
            uint256 slot = _BASE + 2 + i * 4;
            assembly ("memory-safe") {
                tstore(slot, id)
                tstore(add(slot, 1), packed)
                tstore(add(slot, 2), w0)
                tstore(add(slot, 3), w1)
            }
        }
    }

    function clear() internal {
        assembly ("memory-safe") {
            tstore(_BASE, 0)
            tstore(add(_BASE, 1), 0)
        }
    }

    function load() internal view returns (Keystore.InitialActor[] memory actors, uint256 chainId) {
        uint256 n;
        assembly ("memory-safe") {
            n := tload(_BASE)
            chainId := tload(add(_BASE, 1))
        }
        actors = new Keystore.InitialActor[](n);
        for (uint256 i; i < n; i++) {
            uint256 slot = _BASE + 2 + i * 4;
            bytes32 id;
            uint256 packed;
            bytes32 w0;
            bytes32 w1;
            assembly ("memory-safe") {
                id := tload(slot)
                packed := tload(add(slot, 1))
                w0 := tload(add(slot, 2))
                w1 := tload(add(slot, 3))
            }
            uint256 polLen = packed >> 176;
            bytes memory pol;
            if (polLen == 52) pol = abi.encodePacked(w0, bytes20(w1));
            actors[i] = Keystore.InitialActor({
                actorId: id, authenticator: address(uint160(packed)), scope: uint16(packed >> 160), policyData: pol
            });
        }
    }
}
