// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Test} from "forge-std/Test.sol";

import {BLS} from "solady/utils/ext/ithaca/BLS.sol";

import {BLSAuthenticator} from "../../../src/authenticators/pure/BLSAuthenticator.sol";
import {BLSAggregate} from "../../../src/authenticators/pure/BLSAggregate.sol";

contract BLSAggregateTest is Test {
    BLSAuthenticator internal authenticator;

    function setUp() public {
        authenticator = new BLSAuthenticator();
    }

    function test_signMatchesAuthenticator() public {
        bytes32 sk = bytes32(uint256(7));
        bytes32 hash = keccak256("one");
        BLS.G1Point memory pk = BLSAggregate.pubkey(sk);
        BLS.G2Point memory sig = BLSAggregate.sign(sk, hash);

        assertTrue(BLSAggregate.verifyOne(hash, pk, sig));
        bytes memory data = abi.encodePacked(BLSAggregate.encodeG2(sig), BLSAggregate.encodeG1(pk));
        assertEq(authenticator.authenticate(hash, data), BLSAggregate.actorId(pk));
        assertEq(authenticator.authenticate(keccak256("other"), data), bytes32(0));
    }

    function test_aggregateTenPlusK1() public {
        uint256 n = 10;
        BLS.G2Point[] memory sigs = new BLS.G2Point[](n);
        BLS.G1Point[] memory pks = new BLS.G1Point[](n);
        bytes32[] memory hashes = new bytes32[](n);

        for (uint256 i; i < n; i++) {
            hashes[i] = keccak256(abi.encodePacked("tx", i));
            bytes32 sk = bytes32(i + 1);
            pks[i] = BLSAggregate.pubkey(sk);
            sigs[i] = BLSAggregate.sign(sk, hashes[i]);
            assertTrue(BLSAggregate.verifyOne(hashes[i], pks[i], sigs[i]));
        }

        BLS.G2Point memory agg = BLSAggregate.aggregate(sigs);
        assertTrue(BLSAggregate.verifyAggregate(hashes, pks, agg));

        hashes[3] = keccak256("tamper");
        assertFalse(BLSAggregate.verifyAggregate(hashes, pks, agg));
    }

    function test_pointerAuthLayout() public {
        BLS.G1Point memory pk = BLSAggregate.pubkey(bytes32(uint256(1)));
        bytes32 id = keccak256("agg");
        bytes memory auth = BLSAggregate.pointerAuth(address(authenticator), id, pk);
        assertTrue(BLSAggregate.isPointerAuth(auth));
        assertEq(auth.length, 181);
        assertEq(address(bytes20(auth)), address(authenticator));
        assertEq(uint8(auth[20]), uint8(BLSAggregate.POINTER_TAG));
    }
}
