// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Script, console} from "forge-std/Script.sol";

import {BLS} from "solady/utils/ext/ithaca/BLS.sol";

import {BLSAuthenticator} from "../src/authenticators/pure/BLSAuthenticator.sol";
import {BLSAggregate} from "../src/authenticators/pure/BLSAggregate.sol";

/// @notice Demo: 10 BLS 8130 txs + 1 k1 in the middle, then compress the block.
///
///         sender_auth = authenticator(20) || data
///           BLS (inclusion): BLS_AUTH || sig_G2(256) || pubKey_G1(128)
///           BLS (stored):    BLS_AUTH || 0xff || aggregateId(32) || pubKey_G1(128)
///           K1:              address(1) || r(32) || s(32) || v(1)
///
///         Inclusion still uses the regular signature. Compression only matters
///         for block storage: one G2 for every BLS tx. Re-running the block
///         resolves the pointers and checks the aggregate once.
///
///         Run: forge script script/BLSAggregateDemo.s.sol
contract BLSAggregateDemo is Script {
    uint256 internal constant BLS_COUNT = 10;
    uint256 internal constant K1_INDEX = 5; // 0-based slot in the 11-tx block
    address internal constant K1_AUTHENTICATOR = address(1);

    struct DemoTx {
        uint256 index;
        bytes32 hash;
        bytes senderAuth;
        bool bls;
    }

    struct CompressedBlock {
        DemoTx[] txs;
        bytes32 aggregateId;
        bytes aggregateSig;
    }

    function run() external {
        BLSAuthenticator authenticator = new BLSAuthenticator();
        (DemoTx[] memory live, BLS.G2Point[] memory sigs, BLS.G1Point[] memory pks, bytes32[] memory hashes) =
            _signBlock(authenticator);

        _proveLive(authenticator, live);
        uint256 liveAuthBytes = _authBytes(live);

        BLS.G2Point memory sigAgg = BLSAggregate.aggregate(sigs);
        bytes32 aggregateId = keccak256(BLSAggregate.encodeG2(sigAgg));
        CompressedBlock memory stored = _compress(live, pks, aggregateId, sigAgg);
        uint256 storedAuthBytes = _authBytes(stored.txs) + stored.aggregateSig.length;

        console.log("=== 8130 BLS aggregate demo ===");
        console.log("txs: 10 BLS + 1 k1 at index", K1_INDEX);
        console.log("live sender_auth bytes (inclusion)", liveAuthBytes);
        console.log("stored sender_auth + aggregate bytes", storedAuthBytes);
        console.log("saved", liveAuthBytes - storedAuthBytes);
        console.log("aggregate id");
        console.logBytes32(aggregateId);

        _rerun(stored, hashes, pks, sigAgg);
        console.log("rerun: aggregate pairing ok; k1 left uncompressed");
    }

    function _signBlock(BLSAuthenticator authenticator)
        internal
        returns (DemoTx[] memory live, BLS.G2Point[] memory sigs, BLS.G1Point[] memory pks, bytes32[] memory hashes)
    {
        uint256 n = BLS_COUNT + 1;
        live = new DemoTx[](n);
        sigs = new BLS.G2Point[](BLS_COUNT);
        pks = new BLS.G1Point[](BLS_COUNT);
        hashes = new bytes32[](BLS_COUNT);

        uint256 blsI;
        uint256 k1Pk = uint256(keccak256("demo-k1"));
        for (uint256 i; i < n; i++) {
            bytes32 hash = keccak256(abi.encodePacked("eip-8130-demo-tx", i));
            live[i].index = i;
            live[i].hash = hash;
            if (i == K1_INDEX) {
                live[i].bls = false;
                live[i].senderAuth = _k1Auth(k1Pk, hash);
                continue;
            }
            bytes32 sk = bytes32(i + 1);
            BLS.G1Point memory pk = BLSAggregate.pubkey(sk);
            BLS.G2Point memory sig = BLSAggregate.sign(sk, hash);
            live[i].bls = true;
            live[i].senderAuth =
                abi.encodePacked(address(authenticator), BLSAggregate.encodeG2(sig), BLSAggregate.encodeG1(pk));
            sigs[blsI] = sig;
            pks[blsI] = pk;
            hashes[blsI] = hash;
            blsI++;
        }
    }

    function _proveLive(BLSAuthenticator authenticator, DemoTx[] memory live) internal view {
        for (uint256 i; i < live.length; i++) {
            bytes memory blob = _authData(live[i].senderAuth);
            if (live[i].bls) {
                require(authenticator.authenticate(live[i].hash, blob) != bytes32(0), "bls inclusion failed");
            } else {
                require(_k1Recover(live[i].hash, blob) != address(0), "k1 inclusion failed");
            }
        }
    }

    function _compress(DemoTx[] memory live, BLS.G1Point[] memory pks, bytes32 aggregateId, BLS.G2Point memory sigAgg)
        internal
        pure
        returns (CompressedBlock memory stored)
    {
        stored.txs = new DemoTx[](live.length);
        stored.aggregateId = aggregateId;
        stored.aggregateSig = BLSAggregate.encodeG2(sigAgg);
        uint256 blsI;
        for (uint256 i; i < live.length; i++) {
            stored.txs[i].index = live[i].index;
            stored.txs[i].hash = live[i].hash;
            stored.txs[i].bls = live[i].bls;
            if (!live[i].bls) {
                stored.txs[i].senderAuth = live[i].senderAuth;
                continue;
            }
            address authenticator = address(bytes20(live[i].senderAuth));
            stored.txs[i].senderAuth = BLSAggregate.pointerAuth(authenticator, aggregateId, pks[blsI]);
            blsI++;
        }
    }

    function _rerun(
        CompressedBlock memory stored,
        bytes32[] memory hashes,
        BLS.G1Point[] memory pks,
        BLS.G2Point memory sigAgg
    ) internal view {
        require(BLSAggregate.verifyAggregate(hashes, pks, sigAgg), "aggregate pairing failed");
        uint256 blsI;
        for (uint256 i; i < stored.txs.length; i++) {
            if (stored.txs[i].bls) {
                require(BLSAggregate.isPointerAuth(stored.txs[i].senderAuth), "expected pointer");
                require(bytes32(_word(stored.txs[i].senderAuth, 21)) == stored.aggregateId, "pointer id");
                require(BLSAggregate.actorId(pks[blsI]) == keccak256(_pubkeyFromPointer(stored.txs[i].senderAuth)));
                blsI++;
            } else {
                require(!BLSAggregate.isPointerAuth(stored.txs[i].senderAuth), "k1 must stay full");
                require(_k1Recover(stored.txs[i].hash, _authData(stored.txs[i].senderAuth)) != address(0));
            }
        }
        require(blsI == BLS_COUNT);
    }

    function _k1Auth(uint256 pk, bytes32 hash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(K1_AUTHENTICATOR, r, s, v);
    }

    function _k1Recover(bytes32 hash, bytes memory data) internal pure returns (address) {
        require(data.length == 65);
        return ecrecover(hash, uint8(data[64]), bytes32(_word(data, 0)), bytes32(_word(data, 32)));
    }

    function _authData(bytes memory senderAuth) internal pure returns (bytes memory out) {
        require(senderAuth.length >= 20);
        out = new bytes(senderAuth.length - 20);
        for (uint256 i; i < out.length; i++) {
            out[i] = senderAuth[i + 20];
        }
    }

    function _authBytes(DemoTx[] memory txs) internal pure returns (uint256 n) {
        for (uint256 i; i < txs.length; i++) {
            n += txs[i].senderAuth.length;
        }
    }

    function _pubkeyFromPointer(bytes memory senderAuth) internal pure returns (bytes memory pk) {
        pk = new bytes(128);
        for (uint256 i; i < 128; i++) {
            pk[i] = senderAuth[53 + i];
        }
    }

    function _word(bytes memory raw, uint256 off) internal pure returns (bytes32 w) {
        assembly {
            w := mload(add(add(raw, 0x20), off))
        }
    }
}
