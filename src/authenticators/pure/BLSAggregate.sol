// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {BLS} from "solady/utils/ext/ithaca/BLS.sol";

/// @notice Multi-message BLS12-381 helpers matching {BLSAuthenticator}.
///
///         Single-sig check (inclusion):
///           e(−pk, H(hash)) · e(G1, sig) == 1
///         Block aggregate (storage / re-execution), distinct per-tx hashes:
///           e(G1, ∑sig_i) · Π e(−pk_i, H(hash_i)) == 1
///
///         Per-tx `authenticate` cannot check a member against the aggregate —
///         that pairing needs every (hash, pk) at once. The protocol verifies
///         the aggregate once per compressed block; each BLS tx only stores a
///         pointer (aggregate id + pubkey).
library BLSAggregate {
    bytes32 private constant P_A = 0x000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd7;
    bytes32 private constant P_B = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    /// @dev Compressed sender_auth: authenticator(20) || 0xff || aggregateId(32) || pubKey(128)
    bytes1 internal constant POINTER_TAG = 0xff;

    function g1Generator() internal pure returns (BLS.G1Point memory) {
        return BLS.G1Point(
            bytes32(0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0f),
            bytes32(0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb),
            bytes32(0x0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4),
            bytes32(0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1)
        );
    }

    function pubkey(bytes32 sk) internal view returns (BLS.G1Point memory) {
        BLS.G1Point[] memory pts = new BLS.G1Point[](1);
        pts[0] = g1Generator();
        bytes32[] memory scalars = new bytes32[](1);
        scalars[0] = sk;
        return BLS.msm(pts, scalars);
    }

    function sign(bytes32 sk, bytes32 hash) internal view returns (BLS.G2Point memory) {
        BLS.G2Point[] memory pts = new BLS.G2Point[](1);
        pts[0] = BLS.hashToG2(abi.encodePacked(hash));
        bytes32[] memory scalars = new bytes32[](1);
        scalars[0] = sk;
        return BLS.msm(pts, scalars);
    }

    function verifyOne(bytes32 hash, BLS.G1Point memory pk, BLS.G2Point memory sig) internal view returns (bool) {
        BLS.G1Point[] memory g1s = new BLS.G1Point[](2);
        BLS.G2Point[] memory g2s = new BLS.G2Point[](2);
        g1s[0] = negateG1(pk);
        g1s[1] = g1Generator();
        g2s[0] = BLS.hashToG2(abi.encodePacked(hash));
        g2s[1] = sig;
        return BLS.pairing(g1s, g2s);
    }

    function aggregate(BLS.G2Point[] memory sigs) internal view returns (BLS.G2Point memory acc) {
        require(sigs.length != 0);
        acc = sigs[0];
        for (uint256 i = 1; i < sigs.length; i++) {
            acc = BLS.add(acc, sigs[i]);
        }
    }

    /// @notice One pairing product over every (hash, pk) plus the summed signature.
    function verifyAggregate(bytes32[] memory hashes, BLS.G1Point[] memory pks, BLS.G2Point memory sigAgg)
        internal
        view
        returns (bool)
    {
        uint256 n = hashes.length;
        require(n != 0 && n == pks.length);
        BLS.G1Point[] memory g1s = new BLS.G1Point[](n + 1);
        BLS.G2Point[] memory g2s = new BLS.G2Point[](n + 1);
        g1s[0] = g1Generator();
        g2s[0] = sigAgg;
        for (uint256 i; i < n; i++) {
            g1s[i + 1] = negateG1(pks[i]);
            g2s[i + 1] = BLS.hashToG2(abi.encodePacked(hashes[i]));
        }
        return BLS.pairing(g1s, g2s);
    }

    function encodeG1(BLS.G1Point memory p) internal pure returns (bytes memory) {
        return abi.encodePacked(p.x_a, p.x_b, p.y_a, p.y_b);
    }

    function encodeG2(BLS.G2Point memory p) internal pure returns (bytes memory) {
        return abi.encodePacked(p.x_c0_a, p.x_c0_b, p.x_c1_a, p.x_c1_b, p.y_c0_a, p.y_c0_b, p.y_c1_a, p.y_c1_b);
    }

    function decodeG1(bytes memory raw) internal pure returns (BLS.G1Point memory p) {
        require(raw.length == 128);
        p.x_a = bytes32(_word(raw, 0));
        p.x_b = bytes32(_word(raw, 32));
        p.y_a = bytes32(_word(raw, 64));
        p.y_b = bytes32(_word(raw, 96));
    }

    function decodeG2(bytes memory raw) internal pure returns (BLS.G2Point memory p) {
        require(raw.length == 256);
        p.x_c0_a = bytes32(_word(raw, 0));
        p.x_c0_b = bytes32(_word(raw, 32));
        p.x_c1_a = bytes32(_word(raw, 64));
        p.x_c1_b = bytes32(_word(raw, 96));
        p.y_c0_a = bytes32(_word(raw, 128));
        p.y_c0_b = bytes32(_word(raw, 160));
        p.y_c1_a = bytes32(_word(raw, 192));
        p.y_c1_b = bytes32(_word(raw, 224));
    }

    function actorId(BLS.G1Point memory pk) internal pure returns (bytes32) {
        return keccak256(encodeG1(pk));
    }

    function pointerAuth(address authenticator, bytes32 aggregateId, BLS.G1Point memory pk)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(authenticator, POINTER_TAG, aggregateId, encodeG1(pk));
    }

    function isPointerAuth(bytes memory senderAuth) internal pure returns (bool) {
        return senderAuth.length == 181 && senderAuth[20] == POINTER_TAG;
    }

    function negateG1(BLS.G1Point memory pk) internal pure returns (BLS.G1Point memory point) {
        point.x_a = pk.x_a;
        point.x_b = pk.x_b;
        uint256 y_a = uint256(pk.y_a);
        uint256 y_b = uint256(pk.y_b);
        unchecked {
            uint256 borrow = uint256(P_B) < y_b ? 1 : 0;
            point.y_b = bytes32(uint256(P_B) - y_b);
            point.y_a = bytes32(uint256(P_A) - y_a - borrow);
        }
    }

    function _word(bytes memory raw, uint256 off) private pure returns (bytes32 w) {
        assembly {
            w := mload(add(add(raw, 0x20), off))
        }
    }
}
