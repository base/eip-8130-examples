// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Keystore} from "eip-8130/Keystore.sol";
import {ActorId} from "eip-8130/libraries/ActorId.sol";
import {Scopes} from "eip-8130/libraries/Scopes.sol";
import {KeystoreTest} from "eip-8130-test/lib/KeystoreTest.sol";

import {MerkleSessionAuthenticator} from "../../../src/authenticators/sessions/MerkleSessionAuthenticator.sol";

/// @notice Committed-set (merkle root) session keys. One `actorId = root` slot commits many keys; a membership
///         proof PLUS the leaf's own fresh signature authorizes a tx. The root is registered with a BOUNDED
///         (non-admin) scope and a short expiry — that root-actor expiry caps every leaf (cascading).
contract MerkleSessionTest is KeystoreTest {
    MerkleSessionAuthenticator internal merkle;

    uint256 internal adminPk;
    uint256 internal sessionPk;
    uint256 internal otherPk;

    function setUp() public virtual override {
        super.setUp();
        merkle = new MerkleSessionAuthenticator();
        adminPk = _boundK1Pk(1);
        sessionPk = _boundK1Pk(2);
        otherPk = _boundK1Pk(3);
    }

    // ── Guards ──

    function test_authenticate_revert_dataTooShort(bytes32 hash, uint256 lenSeed) public {
        vm.expectRevert(MerkleSessionAuthenticator.InvalidDataLength.selector);
        merkle.authenticate(hash, new bytes(bound(lenSeed, 0, 27)));
    }

    function test_authenticate_revert_recursive(bytes32 hash) public {
        // subAuthenticator == address(merkle); no proof, empty subSig — long enough to reach the guard.
        bytes memory data = abi.encodePacked(address(merkle), uint48(0), uint16(0));
        vm.expectRevert(MerkleSessionAuthenticator.RecursiveDelegation.selector);
        merkle.authenticate(hash, data);
    }

    function test_authenticate_revert_badProofLength(bytes32 hash) public {
        bytes memory subSig = _signDigest(sessionPk, hash);
        // Valid sig so we reach the proof decode, then a 20-byte (non-multiple-of-32) co-path.
        bytes memory data = abi.encodePacked(k1Authenticator, uint48(0), uint16(subSig.length), subSig, new bytes(20));
        vm.expectRevert(MerkleSessionAuthenticator.InvalidDataLength.selector);
        merkle.authenticate(hash, data);
    }

    // ── Membership + fresh signature (the happy path) ──

    function test_success_singleLeaf_k1(bytes32 hash) public {
        (address account,) = _createK1Account(adminPk);
        bytes32 signerId = ActorId.fromAddress(vm.addr(sessionPk));
        bytes32 root = merkle.leafHash(signerId, k1Authenticator, 0); // 1-leaf tree: root == leaf
        _register(account, root, Scopes.OPERATOR, UNBOUNDED);

        bytes memory auth = _auth(k1Authenticator, 0, _signDigest(sessionPk, hash), new bytes32[](0));
        (bytes32 got, uint16 scope) = keystore.authenticateActor(account, hash, auth);
        assertEq(got, root);
        assertEq(scope, Scopes.OPERATOR); // never admin (scope 0)
    }

    function test_success_twoLeaf_k1(bytes32 hash) public {
        (address account,) = _createK1Account(adminPk);
        bytes32 signerId = ActorId.fromAddress(vm.addr(sessionPk));
        bytes32 leaf = merkle.leafHash(signerId, k1Authenticator, 0);
        bytes32 sibling = keccak256("some other committed leaf");
        bytes32 root = _hashPair(leaf, sibling);
        _register(account, root, Scopes.OPERATOR, UNBOUNDED);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;
        bytes memory auth = _auth(k1Authenticator, 0, _signDigest(sessionPk, hash), proof);
        (bytes32 got, uint16 scope) = keystore.authenticateActor(account, hash, auth);
        assertEq(got, root);
        assertEq(scope, Scopes.OPERATOR);
    }

    function test_success_p256Leaf(bytes32 hash) public {
        uint256 p256Pk = _boundP256Pk(42);
        (address account,) = _createK1Account(adminPk);
        bytes32 signerId = _p256ActorId(p256Pk);
        bytes32 root = merkle.leafHash(signerId, address(p256Authenticator), 0);
        _register(account, root, Scopes.OPERATOR, UNBOUNDED);

        bytes memory auth = _auth(address(p256Authenticator), 0, _p256SignData(p256Pk, hash), new bytes32[](0));
        (bytes32 got,) = keystore.authenticateActor(account, hash, auth);
        assertEq(got, root);
    }

    // ── A proof is provenance, not authentication (the Appendix-A invariant) ──

    function test_proofWithoutFreshSig_returnsZero(bytes32 hash) public view {
        // A public, replayable proof with no valid signature must never authenticate.
        bytes memory data = merkle.encode(k1Authenticator, 0, new bytes(65), new bytes32[](0));
        assertEq(merkle.authenticate(hash, data), bytes32(0));
    }

    function test_nonMemberFreshSig_reverts(bytes32 hash) public {
        // Register the set for `sessionPk`, then present a valid signature from a DIFFERENT key: it folds to a
        // different root, which is not the registered actor → the Keystore bind fails.
        (address account,) = _createK1Account(adminPk);
        bytes32 root = merkle.leafHash(ActorId.fromAddress(vm.addr(sessionPk)), k1Authenticator, 0);
        _register(account, root, Scopes.OPERATOR, UNBOUNDED);

        bytes memory auth = _auth(k1Authenticator, 0, _signDigest(otherPk, hash), new bytes32[](0));
        vm.expectRevert(Keystore.AuthenticatorMismatch.selector);
        keystore.authenticateActor(account, hash, auth);
    }

    // ── Expiry ──

    function test_expiredLeaf_returnsZero(bytes32 hash) public {
        vm.warp(1_000_000);
        uint48 expiry = uint48(block.timestamp - 1);
        bytes memory data = merkle.encode(k1Authenticator, expiry, _signDigest(sessionPk, hash), new bytes32[](0));
        assertEq(merkle.authenticate(hash, data), bytes32(0));
    }

    /// @dev Cascading expiry: even a leaf with no expiry (0) is capped by the ROOT actor's own expiry — when the
    ///      committed set lapses, every key in it stops at once, with no per-leaf revocation.
    function test_cascadingExpiry_rootActorCapsSet(bytes32 hash) public {
        vm.warp(1_000_000);
        (address account,) = _createK1Account(adminPk);
        bytes32 signerId = ActorId.fromAddress(vm.addr(sessionPk));
        bytes32 root = merkle.leafHash(signerId, k1Authenticator, 0); // leaf never expires on its own
        uint48 setExpiry = uint48(block.timestamp + 100);
        _register(account, root, Scopes.OPERATOR, setExpiry);

        bytes memory auth = _auth(k1Authenticator, 0, _signDigest(sessionPk, hash), new bytes32[](0));
        (bytes32 got,) = keystore.authenticateActor(account, hash, auth);
        assertEq(got, root); // live before the set lapses

        vm.warp(block.timestamp + 101);
        vm.expectRevert(Keystore.ActorExpired.selector);
        keystore.authenticateActor(account, hash, auth);
    }

    // ── Helpers ──

    function _register(address account, bytes32 root, uint16 scope, uint48 expiry) internal {
        _applyLocal(adminPk, account, _one(_authorizeChange(root, address(merkle), scope, expiry, "")));
    }

    function _auth(address subAuth, uint48 expiry, bytes memory subSig, bytes32[] memory proof)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(address(merkle), merkle.encode(subAuth, expiry, subSig, proof));
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }
}
