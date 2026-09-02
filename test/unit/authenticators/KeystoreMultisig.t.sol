// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Keystore} from "eip-8130/Keystore.sol";
import {Scopes} from "eip-8130/libraries/Scopes.sol";
import {KeystoreTest} from "eip-8130-test/lib/KeystoreTest.sol";

import {KeystoreMultisigAuthenticator} from "../../../src/authenticators/keystore/KeystoreMultisigAuthenticator.sol";

/// @notice Keystore-bounded M-of-N: each signer is an 8130 account; each vouch is one
///         {Keystore.authenticateActor} hop (admin-only), matching {DelegateAuthenticator}.
contract KeystoreMultisigTest is KeystoreTest {
    KeystoreMultisigAuthenticator internal multisig;

    function setUp() public virtual override {
        super.setUp();
        multisig = new KeystoreMultisigAuthenticator(address(keystore));
    }

    // ── Guards ──

    function test_authenticate_revert_dataTooShort(bytes32 hash, uint256 lenSeed, uint256 fillSeed) public {
        uint256 len = bound(lenSeed, 0, 2);
        bytes memory data = new bytes(len);
        for (uint256 i; i < len; i++) {
            data[i] = bytes1(uint8(uint256(keccak256(abi.encode(fillSeed, i)))));
        }

        vm.expectRevert(KeystoreMultisigAuthenticator.InvalidDataLength.selector);
        multisig.authenticate(hash, data);
    }

    function test_authenticate_revert_thresholdZero(bytes32 hash) public {
        address[] memory signers = new address[](1);
        signers[0] = address(0x1);
        bytes memory data = _encode(0, signers, new address[](0), new bytes[](0));

        vm.expectRevert(KeystoreMultisigAuthenticator.InvalidThreshold.selector);
        multisig.authenticate(hash, data);
    }

    function test_authenticate_revert_thresholdAboveN(bytes32 hash) public {
        address[] memory signers = new address[](1);
        signers[0] = address(0x1);
        bytes memory data = abi.encodePacked(uint8(2), uint8(1), signers[0], uint8(0));

        vm.expectRevert(KeystoreMultisigAuthenticator.InvalidThreshold.selector);
        multisig.authenticate(hash, data);
    }

    function test_authenticate_revert_unsortedCommittee(bytes32 hash) public {
        address[] memory signers = new address[](2);
        signers[0] = address(0x2);
        signers[1] = address(0x1);
        bytes memory data = abi.encodePacked(uint8(1), uint8(2), signers[0], signers[1], uint8(0));

        vm.expectRevert(KeystoreMultisigAuthenticator.UnsortedSigners.selector);
        multisig.authenticate(hash, data);
    }

    function test_authenticate_revert_duplicateCommittee(bytes32 hash) public {
        address[] memory signers = new address[](2);
        signers[0] = address(0x1);
        signers[1] = address(0x1);
        bytes memory data = abi.encodePacked(uint8(1), uint8(2), signers[0], signers[1], uint8(0));

        vm.expectRevert(KeystoreMultisigAuthenticator.UnsortedSigners.selector);
        multisig.authenticate(hash, data);
    }

    function test_authenticate_revert_selfNestedAuthenticator(uint256 ownerSeed, bytes32 hash) public {
        uint256 pk = _boundK1Pk(ownerSeed);
        (address account,) = _createK1Account(pk);

        address[] memory signers = _one(account);
        bytes memory nested = abi.encodePacked(address(multisig), bytes20(0));
        bytes memory data = _encode(1, signers, signers, _oneBytes(nested));

        vm.expectRevert(KeystoreMultisigAuthenticator.RecursiveDelegation.selector);
        multisig.authenticate(hash, data);
    }

    function test_authenticate_revert_trailingBytes(uint256 ownerSeed, bytes32 hash) public {
        uint256 pk = _boundK1Pk(ownerSeed);
        (address account,) = _createK1Account(pk);

        address[] memory signers = _one(account);
        bytes memory nested = abi.encodePacked(k1Authenticator, _signDigest(pk, hash));
        bytes memory data = abi.encodePacked(_encode(1, signers, signers, _oneBytes(nested)), bytes1(0x00));

        vm.expectRevert(KeystoreMultisigAuthenticator.InvalidDataLength.selector);
        multisig.authenticate(hash, data);
    }

    function test_authenticate_revert_unsortedProofs(uint256 aSeed, uint256 bSeed, bytes32 hash) public {
        (uint256 pkA, uint256 pkB, address accountA, address accountB) = _twoK1(aSeed, bSeed);
        (address lo, address hi, uint256 pkLo, uint256 pkHi) =
            accountA < accountB ? (accountA, accountB, pkA, pkB) : (accountB, accountA, pkB, pkA);

        address[] memory committee = new address[](2);
        committee[0] = lo;
        committee[1] = hi;

        address[] memory proofs = new address[](2);
        proofs[0] = hi;
        proofs[1] = lo;
        bytes[] memory auths = new bytes[](2);
        auths[0] = abi.encodePacked(k1Authenticator, _signDigest(pkHi, hash));
        auths[1] = abi.encodePacked(k1Authenticator, _signDigest(pkLo, hash));

        vm.expectRevert(KeystoreMultisigAuthenticator.UnsortedSigners.selector);
        multisig.authenticate(hash, _encode(2, committee, proofs, auths));
    }

    // ── Auth failures (bytes32(0)) ──

    function test_authenticate_belowThresholdReturnsZero(uint256 aSeed, uint256 bSeed, bytes32 hash) public {
        (uint256 pkA, uint256 pkB, address accountA, address accountB) = _twoK1(aSeed, bSeed);
        (address lo, address hi, uint256 pkLo,) =
            accountA < accountB ? (accountA, accountB, pkA, pkB) : (accountB, accountA, pkB, pkA);

        address[] memory committee = new address[](2);
        committee[0] = lo;
        committee[1] = hi;
        bytes memory data = _encode(2, committee, _one(lo), _oneBytes(abi.encodePacked(k1Authenticator, _signDigest(pkLo, hash))));

        assertEq(multisig.authenticate(hash, data), bytes32(0));
    }

    function test_authenticate_unknownSignerReturnsZero(uint256 ownerSeed, uint256 outsiderSeed, bytes32 hash) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 outsiderPk = _boundK1Pk(outsiderSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(outsiderPk));

        (address account,) = _createK1Account(ownerPk);
        (address outsider,) = _createK1AccountWithSalt(outsiderPk, bytes32(uint256(2)));

        address[] memory committee = _one(account);
        bytes memory nested = abi.encodePacked(k1Authenticator, _signDigest(outsiderPk, hash));
        bytes memory data = _encode(1, committee, _one(outsider), _oneBytes(nested));

        assertEq(multisig.authenticate(hash, data), bytes32(0));
    }

    function test_authenticate_wrongKeyReturnsZero(uint256 ownerSeed, uint256 wrongSeed, bytes32 hash) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 wrongPk = _boundK1Pk(wrongSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(wrongPk));

        (address account,) = _createK1Account(ownerPk);
        bytes memory nested = abi.encodePacked(k1Authenticator, _signDigest(wrongPk, hash));
        bytes memory data = _encode(1, _one(account), _one(account), _oneBytes(nested));

        assertEq(multisig.authenticate(hash, data), bytes32(0));
    }

    function test_authenticate_wrongHashReturnsZero(uint256 ownerSeed, bytes32 hash) public {
        uint256 pk = _boundK1Pk(ownerSeed);
        (address account,) = _createK1Account(pk);

        bytes memory nested = abi.encodePacked(k1Authenticator, _signDigest(pk, hash));
        bytes memory data = _encode(1, _one(account), _one(account), _oneBytes(nested));

        assertEq(multisig.authenticate(keccak256(abi.encodePacked(hash)), data), bytes32(0));
    }

    function test_authenticate_operatorCannotVouch(uint256 ownerSeed, uint256 signerSeed, bytes32 hash) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 signerPk = _boundK1Pk(signerSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(signerPk));

        (address account,) = _createK1Account(ownerPk);
        _authorizeActorWithScope(
            account, ownerPk, bytes32(uint256(uint160(vm.addr(signerPk)))), address(k1Authenticator), Scopes.OPERATOR
        );

        bytes memory nested = abi.encodePacked(k1Authenticator, _signDigest(signerPk, hash));
        bytes memory data = _encode(1, _one(account), _one(account), _oneBytes(nested));

        assertEq(multisig.authenticate(hash, data), bytes32(0));
    }

    // ── Happy paths ──

    function test_authenticate_success_1of1(uint256 ownerSeed, bytes32 hash) public {
        uint256 pk = _boundK1Pk(ownerSeed);
        (address account,) = _createK1Account(pk);

        address[] memory signers = _one(account);
        bytes memory nested = abi.encodePacked(k1Authenticator, _signDigest(pk, hash));
        bytes memory data = _encode(1, signers, signers, _oneBytes(nested));

        assertEq(multisig.authenticate(hash, data), keccak256(abi.encodePacked(uint8(1), uint8(1), account)));
    }

    function test_authenticate_success_2of3_skipsMiddle(uint256 aSeed, uint256 bSeed, uint256 cSeed, bytes32 hash)
        public
    {
        (address[] memory committee, uint256[] memory pks) = _threeK1(aSeed, bSeed, cSeed);

        address[] memory proofs = new address[](2);
        proofs[0] = committee[0];
        proofs[1] = committee[2];
        bytes[] memory auths = new bytes[](2);
        auths[0] = abi.encodePacked(k1Authenticator, _signDigest(pks[0], hash));
        auths[1] = abi.encodePacked(k1Authenticator, _signDigest(pks[2], hash));

        bytes memory data = _encode(2, committee, proofs, auths);
        assertEq(multisig.authenticate(hash, data), _committeeId(2, committee));
    }

    function test_authenticate_success_mixedK1AndP256(uint256 k1Seed, uint256 p256Seed, bytes32 hash) public {
        uint256 k1Pk = _boundK1Pk(k1Seed);
        uint256 p256Pk = _boundP256Pk(p256Seed);
        (address k1Account,) = _createK1Account(k1Pk);
        (address p256Account,) = _createP256Account(p256Pk, bytes32(uint256(2)));
        vm.assume(k1Account != p256Account);

        (address lo, address hi, bytes memory authLo, bytes memory authHi) = k1Account < p256Account
            ? (
                k1Account,
                p256Account,
                abi.encodePacked(k1Authenticator, _signDigest(k1Pk, hash)),
                abi.encodePacked(address(p256Authenticator), _p256SignData(p256Pk, hash))
            )
            : (
                p256Account,
                k1Account,
                abi.encodePacked(address(p256Authenticator), _p256SignData(p256Pk, hash)),
                abi.encodePacked(k1Authenticator, _signDigest(k1Pk, hash))
            );

        address[] memory committee = new address[](2);
        committee[0] = lo;
        committee[1] = hi;
        address[] memory proofs = new address[](2);
        proofs[0] = lo;
        proofs[1] = hi;
        bytes[] memory auths = new bytes[](2);
        auths[0] = authLo;
        auths[1] = authHi;

        bytes memory data = _encode(2, committee, proofs, auths);
        assertEq(multisig.authenticate(hash, data), _committeeId(2, committee));
    }

    function test_authenticate_endToEnd_actorOnThirdAccount(uint256 aSeed, uint256 bSeed, bytes32 hash) public {
        (uint256 pkA, uint256 pkB, address accountA, address accountB) = _twoK1(aSeed, bSeed);
        (address lo, address hi, uint256 pkLo, uint256 pkHi) =
            accountA < accountB ? (accountA, accountB, pkA, pkB) : (accountB, accountA, pkB, pkA);

        address[] memory committee = new address[](2);
        committee[0] = lo;
        committee[1] = hi;
        bytes32 actorId = _committeeId(2, committee);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: actorId, authenticator: address(multisig), scope: 0, policyData: ""
        });
        address wallet = keystore.createAccount(
            bytes32(uint256(9)), _computeERC1167Bytecode(defaultAccountImplementation), actors
        );

        address[] memory proofs = new address[](2);
        proofs[0] = lo;
        proofs[1] = hi;
        bytes[] memory auths = new bytes[](2);
        auths[0] = abi.encodePacked(k1Authenticator, _signDigest(pkLo, hash));
        auths[1] = abi.encodePacked(k1Authenticator, _signDigest(pkHi, hash));
        bytes memory data = _encode(2, committee, proofs, auths);

        (bytes32 got, uint16 scope) =
            keystore.authenticateActor(wallet, hash, abi.encodePacked(address(multisig), data));
        assertEq(got, actorId);
        assertEq(scope, 0);
    }

    // ── Encoding helpers (committeeActorId / encode) ──

    function test_committeeActorId_matchesManual(uint256 aSeed, uint256 bSeed, uint256 cSeed) public {
        (address[] memory committee,) = _threeK1(aSeed, bSeed, cSeed);
        assertEq(multisig.committeeActorId(2, committee), _committeeId(2, committee));
    }

    function test_committeeActorId_revert_badThreshold(uint256 aSeed, uint256 bSeed, uint256 cSeed) public {
        (address[] memory committee,) = _threeK1(aSeed, bSeed, cSeed);
        vm.expectRevert(KeystoreMultisigAuthenticator.InvalidThreshold.selector);
        multisig.committeeActorId(4, committee);
        vm.expectRevert(KeystoreMultisigAuthenticator.InvalidThreshold.selector);
        multisig.committeeActorId(0, committee);
    }

    function test_encode_roundTripsThroughAuthenticate(uint256 aSeed, uint256 bSeed, uint256 cSeed, bytes32 hash)
        public
    {
        (address[] memory committee, uint256[] memory pks) = _threeK1(aSeed, bSeed, cSeed);

        address[] memory proofs = new address[](2);
        proofs[0] = committee[0];
        proofs[1] = committee[2];
        bytes[] memory auths = new bytes[](2);
        auths[0] = abi.encodePacked(k1Authenticator, _signDigest(pks[0], hash));
        auths[1] = abi.encodePacked(k1Authenticator, _signDigest(pks[2], hash));

        // The on-chain builder must produce the exact bytes the hand-rolled test encoder does...
        bytes memory built = multisig.encode(2, committee, proofs, auths);
        assertEq(built, _encode(2, committee, proofs, auths));

        // ...and that blob authenticates to the committee's actorId.
        assertEq(multisig.authenticate(hash, built), multisig.committeeActorId(2, committee));
    }

    function test_encode_revert_proofLengthMismatch(uint256 aSeed, uint256 bSeed) public {
        (,, address accountA, address accountB) = _twoK1(aSeed, bSeed);
        address[] memory committee = new address[](2);
        (committee[0], committee[1]) =
            accountA < accountB ? (accountA, accountB) : (accountB, accountA);

        vm.expectRevert(KeystoreMultisigAuthenticator.ProofLengthMismatch.selector);
        multisig.encode(1, committee, _one(committee[0]), new bytes[](0));
    }

    function test_encode_revert_unsortedProofs(uint256 aSeed, uint256 bSeed, bytes32 hash) public {
        (uint256 pkA, uint256 pkB, address accountA, address accountB) = _twoK1(aSeed, bSeed);
        (address lo, address hi, uint256 pkLo, uint256 pkHi) =
            accountA < accountB ? (accountA, accountB, pkA, pkB) : (accountB, accountA, pkB, pkA);

        address[] memory committee = new address[](2);
        committee[0] = lo;
        committee[1] = hi;
        address[] memory proofs = new address[](2);
        proofs[0] = hi;
        proofs[1] = lo;
        bytes[] memory auths = new bytes[](2);
        auths[0] = abi.encodePacked(k1Authenticator, _signDigest(pkHi, hash));
        auths[1] = abi.encodePacked(k1Authenticator, _signDigest(pkLo, hash));

        vm.expectRevert(KeystoreMultisigAuthenticator.UnsortedSigners.selector);
        multisig.encode(2, committee, proofs, auths);
    }

    // ── Helpers ──

    function _encode(uint8 threshold, address[] memory committee, address[] memory proofSigners, bytes[] memory auths)
        internal
        pure
        returns (bytes memory data)
    {
        data = abi.encodePacked(threshold, uint8(committee.length));
        for (uint256 i; i < committee.length; i++) {
            data = abi.encodePacked(data, committee[i]);
        }
        data = abi.encodePacked(data, uint8(proofSigners.length));
        for (uint256 i; i < proofSigners.length; i++) {
            data = abi.encodePacked(data, proofSigners[i], uint16(auths[i].length), auths[i]);
        }
    }

    function _committeeId(uint8 threshold, address[] memory committee) internal pure returns (bytes32) {
        bytes memory prefix = abi.encodePacked(threshold, uint8(committee.length));
        for (uint256 i; i < committee.length; i++) {
            prefix = abi.encodePacked(prefix, committee[i]);
        }
        return keccak256(prefix);
    }

    function _one(address a) internal pure returns (address[] memory out) {
        out = new address[](1);
        out[0] = a;
    }

    function _oneBytes(bytes memory b) internal pure returns (bytes[] memory out) {
        out = new bytes[](1);
        out[0] = b;
    }

    function _twoK1(uint256 aSeed, uint256 bSeed)
        internal
        returns (uint256 pkA, uint256 pkB, address accountA, address accountB)
    {
        pkA = _boundK1Pk(aSeed);
        pkB = _boundK1Pk(bSeed);
        vm.assume(vm.addr(pkA) != vm.addr(pkB));
        (accountA,) = _createK1Account(pkA);
        (accountB,) = _createK1AccountWithSalt(pkB, bytes32(uint256(2)));
        vm.assume(accountA != accountB);
    }

    function _threeK1(uint256 aSeed, uint256 bSeed, uint256 cSeed)
        internal
        returns (address[] memory committee, uint256[] memory pks)
    {
        uint256 pkA = _boundK1Pk(aSeed);
        uint256 pkB = _boundK1Pk(bSeed);
        uint256 pkC = _boundK1Pk(cSeed);
        vm.assume(vm.addr(pkA) != vm.addr(pkB) && vm.addr(pkA) != vm.addr(pkC) && vm.addr(pkB) != vm.addr(pkC));

        (address a,) = _createK1Account(pkA);
        (address b,) = _createK1AccountWithSalt(pkB, bytes32(uint256(2)));
        (address c,) = _createK1AccountWithSalt(pkC, bytes32(uint256(3)));
        vm.assume(a != b && a != c && b != c);

        committee = new address[](3);
        pks = new uint256[](3);
        (committee[0], pks[0]) = (a, pkA);
        (committee[1], pks[1]) = (b, pkB);
        (committee[2], pks[2]) = (c, pkC);

        // Insertion sort by address, keeping pks aligned.
        for (uint256 i = 1; i < 3; i++) {
            address addr = committee[i];
            uint256 pk = pks[i];
            uint256 j = i;
            while (j > 0 && committee[j - 1] > addr) {
                committee[j] = committee[j - 1];
                pks[j] = pks[j - 1];
                j--;
            }
            committee[j] = addr;
            pks[j] = pk;
        }
    }

    function _createP256Account(uint256 pk, bytes32 salt) internal returns (address account, bytes32 actorId) {
        actorId = _p256ActorId(pk);
        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: actorId, authenticator: address(p256Authenticator), scope: 0, policyData: ""
        });
        account = keystore.createAccount(salt, _computeERC1167Bytecode(defaultAccountImplementation), actors);
    }
}
