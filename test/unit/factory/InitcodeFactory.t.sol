// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Call} from "eip-8130/accounts/DefaultAccount.sol";
import {Keystore} from "eip-8130/Keystore.sol";
import {ActorId} from "eip-8130/libraries/ActorId.sol";
import {KeystoreTest} from "eip-8130-test/lib/KeystoreTest.sol";

import {InitcodeAccount} from "../../../src/factory/InitcodeAccount.sol";
import {InitcodeFactory} from "../../../src/factory/InitcodeFactory.sol";

contract InitcodeMockTarget {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }
}

contract InitcodeFactoryTest is KeystoreTest {
    uint256 constant OWNER_PK = 800;
    uint256 constant GUARDIAN_PK = 801;

    InitcodeFactory internal factory;
    InitcodeMockTarget internal target;

    function setUp() public override {
        super.setUp();
        factory = new InitcodeFactory(address(keystore));
        target = new InitcodeMockTarget();
    }

    function _k1(uint256 pk, uint16 scope) internal view returns (Keystore.InitialActor memory) {
        return Keystore.InitialActor({
            actorId: ActorId.fromAddress(vm.addr(pk)),
            authenticator: address(k1Authenticator),
            scope: scope,
            policyData: ""
        });
    }

    function _ownerAndGuardian() internal view returns (Keystore.InitialActor[] memory actors) {
        actors = new Keystore.InitialActor[](2);
        Keystore.InitialActor memory a = _k1(OWNER_PK, 0);
        Keystore.InitialActor memory b = _k1(GUARDIAN_PK, 0);
        (actors[0], actors[1]) = a.actorId < b.actorId ? (a, b) : (b, a);
    }

    function test_deploy_constructorThenImport() public {
        Keystore.InitialActor[] memory actors = _ownerAndGuardian();
        bytes32 salt = bytes32(uint256(1));
        address predicted = factory.computeAddress(salt, factory.actorsHash(actors));
        address account = factory.deploy(salt, actors);

        assertEq(account, predicted);
        assertEq(InitcodeAccount(payable(account)).ACTORS_HASH(), factory.actorsHash(actors));
        assertEq(keystore.getChangeSequences(account).localSequence, 1);
        assertTrue(_isActor(account, ActorId.fromAddress(vm.addr(OWNER_PK))));
        assertTrue(_isActor(account, ActorId.fromAddress(vm.addr(GUARDIAN_PK))));

        // Stash is gone: import digest no longer auto-validates.
        bytes32 digest = keystore.computeImportDigest(account, block.chainid, actors);
        assertEq(InitcodeAccount(payable(account)).isValidSignature(digest, ""), bytes4(0xffffffff));
    }

    function test_deploy_executeBatch() public {
        address account = factory.deploy(bytes32(uint256(2)), _ownerAndGuardian());
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(target), 0, abi.encodeCall(InitcodeMockTarget.setValue, (4)));
        vm.prank(account);
        InitcodeAccount(payable(account)).executeBatch(calls);
        assertEq(target.value(), 4);
    }

    function test_postImport_isValidSignature() public {
        address account = factory.deploy(bytes32(uint256(3)), _ownerAndGuardian());
        bytes32 hash = keccak256("hi");
        bytes memory auth = _wrapLocal(_buildK1Auth(OWNER_PK, keystore.replaySafeHash(account, block.chainid, hash)));
        assertEq(InitcodeAccount(payable(account)).isValidSignature(hash, auth), bytes4(0x1626ba7e));
    }

    function test_create_thenStrangerCompletesImport() public {
        Keystore.InitialActor[] memory actors = _ownerAndGuardian();
        bytes32 salt = bytes32(uint256(4));
        address account = factory.create(salt, actors);
        assertEq(keystore.getChangeSequences(account).localSequence, 0);

        vm.prank(address(0xBEEF));
        InitcodeAccount(payable(account)).completeImport(block.chainid, actors);
        assertEq(keystore.getChangeSequences(account).localSequence, 1);
        assertTrue(_isActor(account, ActorId.fromAddress(vm.addr(OWNER_PK))));
    }

    function test_completeImport_wrongActorsReverts() public {
        Keystore.InitialActor[] memory actors = _ownerAndGuardian();
        address account = factory.create(bytes32(uint256(5)), actors);

        Keystore.InitialActor[] memory other = new Keystore.InitialActor[](2);
        other[0] = _k1(900, 0);
        other[1] = _k1(901, 0);
        if (other[0].actorId > other[1].actorId) (other[0], other[1]) = (other[1], other[0]);

        vm.expectRevert(InitcodeAccount.ActorsHashMismatch.selector);
        InitcodeAccount(payable(account)).completeImport(block.chainid, other);
        assertEq(keystore.getChangeSequences(account).localSequence, 0);
    }

    function test_create_rejectsSingleAdmin() public {
        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = _k1(OWNER_PK, 0);
        vm.expectRevert(InitcodeFactory.NeedGuardian.selector);
        factory.create(bytes32(uint256(6)), actors);
    }

    function test_completeImport_secondCallReverts() public {
        Keystore.InitialActor[] memory actors = _ownerAndGuardian();
        address account = factory.deploy(bytes32(uint256(7)), actors);
        vm.expectRevert(InitcodeAccount.AlreadyImported.selector);
        InitcodeAccount(payable(account)).completeImport(block.chainid, actors);
    }

    function test_deploy_multichain() public {
        Keystore.InitialActor[] memory actors = _ownerAndGuardian();
        address account = factory.deploy(bytes32(uint256(8)), actors, 0);
        assertEq(keystore.getChangeSequences(account).localSequence, 1);
    }

    function test_getImportActors_emptyOutsideImport() public {
        address account = factory.create(bytes32(uint256(9)), _ownerAndGuardian());
        Keystore.InitialActor[] memory got = InitcodeAccount(payable(account)).getImportActors();
        assertEq(got.length, 0);
    }
}
