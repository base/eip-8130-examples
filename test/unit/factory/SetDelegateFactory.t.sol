// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Vm} from "forge-std/Vm.sol";

import {Call} from "eip-8130/accounts/DefaultAccount.sol";
import {Keystore} from "eip-8130/Keystore.sol";
import {ActorId} from "eip-8130/libraries/ActorId.sol";
import {KeystoreTest} from "eip-8130-test/lib/KeystoreTest.sol";

import {BootstrapAccount} from "../../../src/factory/BootstrapAccount.sol";
import {SetDelegateFactory} from "../../../src/factory/SetDelegateFactory.sol";

/// @dev Test-only factory: simulates EIP-7819 SETDELEGATE via `vm.etch`. Foundry executes
///      `0xef0100 || target` as an EIP-7702-style delegation when `evm_version` is osaka.
contract TestableSetDelegateFactory is SetDelegateFactory {
    Vm internal constant _vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function _setDelegate(bytes32 salt, address target) internal override returns (address account) {
        account = computeAddress(salt);
        bytes memory existing = account.code;
        require(
            existing.length == 0 || (existing.length >= 3 && bytes3(existing) == bytes3(0xef0100)),
            "SETDELEGATE: not a delegation"
        );
        _vm.etch(account, abi.encodePacked(hex"ef0100", target));
    }
}

contract FactoryMockTarget {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }
}

contract SetDelegateFactoryTest is KeystoreTest {
    TestableSetDelegateFactory internal factory;
    BootstrapAccount internal implementation;
    FactoryMockTarget internal target;

    function setUp() public override {
        super.setUp();
        factory = new TestableSetDelegateFactory();
        implementation = new BootstrapAccount(address(keystore));
        target = new FactoryMockTarget();
    }

    function _oneActor(uint256 pk) internal view returns (Keystore.InitialActor[] memory actors) {
        actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: ActorId.fromAddress(vm.addr(pk)), authenticator: address(k1Authenticator), scope: 0, policyData: ""
        });
    }

    function test_deploy_atomic() public {
        uint256 pk = 700;
        Keystore.InitialActor[] memory actors = _oneActor(pk);
        bytes32 userSalt = bytes32(uint256(42));

        address expected = factory.computeAccount(actors, userSalt);
        address actual = factory.deploy(actors, address(implementation), userSalt);

        assertEq(actual, expected);

        bytes memory code = actual.code;
        assertEq(code.length, 23);
        assertEq(bytes3(code), bytes3(0xef0100));
        address embedded;
        assembly {
            embedded := mload(add(code, 23))
        }
        assertEq(embedded, address(implementation));

        assertEq(keystore.getChangeSequences(actual).localSequence, 1);
        assertTrue(_isActor(actual, ActorId.fromAddress(vm.addr(pk))));

        // Latch cleared: import digest no longer auto-validates.
        bytes32 importDigest = keystore.computeImportDigest(actual, block.chainid, actors);
        assertEq(BootstrapAccount(payable(actual)).isValidSignature(importDigest, ""), bytes4(0xffffffff));
    }

    function test_deploy_executeBatch() public {
        uint256 pk = 700;
        address account = factory.deploy(_oneActor(pk), address(implementation), bytes32(uint256(8)));

        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(target), 0, abi.encodeCall(FactoryMockTarget.setValue, (9)));
        vm.prank(account);
        BootstrapAccount(payable(account)).executeBatch(calls);
        assertEq(target.value(), 9);
    }

    function test_deploy_isDeterministic() public {
        Keystore.InitialActor[] memory actors = _oneActor(700);
        bytes32 userSalt = bytes32(uint256(7));
        address a = factory.deploy(actors, address(implementation), userSalt);
        assertEq(factory.computeAccount(actors, userSalt), a);
    }

    function test_deploy_revertsOnSecondDeploy() public {
        Keystore.InitialActor[] memory actors = _oneActor(700);
        bytes32 userSalt = bytes32(uint256(1));
        factory.deploy(actors, address(implementation), userSalt);
        vm.expectRevert();
        factory.deploy(actors, address(implementation), userSalt);
    }

    function test_differentActors_yieldsDifferentAddress() public view {
        bytes32 userSalt = bytes32(uint256(99));
        assertTrue(factory.computeAccount(_oneActor(700), userSalt) != factory.computeAccount(_oneActor(701), userSalt));
    }

    function test_differentFactory_yieldsDifferentAddress() public {
        TestableSetDelegateFactory other = new TestableSetDelegateFactory();
        Keystore.InitialActor[] memory actors = _oneActor(700);
        bytes32 userSalt = bytes32(uint256(5));
        assertTrue(factory.computeAccount(actors, userSalt) != other.computeAccount(actors, userSalt));
    }

    function test_upgrade_onlyAccount() public {
        Keystore.InitialActor[] memory actors = _oneActor(700);
        bytes32 userSalt = bytes32(uint256(2));
        address account = factory.deploy(actors, address(implementation), userSalt);
        bytes32 ah = factory.actorsHash(actors);
        BootstrapAccount newImpl = new BootstrapAccount(address(keystore));

        vm.expectRevert();
        factory.upgrade(userSalt, ah, address(newImpl));

        vm.prank(account);
        factory.upgrade(userSalt, ah, address(newImpl));

        bytes memory code = account.code;
        address embedded;
        assembly {
            embedded := mload(add(code, 23))
        }
        assertEq(embedded, address(newImpl));
    }

    function test_postBootstrap_isValidSignature_routesThroughKeystore() public {
        uint256 pk = 700;
        address account = factory.deploy(_oneActor(pk), address(implementation), bytes32(uint256(3)));

        bytes32 hash = keccak256("hello");
        bytes memory auth = _wrapLocal(_buildK1Auth(pk, keystore.replaySafeHash(account, block.chainid, hash)));
        assertEq(BootstrapAccount(payable(account)).isValidSignature(hash, auth), bytes4(0x1626ba7e));
    }

    function test_deploy_multichainImport() public {
        uint256 pk = 700;
        Keystore.InitialActor[] memory actors = _oneActor(pk);
        address account = factory.deploy(actors, address(implementation), bytes32(uint256(11)), 0);
        assertEq(keystore.getChangeSequences(account).localSequence, 1);
        assertTrue(_isActor(account, ActorId.fromAddress(vm.addr(pk))));
    }

    function test_bootstrap_rejectsMismatchedActorsHash() public {
        Keystore.InitialActor[] memory actors = _oneActor(700);
        address account = factory.computeAccount(actors, bytes32(uint256(4)));
        // Place the indicator without going through deploy, then call bootstrap with a bad hash.
        vm.etch(account, abi.encodePacked(hex"ef0100", address(implementation)));
        vm.expectRevert(BootstrapAccount.ActorsHashMismatch.selector);
        BootstrapAccount(payable(account)).bootstrap(bytes32(uint256(1)), block.chainid, actors);
    }
}
