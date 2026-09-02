// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Keystore} from "eip-8130/Keystore.sol";
import {ActorId} from "eip-8130/libraries/ActorId.sol";
import {KeystoreTest} from "eip-8130-test/lib/KeystoreTest.sol";

import {HomeChainAuthenticator} from "../../../src/authenticators/homechain/HomeChainAuthenticator.sol";
import {MockHomeChainConfigProver} from "../../../src/authenticators/homechain/MockHomeChainConfigProver.sol";

/// @notice Cross-chain admin: honor a key that is proven admin of an account on a remote "home" chain. Each call
///         needs BOTH a fresh `hash` signature (verified locally) and a home-config proof (the injected mock).
contract HomeChainTest is KeystoreTest {
    HomeChainAuthenticator internal home;
    MockHomeChainConfigProver internal prover;

    uint256 internal constant HOME_CHAIN_ID = 1; // L1
    address internal constant HOME_ACCOUNT = address(0xA11CE);

    function setUp() public virtual override {
        super.setUp();
        prover = new MockHomeChainConfigProver();
        home = new HomeChainAuthenticator(address(prover));
    }

    // ── Guards ──

    function test_authenticate_revert_dataTooShort(bytes32 hash, uint256 lenSeed) public {
        uint256 len = bound(lenSeed, 0, 53);
        vm.expectRevert(HomeChainAuthenticator.InvalidDataLength.selector);
        home.authenticate(hash, new bytes(len));
    }

    function test_authenticate_revert_nestedTooShort(bytes32 hash) public {
        // nestedAuthLen < 20.
        bytes memory data = abi.encodePacked(HOME_CHAIN_ID, HOME_ACCOUNT, uint16(19), new bytes(19));
        vm.expectRevert(HomeChainAuthenticator.InvalidDataLength.selector);
        home.authenticate(hash, data);
    }

    function test_authenticate_revert_recursive(bytes32 hash) public {
        bytes memory nested = abi.encodePacked(address(home), bytes20(0));
        bytes memory data = home.encode(HOME_CHAIN_ID, HOME_ACCOUNT, nested, "");
        vm.expectRevert(HomeChainAuthenticator.RecursiveDelegation.selector);
        home.authenticate(hash, data);
    }

    // ── K1 home admin ──

    function test_authenticate_success_k1Admin(uint256 pkSeed, bytes32 hash) public {
        uint256 pk = _boundK1Pk(pkSeed);
        bytes32 signerActor = ActorId.fromAddress(vm.addr(pk));
        prover.setActorConfig(HOME_CHAIN_ID, HOME_ACCOUNT, signerActor, k1Authenticator, 0, 0);

        bytes memory data = _k1Data(HOME_CHAIN_ID, HOME_ACCOUNT, pk, hash);
        assertEq(home.authenticate(hash, data), home.homeActorId(HOME_CHAIN_ID, HOME_ACCOUNT));
    }

    function test_authenticate_unprovenReturnsZero(uint256 pkSeed, bytes32 hash) public view {
        uint256 pk = _boundK1Pk(pkSeed);
        // No config seeded for this signer.
        bytes memory data = _k1Data(HOME_CHAIN_ID, HOME_ACCOUNT, pk, hash);
        assertEq(home.authenticate(hash, data), bytes32(0));
    }

    function test_authenticate_nonAdminReturnsZero(uint256 pkSeed, uint16 scopeSeed, bytes32 hash) public {
        uint256 pk = _boundK1Pk(pkSeed);
        uint16 scope = uint16(bound(uint256(scopeSeed), 1, type(uint16).max));
        bytes32 signerActor = ActorId.fromAddress(vm.addr(pk));
        prover.setActorConfig(HOME_CHAIN_ID, HOME_ACCOUNT, signerActor, k1Authenticator, 0, scope);

        bytes memory data = _k1Data(HOME_CHAIN_ID, HOME_ACCOUNT, pk, hash);
        assertEq(home.authenticate(hash, data), bytes32(0));
    }

    function test_authenticate_expiredReturnsZero(uint256 pkSeed, bytes32 hash) public {
        vm.warp(1_000_000);
        uint256 pk = _boundK1Pk(pkSeed);
        bytes32 signerActor = ActorId.fromAddress(vm.addr(pk));
        prover.setActorConfig(HOME_CHAIN_ID, HOME_ACCOUNT, signerActor, k1Authenticator, uint48(block.timestamp - 1), 0);

        bytes memory data = _k1Data(HOME_CHAIN_ID, HOME_ACCOUNT, pk, hash);
        assertEq(home.authenticate(hash, data), bytes32(0));
    }

    function test_authenticate_wrongHashReturnsZero(uint256 pkSeed, bytes32 hash) public {
        uint256 pk = _boundK1Pk(pkSeed);
        bytes32 signerActor = ActorId.fromAddress(vm.addr(pk));
        prover.setActorConfig(HOME_CHAIN_ID, HOME_ACCOUNT, signerActor, k1Authenticator, 0, 0);

        // Signature is over `hash`, but we authenticate a different digest → recovers a different actor → unproven.
        bytes memory data = _k1Data(HOME_CHAIN_ID, HOME_ACCOUNT, pk, hash);
        assertEq(home.authenticate(keccak256(abi.encodePacked(hash)), data), bytes32(0));
    }

    function test_authenticate_authenticatorMismatchReturnsZero(uint256 pkSeed, bytes32 hash) public {
        uint256 pk = _boundK1Pk(pkSeed);
        bytes32 signerActor = ActorId.fromAddress(vm.addr(pk));
        // Home config binds this actor to a DIFFERENT authenticator than the k1 sentinel we recover with.
        prover.setActorConfig(HOME_CHAIN_ID, HOME_ACCOUNT, signerActor, address(0xBEEF), 0, 0);

        bytes memory data = _k1Data(HOME_CHAIN_ID, HOME_ACCOUNT, pk, hash);
        assertEq(home.authenticate(hash, data), bytes32(0));
    }

    // ── P256 home admin (contract-scheme path) ──

    function test_authenticate_success_p256Admin(uint256 pkSeed, bytes32 hash) public {
        uint256 pk = _boundP256Pk(pkSeed);
        bytes32 signerActor = _p256ActorId(pk);
        prover.setActorConfig(HOME_CHAIN_ID, HOME_ACCOUNT, signerActor, address(p256Authenticator), 0, 0);

        bytes memory nested = abi.encodePacked(address(p256Authenticator), _p256SignData(pk, hash));
        bytes memory data = home.encode(HOME_CHAIN_ID, HOME_ACCOUNT, nested, "");
        assertEq(home.authenticate(hash, data), home.homeActorId(HOME_CHAIN_ID, HOME_ACCOUNT));
    }

    // ── Identity ──

    function test_homeActorId_bindsChainAndAccount(uint256 chainId, address account) public view {
        assertEq(home.homeActorId(chainId, account), keccak256(abi.encodePacked(chainId, account)));
    }

    // ── End-to-end through the local Keystore ──

    /// @dev Register the home actorId as an admin on a fresh L2 account bound to this authenticator, then
    ///      authenticate via the Keystore exactly as the protocol would.
    function test_endToEnd_l2AdminFromHomeProof(uint256 pkSeed, bytes32 hash) public {
        uint256 pk = _boundK1Pk(pkSeed);
        bytes32 signerActor = ActorId.fromAddress(vm.addr(pk));
        prover.setActorConfig(HOME_CHAIN_ID, HOME_ACCOUNT, signerActor, k1Authenticator, 0, 0);

        bytes32 actorId = home.homeActorId(HOME_CHAIN_ID, HOME_ACCOUNT);
        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({actorId: actorId, authenticator: address(home), scope: 0, policyData: ""});
        address l2Account =
            keystore.createAccount(bytes32(uint256(7)), _computeERC1167Bytecode(defaultAccountImplementation), actors);

        bytes memory data = _k1Data(HOME_CHAIN_ID, HOME_ACCOUNT, pk, hash);
        (bytes32 got, uint16 scope) = keystore.authenticateActor(l2Account, hash, abi.encodePacked(address(home), data));
        assertEq(got, actorId);
        assertEq(scope, 0);
    }

    // ── Helpers ──

    function _k1Data(uint256 homeChainId, address homeAccount, uint256 pk, bytes32 hash)
        internal
        view
        returns (bytes memory)
    {
        bytes memory nested = abi.encodePacked(k1Authenticator, _signDigest(pk, hash));
        return home.encode(homeChainId, homeAccount, nested, "");
    }
}
