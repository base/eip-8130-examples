// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Keystore} from "eip-8130/Keystore.sol";
import {ActorId} from "eip-8130/libraries/ActorId.sol";
import {Scopes} from "eip-8130/libraries/Scopes.sol";
import {KeystoreTest} from "eip-8130-test/lib/KeystoreTest.sol";

import {OperatorSessionAuthenticator} from "../../../src/authenticators/sessions/OperatorSessionAuthenticator.sol";

/// @notice Operator-minted session keys. A live OPERATOR (non-admin) actor signs a grant for a fresh session key;
///         the session key's own signature authorizes the tx. Every minted key resolves to the operator's id, so
///         it inherits the operator's (non-admin) scope and dies the instant the operator is revoked or expires
///         (cascading), with no per-key registration and no admin involvement.
contract OperatorSessionTest is KeystoreTest {
    OperatorSessionAuthenticator internal op;

    uint256 internal adminPk;
    uint256 internal operatorPk;
    uint256 internal sessionPk;

    function setUp() public virtual override {
        super.setUp();
        op = new OperatorSessionAuthenticator();
        adminPk = _boundK1Pk(1);
        operatorPk = _boundK1Pk(2);
        sessionPk = _boundK1Pk(3);
    }

    // ── Guards ──

    function test_authenticate_revert_dataTooShort(bytes32 hash, uint256 lenSeed) public {
        vm.expectRevert(OperatorSessionAuthenticator.InvalidDataLength.selector);
        op.authenticate(hash, new bytes(bound(lenSeed, 0, 27)));
    }

    function test_authenticate_revert_recursive_operator(bytes32 hash) public {
        bytes memory data = abi.encodePacked(address(op), uint48(0), uint16(0), k1Authenticator, uint16(0));
        vm.expectRevert(OperatorSessionAuthenticator.RecursiveDelegation.selector);
        op.authenticate(hash, data);
    }

    function test_authenticate_revert_recursive_session(bytes32 hash) public {
        bytes memory data = abi.encodePacked(k1Authenticator, uint48(0), uint16(0), address(op), uint16(0));
        vm.expectRevert(OperatorSessionAuthenticator.RecursiveDelegation.selector);
        op.authenticate(hash, data);
    }

    // ── Operator mints a session (the happy path) ──

    function test_success_k1Operator_k1Session(bytes32 hash) public {
        (address account,) = _createK1Account(adminPk);
        bytes32 operatorId = ActorId.fromAddress(vm.addr(operatorPk));
        _register(account, operatorId, Scopes.OPERATOR, UNBOUNDED);

        bytes memory auth = _mint(operatorPk, sessionPk, 0, hash);
        (bytes32 got, uint16 scope) = keystore.authenticateActor(account, hash, auth);
        assertEq(got, operatorId);
        assertEq(scope, Scopes.OPERATOR); // minted key inherits the operator's scope — never admin
    }

    function test_success_p256Session(bytes32 hash) public {
        uint256 p256Pk = _boundP256Pk(42);
        (address account,) = _createK1Account(adminPk);
        bytes32 operatorId = ActorId.fromAddress(vm.addr(operatorPk));
        _register(account, operatorId, Scopes.OPERATOR, UNBOUNDED);

        bytes32 sessionId = _p256ActorId(p256Pk);
        bytes32 grant = op.grantHash(sessionId, address(p256Authenticator), 0);
        bytes memory auth = abi.encodePacked(
            address(op),
            op.encode(
                k1Authenticator,
                0,
                _signDigest(operatorPk, grant),
                address(p256Authenticator),
                _p256SignData(p256Pk, hash)
            )
        );
        (bytes32 got,) = keystore.authenticateActor(account, hash, auth);
        assertEq(got, operatorId);
    }

    // ── Install (grant) and authenticate (subSig) are split — neither alone acts (Appendix-A invariant) ──

    function test_subSigWithoutGrant_returnsZero(bytes32 hash) public view {
        // Valid session signature, but a garbage grant: an unsigned session cannot install itself.
        bytes memory subSig = _signDigest(sessionPk, hash);
        bytes memory data = op.encode(k1Authenticator, 0, new bytes(65), k1Authenticator, subSig);
        assertEq(op.authenticate(hash, data), bytes32(0));
    }

    function test_grantWithoutFreshSig_returnsZero(bytes32 hash) public view {
        // A leaked grant is not a leaked key: without the session key's own signature, nothing acts.
        bytes32 sessionId = ActorId.fromAddress(vm.addr(sessionPk));
        bytes memory grantSig = _signDigest(operatorPk, op.grantHash(sessionId, k1Authenticator, 0));
        bytes memory data = op.encode(k1Authenticator, 0, grantSig, k1Authenticator, new bytes(65));
        assertEq(op.authenticate(hash, data), bytes32(0));
    }

    function test_grantBoundToSession_wrongSessionReverts(bytes32 hash) public {
        // Operator grants for `sessionPk`, but a different key signs the tx: the grant recovers a stranger, not the
        // registered operator → the Keystore bind fails.
        (address account,) = _createK1Account(adminPk);
        bytes32 operatorId = ActorId.fromAddress(vm.addr(operatorPk));
        _register(account, operatorId, Scopes.OPERATOR, UNBOUNDED);

        uint256 wrongPk = _boundK1Pk(99);
        bytes32 grantedId = ActorId.fromAddress(vm.addr(sessionPk));
        bytes memory grantSig = _signDigest(operatorPk, op.grantHash(grantedId, k1Authenticator, 0));
        bytes memory auth = abi.encodePacked(
            address(op), op.encode(k1Authenticator, 0, grantSig, k1Authenticator, _signDigest(wrongPk, hash))
        );
        vm.expectRevert(Keystore.AuthenticatorMismatch.selector);
        keystore.authenticateActor(account, hash, auth);
    }

    // ── Expiry ──

    function test_sessionExpired_returnsZero(bytes32 hash) public {
        vm.warp(1_000_000);
        bytes memory data = _mintData(operatorPk, sessionPk, uint48(block.timestamp - 1), hash);
        assertEq(op.authenticate(hash, data), bytes32(0));
    }

    /// @dev Cascading expiry via revocation: revoking the operator instantly stops all of its sessions.
    function test_cascading_revokeOperator_stopsSessions(bytes32 hash) public {
        (address account,) = _createK1Account(adminPk);
        bytes32 operatorId = ActorId.fromAddress(vm.addr(operatorPk));
        _register(account, operatorId, Scopes.OPERATOR, UNBOUNDED);

        bytes memory auth = _mint(operatorPk, sessionPk, 0, hash);
        (bytes32 got,) = keystore.authenticateActor(account, hash, auth);
        assertEq(got, operatorId);

        _revokeActor(account, adminPk, operatorId);
        vm.expectRevert(Keystore.AuthenticatorMismatch.selector);
        keystore.authenticateActor(account, hash, auth);
    }

    /// @dev Cascading expiry via the operator's own window: past it, every minted session stops at once.
    function test_cascading_operatorExpiry_stopsSessions(bytes32 hash) public {
        vm.warp(1_000_000);
        (address account,) = _createK1Account(adminPk);
        bytes32 operatorId = ActorId.fromAddress(vm.addr(operatorPk));
        _register(account, operatorId, Scopes.OPERATOR, uint48(block.timestamp + 100));

        bytes memory auth = _mint(operatorPk, sessionPk, 0, hash);
        (bytes32 got,) = keystore.authenticateActor(account, hash, auth);
        assertEq(got, operatorId);

        vm.warp(block.timestamp + 101);
        vm.expectRevert(Keystore.ActorExpired.selector);
        keystore.authenticateActor(account, hash, auth);
    }

    // ── Helpers ──

    function _register(address account, bytes32 operatorId, uint16 scope, uint48 expiry) internal {
        _applyLocal(adminPk, account, _one(_authorizeChange(operatorId, address(op), scope, expiry, "")));
    }

    /// @dev A full keystore auth blob for a K1 operator minting a K1 session key.
    function _mint(uint256 opPk, uint256 sessPk, uint48 sessionExpiry, bytes32 hash)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodePacked(address(op), _mintData(opPk, sessPk, sessionExpiry, hash));
    }

    function _mintData(uint256 opPk, uint256 sessPk, uint48 sessionExpiry, bytes32 hash)
        internal
        view
        returns (bytes memory)
    {
        bytes32 sessionId = ActorId.fromAddress(vm.addr(sessPk));
        bytes memory grantSig = _signDigest(opPk, op.grantHash(sessionId, k1Authenticator, sessionExpiry));
        return op.encode(k1Authenticator, sessionExpiry, grantSig, k1Authenticator, _signDigest(sessPk, hash));
    }
}
