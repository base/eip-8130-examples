// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {DefaultAccount, Call, TRUSTED_EXECUTOR} from "eip-8130/accounts/DefaultAccount.sol";
import {BackwardsCompatible4337Account, PackedUserOperation} from
    "../../../src/accounts/erc4337/BackwardsCompatible4337Account.sol";
import {Keystore} from "eip-8130/Keystore.sol";
import {Scopes} from "eip-8130/libraries/Scopes.sol";
import {KeystoreTest} from "eip-8130-test/lib/KeystoreTest.sol";

contract UserOpMockTarget {
    uint256 public value;

    function setValue(uint256 v) external payable {
        value = v;
    }

    function reverting() external pure {
        revert("boom");
    }
}

/// @notice ERC-4337 conformance suite for {BackwardsCompatible4337Account}. The EntryPoint is authorized as a
///         config-driven TRUSTED_EXECUTOR actor (seeded into the initial actor set at creation), so it is revocable
///         and version-agnostic — the single opinionated 4337 model for the repo.
contract BackwardsCompatible4337AccountTest is KeystoreTest {
    uint256 constant ACTOR_PK = 100;

    bytes32 constant SIGNED_ACCOUNT_CHANGES_MAGIC = keccak256("ERC4337Account.signedAccountChanges.v1");

    UserOpMockTarget public target;
    address public impl;

    function setUp() public virtual override {
        super.setUp();
        target = new UserOpMockTarget();
        impl = address(new BackwardsCompatible4337Account(address(keystore)));
    }

    /// @dev Create an account from `impl` with `pk` as the unrestricted owner, seeding the EntryPoint as a
    ///      TRUSTED_EXECUTOR actor so it is an authorized caller from the account's first op (the config-driven
    ///      model has no hardcoded EntryPoint). Returns (account, ownerActorId).
    function _create4337Account(uint256 pk) internal returns (address account, bytes32 actorId) {
        actorId = _actorId(vm.addr(pk));
        Keystore.InitialActor memory owner = Keystore.InitialActor({
            actorId: actorId, authenticator: address(k1Authenticator), scope: 0, policyData: ""
        });
        Keystore.InitialActor memory ep = Keystore.InitialActor({
            actorId: _actorId(ENTRY_POINT), authenticator: TRUSTED_EXECUTOR, scope: 0, policyData: ""
        });

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](2);
        (actors[0], actors[1]) = owner.actorId < ep.actorId ? (owner, ep) : (ep, owner);
        account = keystore.createAccount(bytes32(0), _computeERC1167Bytecode(impl), actors);
    }

    // ── Shared helpers ──

    /// @dev Address-derived actorId (right-aligned into a 32-byte word, per {ActorId.fromAddress}).
    function _actorId(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _singleCall(address t, uint256 v, bytes memory d) internal pure returns (Call[] memory calls) {
        calls = new Call[](1);
        calls[0] = Call(t, v, d);
    }

    function _buildUserOp(address account, bytes memory signature) internal pure returns (PackedUserOperation memory) {
        return _buildUserOp(account, "", signature);
    }

    function _buildUserOp(address account, bytes memory callData, bytes memory signature)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: signature
        });
    }

    function _executeBatchCallData(address t, uint256 v, bytes memory d) internal pure returns (bytes memory) {
        return abi.encodeCall(DefaultAccount.executeBatch, (_singleCall(t, v, d)));
    }

    /// @dev Chain-local ERC-1271 envelope over the account-scoped replaySafeHash digest.
    function _erc1271Auth(address account, uint256 pk, bytes32 hash) internal view returns (bytes memory) {
        return _wrapLocal(_buildK1Auth(pk, keystore.replaySafeHash(account, block.chainid, hash)));
    }

    /// @dev Authorizes a new K1 actor on `account` with the given scope/policy, signed by the unrestricted owner
    ///      (`ownerPk`) via `applySignedAccountChanges`. Returns the new actor's id. Policy data is attached whenever
    ///      `scope` carries Scopes.POLICY. Granted UNBOUNDED (never-expiring) on a sequenced batch.
    function _authorizeScopedActor(
        address account,
        uint256 ownerPk,
        uint256 newPk,
        uint16 scope,
        address policyManager,
        bytes32 commitment
    ) internal returns (bytes32 newActorId) {
        newActorId = _actorId(vm.addr(newPk));
        bytes memory policyData =
            scope & Scopes.POLICY == 0 ? bytes("") : abi.encodePacked(policyManager, commitment);
        _applyLocal(
            ownerPk, account, _one(_authorizeChange(newActorId, address(k1Authenticator), scope, UNBOUNDED, policyData))
        );
    }

    /// @dev A one-element authorize-actor change batch adding `newPk` as an unrestricted (admin) K1 actor.
    function _authorizeK1ChangeArray(uint256 newPk)
        internal
        view
        returns (Keystore.AccountChange[] memory changes, bytes32 newActorId)
    {
        newActorId = _actorId(vm.addr(newPk));
        changes = _one(_authorizeChange(newActorId, address(k1Authenticator), 0, UNBOUNDED, ""));
    }

    // ── Always-authorized callers ──

    function test_entryPointIsAuthorized() public {
        (address account,) = _create4337Account(ACTOR_PK);
        assertTrue(DefaultAccount(payable(account)).isAuthorizedCaller(ENTRY_POINT));
    }

    function test_selfIsAlwaysAuthorized() public {
        (address account,) = _create4337Account(ACTOR_PK);
        assertTrue(DefaultAccount(payable(account)).isAuthorizedCaller(account));
    }

    function test_unknownCallerNotAuthorized() public {
        (address account,) = _create4337Account(ACTOR_PK);
        assertFalse(DefaultAccount(payable(account)).isAuthorizedCaller(address(0xdead)));
    }

    // ── Trusted-executor actor (relayer / PolicyManager registered via the Keystore) ──

    function test_trustedExecutorActorIsAuthorized() public {
        (address account,) = _create4337Account(ACTOR_PK);
        address relayer = address(0xBEEF);

        _applyLocal(
            ACTOR_PK, account, _one(_authorizeChange(_actorId(relayer), TRUSTED_EXECUTOR, Scopes.SENDER, UNBOUNDED, ""))
        );

        assertTrue(DefaultAccount(payable(account)).isAuthorizedCaller(relayer));

        vm.prank(relayer);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(UserOpMockTarget.setValue, (7))));
        assertEq(target.value(), 7);
    }

    // ── executeBatch from EntryPoint ──

    function test_executeBatch_fromEntryPoint() public {
        (address account,) = _create4337Account(ACTOR_PK);

        vm.prank(ENTRY_POINT);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(UserOpMockTarget.setValue, (77))));

        assertEq(target.value(), 77);
    }

    // ── validateUserOp ──

    function test_validateUserOp_validSignature() public {
        (address account,) = _create4337Account(ACTOR_PK);

        bytes32 userOpHash = keccak256("user-op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(ACTOR_PK, userOpHash));

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 0);
    }

    function test_validateUserOp_invalidSignature() public {
        (address account,) = _create4337Account(ACTOR_PK);

        bytes32 userOpHash = keccak256("user-op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(999, userOpHash));

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 1);
    }

    function test_validateUserOp_revertsFromUnauthorizedCaller() public {
        (address account,) = _create4337Account(ACTOR_PK);

        bytes32 userOpHash = keccak256("user-op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(ACTOR_PK, userOpHash));

        vm.prank(address(0xdead));
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0);
    }

    function test_validateUserOp_paysPrefund() public {
        (address account,) = _create4337Account(ACTOR_PK);
        vm.deal(account, 1 ether);

        bytes32 userOpHash = keccak256("user-op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(ACTOR_PK, userOpHash));

        uint256 prefund = 0.1 ether;
        uint256 epBalanceBefore = ENTRY_POINT.balance;

        vm.prank(ENTRY_POINT);
        BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, prefund);

        assertEq(ENTRY_POINT.balance - epBalanceBefore, prefund);
    }

    // ── validateUserOp: validation-phase account changes ──

    /// @notice A single UserOperation can rotate/add a key during validation; the op is then authenticated as
    ///         usual by `opAuth` — produced here by the brand-new key.
    function test_validateUserOp_appliesSignedAccountChanges() public {
        (address account,) = _create4337Account(ACTOR_PK);

        uint256 newPk = 101;
        (Keystore.AccountChange[] memory changes, bytes32 newActorId) = _authorizeK1ChangeArray(newPk);

        Keystore.SignedAccountChanges[] memory changeSets = new Keystore.SignedAccountChanges[](1);
        changeSets[0] = _localBatch(ACTOR_PK, account, changes);

        bytes32 userOpHash = keccak256("rotate-and-go");
        bytes memory opAuth = _buildK1Auth(newPk, userOpHash);
        bytes memory signature = abi.encode(SIGNED_ACCOUNT_CHANGES_MAGIC, changeSets, opAuth);
        PackedUserOperation memory userOp = _buildUserOp(account, signature);

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 0);
        assertTrue(_isActor(account, newActorId));
    }

    /// @notice Multiple independently-signed change sets are applied in order: the owner authorizes key B, then
    ///         key B (now active) authorizes key C, all in one op. The op is then authenticated by C's `opAuth`.
    function test_validateUserOp_appliesMultipleSignedAccountChangeSets() public {
        (address account,) = _create4337Account(ACTOR_PK);

        uint256 pkB = 101;
        uint256 pkC = 102;
        (Keystore.AccountChange[] memory changesB, bytes32 actorB) = _authorizeK1ChangeArray(pkB);
        (Keystore.AccountChange[] memory changesC, bytes32 actorC) = _authorizeK1ChangeArray(pkC);

        uint64 word = _localSeqWord(account);
        Keystore.SignedAccountChanges[] memory changeSets = new Keystore.SignedAccountChanges[](2);
        // Set 0 signed by owner at the current sequence word; set 1 signed by B at the next sequence.
        changeSets[0] = _signBatch(ACTOR_PK, account, Keystore.AccountChangeChannel.Local, word, changesB);
        changeSets[1] = _signBatch(pkB, account, Keystore.AccountChangeChannel.Local, word + 1, changesC);

        bytes32 userOpHash = keccak256("chain-of-rotations");
        bytes memory opAuth = _buildK1Auth(pkC, userOpHash); // op signed by C (active after set 1)
        bytes memory signature = abi.encode(SIGNED_ACCOUNT_CHANGES_MAGIC, changeSets, opAuth);
        PackedUserOperation memory userOp = _buildUserOp(account, signature);

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 0);
        assertTrue(_isActor(account, actorB));
        assertTrue(_isActor(account, actorC));
    }

    /// @notice Applying changes does NOT authorize the op: a valid change set with an `opAuth` that does not sign
    ///         this userOpHash fails validation.
    function test_validateUserOp_signedAccountChanges_requiresOpAuth() public {
        (address account,) = _create4337Account(ACTOR_PK);

        uint256 newPk = 101;
        (Keystore.AccountChange[] memory changes,) = _authorizeK1ChangeArray(newPk);

        Keystore.SignedAccountChanges[] memory changeSets = new Keystore.SignedAccountChanges[](1);
        changeSets[0] = _localBatch(ACTOR_PK, account, changes);

        bytes32 userOpHash = keccak256("rotate-but-no-op-auth");
        bytes memory opAuth = _buildK1Auth(999, userOpHash); // unauthorized key
        bytes memory signature = abi.encode(SIGNED_ACCOUNT_CHANGES_MAGIC, changeSets, opAuth);
        PackedUserOperation memory userOp = _buildUserOp(account, signature);

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 1);
    }

    /// @notice An invalid change authorization fails validation and applies nothing.
    function test_validateUserOp_signedAccountChanges_invalidChangeAuthFails() public {
        (address account,) = _create4337Account(ACTOR_PK);

        uint256 newPk = 101;
        (Keystore.AccountChange[] memory changes, bytes32 newActorId) = _authorizeK1ChangeArray(newPk);

        Keystore.SignedAccountChanges[] memory changeSets = new Keystore.SignedAccountChanges[](1);
        changeSets[0] = _localBatch(999, account, changes); // signed by a non-owner key

        bytes32 userOpHash = keccak256("op");
        bytes memory opAuth = _buildK1Auth(ACTOR_PK, userOpHash);
        bytes memory signature = abi.encode(SIGNED_ACCOUNT_CHANGES_MAGIC, changeSets, opAuth);
        PackedUserOperation memory userOp = _buildUserOp(account, signature);

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 1);
        assertFalse(_isActor(account, newActorId));
    }

    /// @notice An empty change-set batch is rejected (it must not authorize any op).
    function test_validateUserOp_signedAccountChanges_emptyBatchFails() public {
        (address account,) = _create4337Account(ACTOR_PK);

        Keystore.SignedAccountChanges[] memory changeSets = new Keystore.SignedAccountChanges[](0);
        bytes32 userOpHash = keccak256("op");
        bytes memory opAuth = _buildK1Auth(ACTOR_PK, userOpHash);
        bytes memory signature = abi.encode(SIGNED_ACCOUNT_CHANGES_MAGIC, changeSets, opAuth);
        PackedUserOperation memory userOp = _buildUserOp(account, signature);

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 1);
    }

    // ── ERC-1271 signing (operational authority) ──

    function test_isValidSignature_nonOperationalActorCannotSign() public {
        (address account,) = _create4337Account(ACTOR_PK);
        uint256 scopedPk = 201;
        // A payer-only (non-SENDER) actor is not operational.
        _authorizeScopedActor(account, ACTOR_PK, scopedPk, Scopes.SPONSOR_PAYER, address(0), bytes32(0));

        bytes32 hash = keccak256("sign me");
        bytes memory authData = _erc1271Auth(account, scopedPk, hash);

        // A non-operational scoped actor cannot ERC-1271 sign, so validation must fail.
        assertEq(DefaultAccount(payable(account)).isValidSignature(hash, authData), bytes4(0xFFFFFFFF));
    }

    function test_isValidSignature_operationalSenderSigns() public {
        (address account,) = _create4337Account(ACTOR_PK);
        uint256 senderPk = 202;
        // A SENDER-without-POLICY actor is operational and can ERC-1271 sign.
        _authorizeScopedActor(account, ACTOR_PK, senderPk, Scopes.SENDER, address(0), bytes32(0));

        bytes32 hash = keccak256("sign me");
        bytes memory authData = _erc1271Auth(account, senderPk, hash);

        assertEq(DefaultAccount(payable(account)).isValidSignature(hash, authData), bytes4(0x1626ba7e));
    }

    function test_isValidSignature_adminSucceeds() public {
        (address account,) = _create4337Account(ACTOR_PK);

        // The unrestricted admin actor (scope == 0x00) is operational and can ERC-1271 sign.
        bytes32 hash = keccak256("sign me");
        bytes memory authData = _erc1271Auth(account, ACTOR_PK, hash);

        assertEq(DefaultAccount(payable(account)).isValidSignature(hash, authData), bytes4(0x1626ba7e));
    }

    // ── SENDER scope (validateUserOp) ──

    function test_validateUserOp_senderScopeAuthorizes() public {
        (address account,) = _create4337Account(ACTOR_PK);
        uint256 senderPk = 203;
        _authorizeScopedActor(account, ACTOR_PK, senderPk, Scopes.SENDER, address(0), bytes32(0));

        bytes32 userOpHash = keccak256("op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(senderPk, userOpHash));

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 0);
    }

    function test_validateUserOp_requiresSenderScope() public {
        (address account,) = _create4337Account(ACTOR_PK);
        uint256 nonSenderPk = 204;
        _authorizeScopedActor(account, ACTOR_PK, nonSenderPk, Scopes.SPONSOR_PAYER, address(0), bytes32(0));

        bytes32 userOpHash = keccak256("op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(nonSenderPk, userOpHash));

        // An actor without SENDER scope cannot initiate transactions.
        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 1);
    }

    // ── SELF_PAYER scope (self-funded ops) ──

    function test_validateUserOp_selfFundedRequiresSelfPayerScope() public {
        (address account,) = _create4337Account(ACTOR_PK);
        vm.deal(account, 1 ether);
        uint256 senderOnlyPk = 205;
        _authorizeScopedActor(account, ACTOR_PK, senderOnlyPk, Scopes.SENDER, address(0), bytes32(0));

        bytes32 userOpHash = keccak256("op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(senderOnlyPk, userOpHash));

        // SENDER but not SELF_PAYER: cannot authorize spending the account's funds on gas.
        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0.1 ether), 1);
    }

    function test_validateUserOp_senderSelfPayerScope_selfFundedSucceeds() public {
        (address account,) = _create4337Account(ACTOR_PK);
        vm.deal(account, 1 ether);
        uint256 pk = 206;
        _authorizeScopedActor(account, ACTOR_PK, pk, Scopes.SENDER | Scopes.SELF_PAYER, address(0), bytes32(0));

        bytes32 userOpHash = keccak256("op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(pk, userOpHash));

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0.1 ether), 0);
    }

    // ── Scopes.POLICY (no native-dispatch call-target gating in this reduced 4337 bridge) ──

    function test_validateUserOp_policyScopeOnly_rejectedForLackingSenderScope() public {
        (address account,) = _create4337Account(ACTOR_PK);
        address policyManager = address(0xB0B);
        uint256 pk = 207;
        _authorizeScopedActor(account, ACTOR_PK, pk, Scopes.POLICY, policyManager, keccak256("commit"));

        // A pure-Scopes.POLICY actor lacks Scopes.SENDER, so this reduced 4337 bridge rejects it outright — it does
        // not replicate native-dispatch's policy-target call gating.
        bytes memory callData = _executeBatchCallData(policyManager, 0, abi.encodeCall(UserOpMockTarget.setValue, (1)));
        bytes32 userOpHash = keccak256(abi.encode("op", callData));
        PackedUserOperation memory userOp = _buildUserOp(account, callData, _buildK1Auth(pk, userOpHash));

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 1);
    }

    function test_validateUserOp_policyAndSenderScope_authorizedWithoutTargetGating() public {
        (address account,) = _create4337Account(ACTOR_PK);
        address policyManager = address(0xB0B);
        uint256 pk = 208;
        uint16 scope = Scopes.SENDER | Scopes.POLICY;
        _authorizeScopedActor(account, ACTOR_PK, pk, scope, policyManager, keccak256("commit"));

        // An actor combining Scopes.POLICY | Scopes.SENDER is authorized here exactly like any other SENDER-scoped
        // actor: this reduced 4337 bridge does not confine its calls to the policy target (that enforcement is
        // native-dispatch, protocol-side behavior out of scope for this repo).
        bytes memory callData =
            _executeBatchCallData(address(target), 0, abi.encodeCall(UserOpMockTarget.setValue, (1)));
        bytes32 userOpHash = keccak256(abi.encode("op", callData));
        PackedUserOperation memory userOp = _buildUserOp(account, callData, _buildK1Auth(pk, userOpHash));

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 0);
    }
}
