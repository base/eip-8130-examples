// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Call, DefaultAccount} from "eip-8130/accounts/DefaultAccount.sol";
import {AccountConfiguration} from "eip-8130/AccountConfiguration.sol";
import {AccountConfigurationTest} from "eip-8130-test/lib/AccountConfigurationTest.sol";
import {MODULE_TYPE_VALIDATOR} from "openzeppelin/interfaces/draft-IERC7579.sol";

import {AccountConfigurationValidator} from "../../../src/accounts/erc7579/AccountConfigurationValidator.sol";
import {ERC7579Account} from "../../../src/accounts/erc7579/ERC7579Account.sol";

/// @dev Matches Solady / ERC-7821 Call layout used inside `abi.encode(calls)`.
struct BatchCall {
    address to;
    uint256 value;
    bytes data;
}

contract ERC7579MockTarget {
    uint256 public value;

    function setValue(uint256 v) external payable {
        value = v;
    }
}

contract ERC7579AccountTest is AccountConfigurationTest {
    uint256 constant ACTOR_PK = 100;

    /// @dev ERC-7821 mode: batch, revert-on-fail, no opData support bit.
    bytes32 constant MODE_BATCH = bytes32(uint256(0x01) << 248);
    /// @dev ERC-7821 mode: batch with optional opData (`0x78210001` payload).
    bytes32 constant MODE_BATCH_OPDATA = bytes32((uint256(0x01) << 248) | (uint256(0x78210001) << 176));

    ERC7579MockTarget public target;
    address public impl;
    AccountConfigurationValidator public configValidator;

    function setUp() public virtual override {
        super.setUp();
        target = new ERC7579MockTarget();
        configValidator = new AccountConfigurationValidator(address(accountConfiguration));
        impl = address(new ERC7579Account(address(accountConfiguration)));
    }

    function _create7579Account(uint256 pk) internal returns (address account, bytes32 actorId) {
        actorId = bytes32(bytes20(vm.addr(pk)));
        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](1);
        actors[0] = AccountConfiguration.InitialActor({
            actorId: actorId, authenticator: address(k1Authenticator), scope: 0, policyData: ""
        });
        bytes memory proxyBytecode = _computeERC1167Bytecode(impl);
        account = accountConfiguration.createAccount(bytes32(0), proxyBytecode, actors);
    }

    function _installConfigValidator(address account) internal {
        vm.prank(account);
        ERC7579Account(payable(account)).installModule(MODULE_TYPE_VALIDATOR, address(configValidator), "");
    }

    function _encodeBatch(BatchCall[] memory calls) internal pure returns (bytes memory) {
        return abi.encode(calls);
    }

    function _encodeBatchWithOpData(BatchCall[] memory calls, bytes memory opData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(calls, opData);
    }

    // ── Module install ──

    function test_installAccountConfigurationValidator() public {
        (address account,) = _create7579Account(ACTOR_PK);
        _installConfigValidator(account);

        assertTrue(
            ERC7579Account(payable(account)).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(configValidator), "")
        );
    }

    function test_installModule_revertsFromUnauthorizedCaller() public {
        (address account,) = _create7579Account(ACTOR_PK);
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        ERC7579Account(payable(account)).installModule(MODULE_TYPE_VALIDATOR, address(configValidator), "");
    }

    // ── executeBatch (typed) vs execute (ERC-7821) ──

    function test_executeBatch_and_execute_areEquivalent() public {
        (address account,) = _create7579Account(ACTOR_PK);

        Call[] memory typed = new Call[](1);
        typed[0] = Call({target: address(target), value: 0, data: abi.encodeCall(ERC7579MockTarget.setValue, (7))});
        vm.prank(account);
        ERC7579Account(payable(account)).executeBatch(typed);
        assertEq(target.value(), 7);

        BatchCall[] memory batch = new BatchCall[](1);
        batch[0] = BatchCall({to: address(target), value: 0, data: abi.encodeCall(ERC7579MockTarget.setValue, (11))});
        vm.prank(account);
        ERC7579Account(payable(account)).execute(MODE_BATCH, _encodeBatch(batch));
        assertEq(target.value(), 11);
    }

    function test_execute_withOpData_relaysViaAccountConfiguration() public {
        (address account,) = _create7579Account(ACTOR_PK);

        BatchCall[] memory batch = new BatchCall[](1);
        batch[0] = BatchCall({to: address(target), value: 0, data: abi.encodeCall(ERC7579MockTarget.setValue, (42))});

        bytes32 batchHash = keccak256(
            abi.encodePacked(
                keccak256("batch"),
                address(target),
                uint256(0),
                keccak256(abi.encodeCall(ERC7579MockTarget.setValue, (42)))
            )
        );
        bytes32 digest =
            keccak256(abi.encode(ERC7579Account(payable(account)).EXECUTE_TYPEHASH(), MODE_BATCH_OPDATA, batchHash));
        bytes memory opData = _buildK1Auth(ACTOR_PK, digest);

        // Anyone may submit; auth is in opData.
        ERC7579Account(payable(account)).execute(MODE_BATCH_OPDATA, _encodeBatchWithOpData(batch, opData));
        assertEq(target.value(), 42);
    }

    // ── ERC-1271 via AccountConfigurationValidator ──

    function test_isValidSignature_viaConfigValidator() public {
        (address account,) = _create7579Account(ACTOR_PK);
        _installConfigValidator(account);

        bytes32 hash = keccak256("gm");
        bytes memory inner = _buildK1Auth(ACTOR_PK, hash);
        bytes memory signature = abi.encodePacked(address(configValidator), inner);

        bytes4 result = ERC7579Account(payable(account)).isValidSignature(hash, signature);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_rejectsBadSig() public {
        (address account,) = _create7579Account(ACTOR_PK);
        _installConfigValidator(account);

        bytes32 hash = keccak256("gm");
        bytes memory inner = _buildK1Auth(999, hash);
        bytes memory signature = abi.encodePacked(address(configValidator), inner);

        bytes4 result = ERC7579Account(payable(account)).isValidSignature(hash, signature);
        assertEq(result, bytes4(0xffffffff));
    }

    function test_accountId_and_supports() public {
        (address account,) = _create7579Account(ACTOR_PK);
        assertEq(ERC7579Account(payable(account)).accountId(), "coinbase.eip8130-erc7579.v0.1.0");
        assertTrue(ERC7579Account(payable(account)).supportsExecutionMode(MODE_BATCH));
        assertTrue(ERC7579Account(payable(account)).supportsExecutionMode(MODE_BATCH_OPDATA));
        assertTrue(ERC7579Account(payable(account)).supportsModule(MODULE_TYPE_VALIDATOR));
        assertFalse(ERC7579Account(payable(account)).supportsModule(2));
    }
}
