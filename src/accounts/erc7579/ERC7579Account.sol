// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";

import {DefaultAccount} from "eip-8130/accounts/DefaultAccount.sol";
import {
    IERC7579AccountConfig,
    IERC7579Execution,
    IERC7579Module,
    IERC7579ModuleConfig,
    IERC7579Validator,
    MODULE_TYPE_VALIDATOR
} from "openzeppelin/interfaces/draft-IERC7579.sol";

/// @notice Minimal ERC-7579 + ERC-7821 account example for EIP-8130.
///
///         Auth: install {AccountConfigurationValidator} as a MODULE_TYPE_VALIDATOR. ERC-1271 and (optionally)
///         UserOp validation go through that module into AccountConfiguration — not a key held in the account.
///
///         Execution (two equivalent batch surfaces):
///           - {executeBatch} — typed `Call[]` (EIP-8130 / DefaultAccount). Preferred when the caller can ABI-encode
///             structs directly.
///           - {execute} — ERC-7821 `execute(mode, executionData)`. Same batch semantics; `executionData` is
///             `abi.encode(calls)` (and optionally `opData` for signed relay). This is what wallets / 7579 tooling
///             speak. Not a different capability — a different encoding of the same batch.
///
///         Module surface is intentionally narrow: validators only. Executors / hooks / fallbacks can be layered
///         later without changing the auth model.
///
/// @author Coinbase
contract ERC7579Account is DefaultAccount, IERC7579Execution, IERC7579AccountConfig, IERC7579ModuleConfig {
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    /// @dev Typehash domain for ERC-7821 `execute` when authorizing via `opData` (excludes the signature itself).
    bytes32 public constant EXECUTE_TYPEHASH = keccak256("Execute(bytes32 mode,bytes32 batchHash)");

    /// @dev Installed ERC-7579 validator modules.
    EnumerableSetLib.AddressSet private _validators;

    /// @dev ERC-7821 / ERC-7579 execution mode is not supported.
    error UnsupportedExecutionMode();
    /// @dev Caller is not an authorized account driver (self / TRUSTED_EXECUTOR) and `opData` was empty or invalid.
    error UnauthorizedExecution();
    /// @dev Module type is not supported by this account.
    error UnsupportedModuleType(uint256 moduleTypeId);
    /// @dev Module is already installed.
    error ModuleAlreadyInstalled(address module);
    /// @dev Module is not installed.
    error ModuleNotInstalled(address module);
    /// @dev Module does not report the claimed type.
    error MismatchedModuleType(uint256 moduleTypeId, address module);

    constructor(address accountConfiguration) DefaultAccount(accountConfiguration) {}

    // ══════════════════════════════════════════════
    //  ERC-7579 ACCOUNT CONFIG
    // ══════════════════════════════════════════════

    /// @inheritdoc IERC7579AccountConfig
    function accountId() external pure returns (string memory) {
        return "coinbase.eip8130-erc7579.v0.1.0";
    }

    /// @inheritdoc IERC7579AccountConfig
    /// @dev Supports ERC-7821 batch modes (with and without `opData`) and plain ERC-7579 batch (no mode payload).
    function supportsExecutionMode(bytes32 mode) external pure returns (bool) {
        return _executionModeId(mode) != 0;
    }

    /// @inheritdoc IERC7579AccountConfig
    function supportsModule(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    // ══════════════════════════════════════════════
    //  ERC-7579 MODULE CONFIG
    // ══════════════════════════════════════════════

    /// @inheritdoc IERC7579ModuleConfig
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();
        if (moduleTypeId != MODULE_TYPE_VALIDATOR) revert UnsupportedModuleType(moduleTypeId);
        if (!IERC7579Module(module).isModuleType(moduleTypeId)) {
            revert MismatchedModuleType(moduleTypeId, module);
        }
        if (!_validators.add(module)) revert ModuleAlreadyInstalled(module);

        IERC7579Module(module).onInstall(initData);
        emit ModuleInstalled(moduleTypeId, module);
    }

    /// @inheritdoc IERC7579ModuleConfig
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData) external {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();
        if (moduleTypeId != MODULE_TYPE_VALIDATOR) revert UnsupportedModuleType(moduleTypeId);
        if (!_validators.remove(module)) revert ModuleNotInstalled(module);

        IERC7579Module(module).onUninstall(deInitData);
        emit ModuleUninstalled(moduleTypeId, module);
    }

    /// @inheritdoc IERC7579ModuleConfig
    function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata) external view returns (bool) {
        if (moduleTypeId != MODULE_TYPE_VALIDATOR) return false;
        return _validators.contains(module);
    }

    // ══════════════════════════════════════════════
    //  ERC-7821 / ERC-7579 EXECUTION
    // ══════════════════════════════════════════════

    /// @inheritdoc IERC7579Execution
    /// @dev ERC-7821 batch encoding. Empty `opData` → same caller gate as {executeBatch}. Non-empty `opData` →
    ///      treated as an EIP-8130 auth blob (`authenticator || data`) over `keccak256(mode || executionData)`.
    function execute(bytes32 mode, bytes calldata executionData) external payable {
        uint256 id = _executionModeId(mode);
        if (id == 0) revert UnsupportedExecutionMode();

        (bytes32[] calldata pointers, bytes calldata opData) = LibERC7579.decodeBatchAndOpData(executionData);
        _authorizeExecute(mode, pointers, opData);
        _executePointers(pointers);
    }

    /// @inheritdoc IERC7579Execution
    /// @dev Executor modules are not supported yet; always reverts. Kept for IERC7579Execution compliance.
    function executeFromExecutor(bytes32, bytes calldata) external payable returns (bytes[] memory) {
        revert UnsupportedModuleType(2);
    }

    // ══════════════════════════════════════════════
    //  ERC-1271 (via validator modules)
    // ══════════════════════════════════════════════

    /// @notice Validates an ERC-1271 signature by forwarding to installed validator modules.
    /// @dev Signature layout (common 7579 practice): `validator(20) || innerSignature`. If fewer than 20 bytes,
    ///      or the prefixed address is not installed, tries each installed validator with the full blob.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4) {
        if (signature.length >= 20) {
            address validator = address(bytes20(signature[:20]));
            if (_validators.contains(validator)) {
                return IERC7579Validator(validator).isValidSignatureWithSender(msg.sender, hash, signature[20:]);
            }
        }

        address[] memory validators = _validators.values();
        for (uint256 i; i < validators.length; i++) {
            bytes4 magic = IERC7579Validator(validators[i]).isValidSignatureWithSender(msg.sender, hash, signature);
            if (magic == bytes4(0x1626ba7e)) return magic;
        }
        return bytes4(0xffffffff);
    }

    // ══════════════════════════════════════════════
    //  INTERNALS
    // ══════════════════════════════════════════════

    /// @dev 0: unsupported, 1: plain 7579/7821 batch (no opData mode bit), 2: 7821 batch with optional opData.
    function _executionModeId(bytes32 mode) internal pure returns (uint256 id) {
        assembly ("memory-safe") {
            let m := and(shr(mul(22, 8), mode), 0xffff00000000ffffffff)
            id := eq(m, 0x01000000000000000000)
            id := or(shl(1, eq(m, 0x01000000000078210001)), id)
        }
    }

    /// @dev Empty opData: require {DefaultAccount} caller auth. Non-empty: AccountConfiguration auth over a digest
    ///      of `(mode, batch)` — the signature is not part of the digest, so it can sit in `opData` safely.
    function _authorizeExecute(bytes32 mode, bytes32[] calldata pointers, bytes calldata opData) internal view {
        if (opData.length == 0) {
            if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedExecution();
            return;
        }
        bytes32 digest = keccak256(abi.encode(EXECUTE_TYPEHASH, mode, _hashBatch(pointers)));
        ACCOUNT_CONFIGURATION.authenticateActor(address(this), digest, opData);
    }

    function _hashBatch(bytes32[] calldata pointers) internal pure returns (bytes32 h) {
        h = keccak256("batch");
        for (uint256 i; i < pointers.length; i++) {
            (address target, uint256 value, bytes calldata data) = LibERC7579.getExecution(pointers, i);
            h = keccak256(abi.encodePacked(h, target, value, keccak256(data)));
        }
    }

    function _executePointers(bytes32[] calldata pointers) internal {
        for (uint256 i; i < pointers.length; i++) {
            (address target, uint256 value, bytes calldata data) = LibERC7579.getExecution(pointers, i);
            (bool success,) = target.call{value: value}(data);
            if (!success) revert CallFailed();
        }
    }
}
