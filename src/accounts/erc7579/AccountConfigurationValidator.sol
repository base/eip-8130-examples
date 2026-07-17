// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AccountConfiguration} from "eip-8130/AccountConfiguration.sol";
import {
    IERC7579Module,
    IERC7579Validator,
    MODULE_TYPE_VALIDATOR,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED
} from "openzeppelin/interfaces/draft-IERC7579.sol";
import {PackedUserOperation} from "openzeppelin/interfaces/draft-IERC4337.sol";

/// @notice ERC-7579 validator module that delegates auth to EIP-8130 {AccountConfiguration}.
///
///         Install on an {ERC7579Account} (or any 7579 account) so signature / UserOp validation uses the
///         account's actors and authenticators instead of a key stored in the module.
///
///         Signature format is the EIP-8130 blob: `authenticator(20) || authenticator-specific data`.
///
/// @author Coinbase
contract AccountConfigurationValidator is IERC7579Validator {
    /// @notice The AccountConfiguration system contract used for all authentication.
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
    }

    /// @inheritdoc IERC7579Module
    function onInstall(bytes calldata) external pure {}

    /// @inheritdoc IERC7579Module
    function onUninstall(bytes calldata) external pure {}

    /// @inheritdoc IERC7579Module
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    /// @inheritdoc IERC7579Validator
    /// @dev `msg.sender` is the smart account. Authenticates `userOp.signature` over `userOpHash` via
    ///      AccountConfiguration; does not enforce elevated scope bits (the account / EntryPoint path should).
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external view returns (uint256) {
        try ACCOUNT_CONFIGURATION.authenticateActor(msg.sender, userOpHash, userOp.signature) returns (
            bytes32, uint8, address
        ) {
            return VALIDATION_SUCCESS;
        } catch {
            return VALIDATION_FAILED;
        }
    }

    /// @inheritdoc IERC7579Validator
    /// @dev `msg.sender` is the smart account. Uses {AccountConfiguration-verifySignature} so only operational
    ///      actors (admin, or SENDER without POLICY) may produce a valid ERC-1271 result.
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        return ACCOUNT_CONFIGURATION.verifySignature(msg.sender, hash, signature)
            ? bytes4(0x1626ba7e)
            : bytes4(0xffffffff);
    }
}
