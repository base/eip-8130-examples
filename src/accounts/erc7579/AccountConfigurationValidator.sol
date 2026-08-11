// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Keystore} from "eip-8130/Keystore.sol";
import {Scopes} from "eip-8130/libraries/Scopes.sol";
import {
    IERC7579Module,
    IERC7579Validator,
    MODULE_TYPE_VALIDATOR,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED
} from "openzeppelin/interfaces/draft-IERC7579.sol";
import {PackedUserOperation} from "openzeppelin/interfaces/draft-IERC4337.sol";

/// @notice ERC-7579 validator module that delegates auth to the EIP-8130 {Keystore}.
///
///         Install on an {ERC7579Account} (or any 7579 account) so signature / UserOp validation uses the
///         account's actors and authenticators instead of a key stored in the module.
///
///         Signature format is the EIP-8130 blob: `authenticator(20) || authenticator-specific data` for UserOps,
///         and the account-scoped envelope `sigType(1) || authenticator(20) || data` for ERC-1271.
///
/// @author Coinbase
contract AccountConfigurationValidator is IERC7579Validator {
    /// @notice The Keystore system contract used for all authentication.
    Keystore public immutable KEYSTORE;

    /// @notice ERC-1271 magic value returned for a valid signature.
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    /// @notice ERC-1271 sentinel returned for an invalid signature.
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;

    constructor(address keystore) {
        KEYSTORE = Keystore(keystore);
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
    /// @dev `msg.sender` is the smart account. Authenticates `userOp.signature` over `userOpHash` via the Keystore;
    ///      does not enforce scope bits (the account / EntryPoint path should). The userOpHash is already
    ///      replay-safe, so it is authenticated directly rather than through the signature envelope.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external view returns (uint256) {
        try KEYSTORE.authenticateActor(msg.sender, userOpHash, userOp.signature) returns (bytes32, uint16) {
            return VALIDATION_SUCCESS;
        } catch {
            return VALIDATION_FAILED;
        }
    }

    /// @inheritdoc IERC7579Validator
    /// @dev `msg.sender` is the smart account. Uses {Keystore.validateSignature} and gates on {Scopes.isOperator}
    ///      so only operational actors (admin, or SENDER without POLICY) may produce a valid ERC-1271 result,
    ///      mirroring {DefaultAccount.isValidSignature}. `signature` is the account-scoped envelope
    ///      `sigType(1) || authenticator(20) || data`.
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4)
    {
        try KEYSTORE.validateSignature(msg.sender, hash, signature) returns (bytes32, uint16 scope) {
            return Scopes.isOperator(scope) ? ERC1271_MAGIC_VALUE : ERC1271_INVALID;
        } catch {
            return ERC1271_INVALID;
        }
    }
}
