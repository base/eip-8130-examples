// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Transaction-context surface that gas-payer authenticators need (calls, gas limit, max cost).
///
/// @dev The canonical {ITransactionContext} in `eip-8130` currently only exposes
///      `getTransactionSender`, `getTransactionPayer`, and `getTransactionSenderActorId`, and is populated only
///      while the protocol is dispatching a transaction's calls. STATICCALL during validation (and on non-8130
///      chains) returns zero/default values. These examples therefore cannot run against that precompile as-shipped:
///      they need `getTransactionCalls` / `getTransactionGasLimit` / `maxCost` at validation time.
interface IExtendedTransactionContext {
    struct Call {
        address to;
        bytes data;
    }

    function getTransactionSender() external view returns (address);
    function getTransactionPayer() external view returns (address);
    function getTransactionSenderActorId() external view returns (bytes32);
    function getTransactionCalls() external view returns (Call[][] memory);
    function getTransactionGasLimit() external view returns (uint256);
    /// @notice Protocol-computed worst-case payer charge in wei (incl. enshrined auth costs charged outside gas_limit).
    function maxCost() external view returns (uint256);
}
