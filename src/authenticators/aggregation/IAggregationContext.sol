// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Transaction-context surface from the 8130 signature-aggregation draft.
///
/// @dev Not on the shipped {ITransactionContext}. A block STARK would populate facts;
///      this repo's {MockAggregationContext} is that stub. Authorization (actor_config,
///      scope, expiry) stays inline in the Keystore — only the cryptographic check is
///      deferred.
interface IAggregationContext {
    /// @notice Whether the block proof covers `(scheme, message, actorId)`.
    function isFactProven(address scheme, bytes32 message, bytes32 actorId) external view returns (bool);

    /// @notice ERC-1271 / in-EVM resolution of an aggregated blob (`isDependencyProven`).
    function isDependencyProven(bytes32 hash, bytes32 actorId) external view returns (bool);

    function dependencyCount() external view returns (uint256);

    function dependencyAt(uint256 i) external view returns (uint8 kind, bytes32 hash, bytes32 actorId);
}
