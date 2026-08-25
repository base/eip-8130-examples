// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Block-level BLS aggregate on the transaction-context precompile.
///
/// @dev Not on the shipped {ITransactionContext}. Aggregation is a **storage /
///      re-execution** concern, not inclusion:
///        1. Mempool / first verify: each BLS tx carries a full sig and
///           {BLSAuthenticator.authenticate} checks it alone.
///        2. Seal: sum the G2 sigs, replace each BLS `sender_auth` with a
///           pointer (`0xff || aggregateId || pubKey`), keep K1 (and other)
///           auths intact.
///        3. Re-run: the protocol verifies {getBLSAggregateSignature} once
///           against every pointed-to (hash, pk). Individual `authenticate`
///           cannot do that pairing — it needs the whole member set.
interface IBLSAggregateContext {
    /// @notice Id of the aggregate stored with this block. Pointer auths must match.
    function getBLSAggregateId() external view returns (bytes32);

    /// @notice Aggregated G2 signature (256 bytes). Empty if the block was not compressed.
    function getBLSAggregateSignature() external view returns (bytes memory sigG2);
}
