# Signature aggregation (draft stub)

> **Warning** — Unaudited example. Stubs the block STARK and a native PQ scheme.

A sketch of [signature aggregation for 8130 authenticators](https://github.com/chunter-cb/EIPs/blob/f5abeeb28470a36d2c4cf10150d34cb78905f185/EIPS/eip-draft_signature-aggregation.md):
inline and aggregated are two representations of **one** `actorId`. Authorization stays in the
Keystore. Only the cryptographic check is deferred.

The pairing-sum demo in `script/BLSAggregateDemo.s.sol` is a different, BLS-specific compression.
This folder follows the draft: a representation byte, block facts, `AGG_WRAP`, and
`isDependencyProven`.

| Piece | Role |
|-------|------|
| `HashSchemeAuthenticator` | Stub "native" scheme (`sig = keccak256(hash ‖ pk)`). Stands in for ML-DSA. |
| `AggregatableBLSAuthenticator` | Real BLS INLINE verify; AGGREGATED reads the fact stub |
| `AggregationWrapper` | `message = keccak256(hash ‖ depsCommitment)` + optional inner auth |
| `MockAggregationContext` | Stub STARK / TX_CONTEXT: `{proveFact}`, `{isDependencyProven}` |

```
SCHEME_AUTH ‖ INLINE (0x00)     ‖ pubkey ‖ signature     // self-contained
SCHEME_AUTH ‖ AGGREGATED (0x01) ‖ actorId (32)           // ~53 bytes
```

`actorId = keccak256(SCHEME_AUTH ‖ pubkey)` in both. The builder flips the byte; the wallet signs once.

```bash
forge test --match-contract AggregationTest
forge script script/SignatureAggregationDemo.s.sol
```
