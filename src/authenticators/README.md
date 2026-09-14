# Authenticators (examples)

> **Warning** — Unaudited, **non-canonical** example authenticators. Not for production use.
> Canonical authenticators live in [`base/eip-8130`](https://github.com/base/eip-8130) (`P256Authenticator`,
> `WebAuthnAuthenticator`, `DelegateAuthenticator`, plus built-in `K1_AUTHENTICATOR` at `address(1)`).

These contracts implement `IAuthenticator.authenticate(hash, data) → actorId`. They are the old
`src/verifiers/` set (renamed verifier → authenticator) plus a payer policy for the toy privacy pool
in [`src/privacy/`](../privacy/).

## Transaction context

Gas-payer authenticators inspect the transaction's calls, gas limit, and max cost at validation time.
The shipped `{ITransactionContext}` precompile in `eip-8130` does **not** expose those methods (only
sender / payer / senderActorId, and only while the protocol is dispatching calls). These examples
therefore cannot run against that precompile as-shipped — they take an `{IExtendedTransactionContext}`
address instead.

Two aggregation sketches live here:

- **Pairing-sum (BLS-only):** inclusion still uses `{BLSAuthenticator}` per tx; a sealed block stores one G2
  and pointers (`{IBLSAggregateContext}`). Demo: `forge script script/BLSAggregateDemo.s.sol`.
- **Draft-shaped (representation byte + facts):** inline and aggregated share one `actorId`; a mock context
  stubs the block STARK and `isDependencyProven`. See [`aggregation/`](aggregation/).
  Demo: `forge script script/SignatureAggregationDemo.s.sol`.

## Buckets

### Pure function

Stateless (or precompile-only) signature checks. No Keystore lookup, no transaction-context reads.

| Path | Algorithm |
|------|-----------|
| `pure/AlwaysValidAuthenticator` | Always succeeds; fixed `ALWAYS_VALID` actorId (keyless / dangerous) |
| `pure/BLSAuthenticator` | BLS12-381 pairing (EIP-2537) |
| `pure/Groth16Authenticator` | Groth16 over BN254 (generic VK-in-calldata) |
| `pure/MultisigAuthenticator` | secp256k1 M-of-N |
| `pure/SchnorrAuthenticator` | secp256k1 Schnorr via ecrecover |

Canonical counterparts (not duplicated here): `K1_AUTHENTICATOR`, `P256Authenticator`, `WebAuthnAuthenticator`.

### Keystore bounded

Authentication that consults another account's Keystore config (one hop).

| Path | What |
|------|------|
| `keystore/KeystoreMultisigAuthenticator` | M-of-N over 8130 accounts; each vouch is `{Keystore.authenticateActor}` (admin-only) |

Canonical counterpart: `{DelegateAuthenticator}` in `base/eip-8130` (1-of-1 hop to one account).

### Cross-chain (home chain)

Honor a key that is authorized as **admin** of an account on a remote "home" chain (e.g. keep the master key on
L1, use it on L2s). A cross-chain `{DelegateAuthenticator}`: the vouching config is *proven* from the home chain
instead of read from the local Keystore.

| Path | What |
|------|------|
| `homechain/HomeChainAuthenticator` | `actorId = keccak256(homeChainId ‖ homeAccount)`; needs a fresh `hash` signature **and** a home-config admin proof |
| `homechain/IHomeChainConfigProver` | Trust seam: proves `{Keystore.getActorConfig}` for an actor on the home chain |
| `homechain/MockHomeChainConfigProver` | Test/demo prover (seeded facts; ignores `proof`) — for unit-testing the authenticator |

The proof only attests slowly-changing home state, so a `hash`-bound signature is still required every call.
Intended pattern is **sync + expire**: the proof-carrying admin authorizes a cheap short-lived operator; day-to-day
txs use the operator with no proof; re-authorize when it lapses.

#### Real state-proof prover (`homechain/prover/`)

A genuine (non-mock) `{IHomeChainConfigProver}` built on OpenZeppelin `{TrieProof}` + `{RLP}`. Every home reduces
to *"derive the home Keystore's storage root, then storage-prove `_actors[actorId][account].config`"*; only the
storage-root derivation differs per chain (the recursive part), keyed by a `chainId → prover` registry.

| Path | What |
|------|------|
| `prover/HomeChainProver` | Orchestrates: L1 state root (oracle) → per-chain storage root → actor-config storage proof + decode |
| `prover/StateProofLib` | MPT/RLP helpers: actor-config slot, account/storage/header decode, output-root & confirmData hashing |
| `prover/IChainProver` + `L1ChainProver` | Home = L1: account-prove the Keystore against the L1 state root |
| `prover/OpStackChainProver` | Home = Optimism / Base: L1-committed output root → L2 state root → Keystore account |
| `prover/ArbitrumChainProver` | Home = Arbitrum: L1-committed confirmData → L2 header → L2 state root → Keystore account |
| `prover/IL1StateOracle` + `L1BlockStateOracle` | L1 state root on an OP-stack local chain (`L1Block` predeploy + RLP header) |
| `prover/MockL1StateOracle` | Settable L1 state root for tests/fixtures |

Verification is real MPT (tests build single-leaf trie fixtures and validate slot/packing against a live Keystore).
Two example simplifications remain for production: the caller picks which output/confirmData slot is read (must be
constrained + finalized), and non-inclusion (a *missing* actor) is not positively proven — it just reverts.

### Sessions (churn tier)

The high-churn companion to the home-chain **admin tier**: a committed, short-lived, non-admin session key
redeemed by its own fresh signature. Register the anchor (`root` / operator id) once with a bounded scope and a
short expiry — the Keystore then caps every session by that anchor's liveness (cascading expiry). See
[`sessions/README.md`](sessions/README.md) for the two-tier model and the full property table.

| Path | What |
|------|------|
| `sessions/MerkleSessionAuthenticator` | Committed set: `actorId = root`; a membership proof + the leaf's fresh signature; one commitment covers many keys |
| `sessions/OperatorSessionAuthenticator` | Operator-minted: a live non-admin operator grants a session key; `actorId` = the operator's — so it inherits the operator's scope and dies when the operator does |

### Gas payers

Payer-scoped actors. They ignore the signed `hash` and instead pin phase-0 repayment so the payer is made
whole. All of them need `{IExtendedTransactionContext}` (see above).

| Path | What |
|------|------|
| `gas-payers/ChainlinkPayerAuthenticator` | ERC-20 sponsorship priced via a Chainlink ETH/USD feed; optional blocklist |
| `gas-payers/AeroPayerAuthenticator` | ERC-20 sponsorship quoted via Aerodrome WETH/TOKEN |
| `gas-payers/SimplePoolAuth` | Sponsors a [`SimplePool`](../privacy/SimplePool.sol) spend (phase 0: spend + `payFee`) |

The pool is not an authenticator — see [`src/privacy/README.md`](../privacy/README.md).

### Signature aggregation (draft stub)

| Path | What |
|------|------|
| `aggregation/HashSchemeAuthenticator` | Cheap ML-DSA stand-in (`sig = keccak256(hash ‖ pk)`) with INLINE / AGGREGATED |
| `aggregation/AggregatableBLSAuthenticator` | Real BLS INLINE; AGGREGATED reads `{isFactProven}` |
| `aggregation/AggregationWrapper` | `AGG_WRAP`: `message = keccak256(hash ‖ depsCommitment)` + optional inner auth |
| `aggregation/MockAggregationContext` | Stub STARK / TX_CONTEXT (`proveFact`, `isDependencyProven`) |
