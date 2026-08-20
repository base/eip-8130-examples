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

None in this folder — the canonical `{DelegateAuthenticator}` in `base/eip-8130` is the keystore-bounded
authenticator.

### Gas payers

Payer-scoped actors. They ignore the signed `hash` and instead pin phase-0 repayment so the payer is made
whole. All of them need `{IExtendedTransactionContext}` (see above).

| Path | What |
|------|------|
| `gas-payers/ChainlinkPayerAuthenticator` | ERC-20 sponsorship priced via a Chainlink ETH/USD feed; optional blocklist |
| `gas-payers/AeroPayerAuthenticator` | ERC-20 sponsorship quoted via Aerodrome WETH/TOKEN |
| `gas-payers/SimplePoolAuth` | Sponsors a [`SimplePool`](../privacy/SimplePool.sol) spend (phase 0: spend + `payFee`) |

The pool is not an authenticator — see [`src/privacy/README.md`](../privacy/README.md).
