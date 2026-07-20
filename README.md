# eip-8130-examples

> **Warning** — Unaudited example code. Not for production use.

Example (non-canonical) EIP-8130 account wallets, extracted from the core
[`base/eip-8130`](https://github.com/base/eip-8130) repository.

## Layout

```
src/accounts/
  upgradeable/   — UUPS-upgradeable DefaultAccount + UpgradeableProxy
  erc4337/       — opt-in ERC-4337 account (validateUserOp) for non-8130 chains
  erc7579/       — ERC-7579 + ERC-7821 account; AccountConfiguration as a validator module
src/factory/
  SetDelegateFactory / BootstrapAccount — EIP-7819 SETDELEGATE + importAccount external factory
src/authenticators/
  ZKProofAuthenticator            — authenticate with a zero-knowledge proof
  CrossChainConfigAuthenticator   — accept a key authorized on another chain
  interfaces/                     — pluggable verifier / oracle surfaces
```

| Path | What |
|------|------|
| `upgradeable/UpgradeableAccount` | General UUPS-upgradeable account |
| `upgradeable/UpgradeableProxy` | Per-account ERC-1967 proxy bytecode |
| `erc4337/BackwardsCompatible4337Account` | `DefaultAccount` + `validateUserOp` for bundler/EntryPoint support |
| `erc7579/ERC7579Account` | Minimal 7579 account; keeps `executeBatch(Call[])` and adds ERC-7821 `execute(mode, data)` |
| `erc7579/AccountConfigurationValidator` | ERC-7579 validator module that authenticates via AccountConfiguration |
| `factory/SetDelegateFactory` | External factory: `SETDELEGATE` + self-driven `importAccount` bootstrap |
| `factory/BootstrapAccount` | Minimal bootstrap-aware implementation (transient latch + ERC-1271) |
| `authenticators/ZKProofAuthenticator` | Authenticate via a SNARK instead of a raw signature |
| `authenticators/CrossChainConfigAuthenticator` | Accept a key that was added to the account on another chain |

## Authenticators

An EIP-8130 authenticator implements a single `view` method:

```solidity
function authenticate(bytes32 hash, bytes calldata data) external view returns (bytes32 actorId);
```

It derives an `actorId` from `data`, checks that `data` authorizes `hash`, and returns the `actorId` (or
`bytes32(0)` on failure). `AccountConfiguration` then checks that `actorId` is a live actor bound to that
authenticator. The auth blob on the wire is always `authenticator(20) || authenticator-specific data`.

### Upstream authenticators (in `base/eip-8130`)

These ship in the core repo and are the baseline set:

| Authenticator | actorId | Notes |
|---------------|---------|-------|
| K1 (sentinel `address(1)`) | `bytes20(signer)` | Native `ecrecover`; not a deployed contract |
| `P256Authenticator` | `keccak256(x‖y)` | Raw secp256r1 ECDSA |
| `WebAuthnAuthenticator` | `keccak256(x‖y)` | P-256 passkey / WebAuthn assertion |
| `DelegateAuthenticator` | `bytes20(delegate)` | One-hop vouch by another account's admin actor |
| `AlwaysValidAuthenticator` | `keccak256("ALWAYS_VALID")` | Keyless relay — authorizes ANY tx (use with care) |

### New examples (this repo)

**`ZKProofAuthenticator`** — authenticate with a zero-knowledge proof instead of a raw signature. The actor's
public identity is a `commitment` (e.g. a Poseidon hash of a secret, or a group Merkle root); the prover submits a
SNARK proving knowledge of the secret behind `commitment`, bound to `hash`. `actorId = commitment` and nothing
about the secret leaks on-chain. Proof checking is delegated to a pluggable `IZKVerifier` (Groth16 / PLONK / Halo2
— the proof system is the verifier's concern). Data layout: `commitment(32) || proof`; public inputs are
`[hash, commitment]`. Being a stateless `view`, it cannot burn a nullifier, so bind freshness via the digest (the
8130 signed flows already bind a monotonic sequence).

**`CrossChainConfigAuthenticator`** — "I added this key on Base; here is proof." EIP-8130 actor config is per-chain
on the local channel, so a key added on one chain is not automatically usable on another. The account installs one
bridge actor (`actorId = the account itself`, authenticator = this contract). Then any key that is an *admin* actor
of the account on a trusted source chain can authenticate by presenting a nested signature over `hash` plus proof —
via a pluggable `ICrossChainConfigOracle` — that the key is an admin actor on the source chain. The vouch is
admin-only (source scope must be `0x00`), mirroring `DelegateAuthenticator`'s non-escalation guarantee. The trust
model lives entirely behind the oracle interface, which can be backed by a canonical state-root oracle + MPT storage
proof (trustless), a Chainlink CCIP / attestation relay, or a trusted committee.

### `executeBatch` vs ERC-7821 `execute`

Same capability — atomic batch calls — different encoding:

- **`executeBatch(Call[])`** — typed ABI (EIP-8130 / `DefaultAccount`). Prefer this when you control the caller.
- **`execute(mode, executionData)`** — ERC-7821 / ERC-7579 wallet encoding (`abi.encode(calls)` ± `opData`). Prefer this for wallet/tooling interoperability.

Auth for the 7579 example goes through `{AccountConfigurationValidator}` (a `MODULE_TYPE_VALIDATOR`), not a key stored on the account.

## Deployment

The examples deployment compiles `AccountConfiguration` from the pinned `lib/eip-8130` submodule, then deploys it
with the `UpgradeableAccount` and `BackwardsCompatible4337Account` implementation singletons:

```bash
# Preview deterministic addresses and account proxy bytecode.
forge script script/Deploy.s.sol --sig "addresses()"

# Deploy all three contracts.
forge script script/Deploy.s.sol \
  --rpc-url "$RPC_URL" --broadcast --private-key "$PRIVATE_KEY"
```

The script uses a deterministic CREATE2 factory and zero salt. Each deployment is idempotent, so an existing
contract at its computed address is reused. The script also prints the 93-byte `UpgradeableProxy` bytecode and the
45-byte ERC-1167 runtime for creating accounts backed by each implementation.

## Getting started

```bash
git submodule update --init --recursive
forge build
forge test
```
