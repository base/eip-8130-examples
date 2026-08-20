# eip-8130-examples

> **Warning** — Unaudited example code. Not for production use.

Example (non-canonical) EIP-8130 account wallets, authenticators, and a toy privacy pool, extracted from the core
[`base/eip-8130`](https://github.com/base/eip-8130) repository. Accounts build on the canonical `DefaultAccount`
and defer all authorization to the `Keystore` system contract.

## Layout

```
src/accounts/
  upgradeable/   — UUPS-upgradeable DefaultAccount + UpgradeableProxy
  erc4337/       — opt-in ERC-4337 account (validateUserOp) for non-8130 chains
  erc7579/       — ERC-7579 + ERC-7821 account; Keystore auth as a validator module
src/authenticators/
  pure/          — stateless signature authenticators (AlwaysValid, BLS, Groth16, multisig, Schnorr)
  gas-payers/    — payer-scoped authenticators (Chainlink, Aerodrome, SimplePoolAuth)
src/privacy/     — toy note pool + splitter (not 8130-aware; SimplePoolAuth sponsors spends)
```

| Path | What |
|------|------|
| `upgradeable/UpgradeableAccount` | General UUPS-upgradeable account with owner-signed, compare-and-swap upgrades |
| `upgradeable/UpgradeableProxy` | Per-account ERC-1967 proxy bytecode |
| `erc4337/BackwardsCompatible4337Account` | `DefaultAccount` + `validateUserOp` for bundler/EntryPoint support |
| `erc7579/ERC7579Account` | Minimal 7579 account; keeps `executeBatch(Call[])` and adds ERC-7821 `execute(mode, data)` |
| `erc7579/AccountConfigurationValidator` | ERC-7579 validator module that authenticates via the `Keystore` |
| `authenticators/` | Non-canonical authenticators — see [`src/authenticators/README.md`](src/authenticators/README.md) |
| `privacy/SimplePool` | Toy note pool + splitter — see [`src/privacy/README.md`](src/privacy/README.md) |

## Authorization model

All authorization is deferred to the EIP-8130 `Keystore`. An auth blob on the wire is
`authenticator(20) || authenticator-specific data`; the `Keystore` resolves the `actorId`, verifies it is a live
actor bound to that authenticator, and returns its `scope`. ERC-1271 signing rides on the account-scoped signature
envelope (`sigType(1) || authenticator(20) || data`) via `Keystore.validateSignature`, gated on operational
authority (`Scopes.isOperator`).

### `executeBatch` vs ERC-7821 `execute`

Same capability — atomic batch calls — different encoding:

- **`executeBatch(Call[])`** — typed ABI (EIP-8130 / `DefaultAccount`). Prefer this when you control the caller.
- **`execute(mode, executionData)`** — ERC-7821 / ERC-7579 wallet encoding (`abi.encode(calls)` ± `opData`). Prefer this for wallet/tooling interoperability.

Auth for the 7579 example goes through `{AccountConfigurationValidator}` (a `MODULE_TYPE_VALIDATOR`), not a key stored on the account.

## Authenticators

See [`src/authenticators/README.md`](src/authenticators/README.md). These are non-canonical. Canonical
authenticators (`P256`, `WebAuthn`, `Delegate`, built-in K1) stay in `base/eip-8130`. Gas-payer examples
need call/gas/maxCost reads that the shipped `ITransactionContext` precompile does not provide.

## Privacy pool

See [`src/privacy/README.md`](src/privacy/README.md). A withdraw-to-escrow note pool with public amounts
and a keccak tree — not full privacy. `{SimplePoolAuth}` is the 8130 payer policy that pins a spend
against it.

## Deployment

The examples deployment compiles the `Keystore` from the pinned `lib/eip-8130` submodule, then deploys it
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
