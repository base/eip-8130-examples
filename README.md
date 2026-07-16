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
```

| Path | What |
|------|------|
| `upgradeable/UpgradeableAccount` | General UUPS-upgradeable account |
| `upgradeable/UpgradeableProxy` | Per-account ERC-1967 proxy bytecode |
| `erc4337/BackwardsCompatible4337Account` | `DefaultAccount` + `validateUserOp` for bundler/EntryPoint support |
| `erc7579/ERC7579Account` | Minimal 7579 account; keeps `executeBatch(Call[])` and adds ERC-7821 `execute(mode, data)` |
| `erc7579/AccountConfigurationValidator` | ERC-7579 validator module that authenticates via AccountConfiguration |

### `executeBatch` vs ERC-7821 `execute`

Same capability — atomic batch calls — different encoding:

- **`executeBatch(Call[])`** — typed ABI (EIP-8130 / `DefaultAccount`). Prefer this when you control the caller.
- **`execute(mode, executionData)`** — ERC-7821 / ERC-7579 wallet encoding (`abi.encode(calls)` ± `opData`). Prefer this for wallet/tooling interoperability.

Auth for the 7579 example goes through `{AccountConfigurationValidator}` (a `MODULE_TYPE_VALIDATOR`), not a key stored on the account.

## Getting started

```bash
git submodule update --init --recursive
forge build
forge test
```
