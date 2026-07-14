# eip-8130-examples

> **Warning** — Unaudited example code. Not for production use.

Example (non-canonical) EIP-8130 account wallets, extracted from the core
[`base/eip-8130`](https://github.com/base/eip-8130) repository:

- `UpgradeableAccount` / `UpgradeableProxy` — a general UUPS-upgradeable account.
- `BackwardsCompatible4337Account` — an opt-in ERC-4337 account (`validateUserOp`)
  for bundler/EntryPoint support on non-8130 chains.

## Layout

- `src/accounts/` — the example account implementations.
- `test/unit/accounts/` — their test suites (reuse the core test harness).

The core contracts are consumed via the `lib/eip-8130` git submodule.

## Getting started

```bash
git submodule update --init --recursive
forge build
forge test
```
