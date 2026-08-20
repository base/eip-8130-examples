# Privacy pool (example)

> **Warning** — Unaudited toy. Not a production privacy system.

A withdraw-to-escrow note pool that is **not** EIP-8130-aware. The 8130 payer policy that
sponsors spends lives in [`../authenticators/gas-payers/SimplePoolAuth.sol`](../authenticators/gas-payers/SimplePoolAuth.sol).

This is **not** full privacy: amounts are public, the tree is keccak256 (not Poseidon), there are
no output notes / internal transfers, and `{INoteVerifier}` is a stub you wire to a real circuit.
What it does get right is the pool shape: deposit binds `msg.value`, spend is self-verifying, and
payouts go through a splitter so the recipient is not paid until they pull.

| Contract | Role |
|----------|------|
| `SimplePool` | Escrow ETH behind `H(NOTE_DOMAIN, msg.value, secretHash)`; `spend` credits the splitter |
| `PoolSplitter` | Per-nullifier credit for K; `payFee` then `withdraw` |
| `INoteVerifier` | Pluggable spend proof (range-check field elements in a real verifier) |

Flow: `deposit` → `spend` (credit splitter for K) → `payFee` (K reimburses a sponsor) → `withdraw` (K takes the rest).
