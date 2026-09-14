# Sessions (churn tier)

> **Warning** — Unaudited, **non-canonical** examples. Not for production use.

The **churn tier** of a two-tier keystore account. Pair these with [`../homechain/`](../homechain/) (the **admin
tier**) to get: a rarely-touched admin whose freshness is gated by a home-chain proof, and a high-churn set of
short-lived, non-admin session keys that transact with nothing but their own signature.

Both contracts here are the *same idea* — a committed session key redeemed by its own fresh signature — with two
authorizers:

| Path | Authorizer | `actorId` | Use when |
|------|-----------|-----------|----------|
| `MerkleSessionAuthenticator` | a merkle **membership proof** | the committed **root** | one commitment authorizes a whole set; rotating the set is one admin op |
| `OperatorSessionAuthenticator` | a live **operator's grant** | the **operator's** id | a non-admin operator mints keys itself — no admin, no per-key write |

Register the anchor (`root` / operator id) **once**, bound to the authenticator, with a **bounded (non-admin) scope
and a short expiry** — never `scope == 0`. That is the whole safety story: the anchor is the on-chain floor, and
the Keystore re-checks its liveness on every call.

## Why a proof/grant alone can never act

Membership (or a grant) is *provenance*, not *authentication*. Each call ALSO carries a fresh `hash`-bound
signature from the leaf key, folded into the committed leaf. So a public, replayable proof — or a leaked grant —
lets an attacker *install* a key they cannot *sign for*. (This is the split-install/authenticate rule the canonical
`DelegateAuthenticator` and [`../homechain/`](../homechain/) also follow.)

## Properties

| Property | How it holds |
|----------|--------------|
| **Admin changes never replay** | Admin rotation is a nonce-serialized write on the home chain, proven via `homechain/`. These authenticators are registered non-admin and can never return `scope == 0`. |
| **Sessions are a separate track** | The session anchor is a distinct actor with a bounded scope; churning it never touches the admin. |
| **No global counter for the hot path** | A session is a membership proof / grant + signature — not a sequenced account change. |
| **Anti-fork** | The `root` / operator id is an on-chain anchor. A leaf cannot forge a path to a root it isn't in (second-preimage), and rotating the set is an admin op; cross-chain freshness of the *anchor* comes from the home proof. |
| **Immediate transacting** | A session key acts with just its proof/grant + its own signature — no wait on any attestation or checkpoint. |
| **Cascading expiry, no per-chain revocation** | The Keystore caps every session by the anchor's own expiry, so the whole set/subtree lapses at once; `OperatorSessionAuthenticator` also dies instantly if the operator is revoked. |
| **Bounded compromise** | A leaked proof/grant is not a key; a minted key is non-admin, ≤ the operator's scope, and expiry-capped — blast radius is the committed set / operator subtree, not the account. |

See each contract's header for the exact `data` layout.
