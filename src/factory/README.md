# Example external factory (`SETDELEGATE` + EIP-8130)

Reference, **unaudited** example of an external account factory that combines
[EIP-7819](https://eips.ethereum.org/EIPS/eip-7819) (`SETDELEGATE`) with the EIP-8130 Keystore.

`SETDELEGATE` places a 23-byte delegation indicator (`0xef0100 || target`) at a deterministic address.
The account then imports itself: `Keystore.importAccount` is `msg.sender`-gated and reads the actor set
from `{IKeystoreImport.getImportActors}` on the account's code. ERC-1271 only confirms
`computeImportDigest` of that set.

```
factory.deploy(initialActors, implementation, userSalt)
  1. SETDELEGATE(salt, implementation)     // code = 0xef0100 || implementation
  2. account.bootstrap(actorsHash, chainId, initialActors)
       latch := actors
       KEYSTORE.importAccount(chainId, "")   // msg.sender = account
         actors = account.getImportActors()
         STATICCALL account.isValidSignature(computeImportDigest(...), "")
       latch := 0
```

After import the account is a normal {DefaultAccount}: `execute` / `executeBatch` and operational ERC-1271.

```bash
forge test --match-contract SetDelegateFactoryTest
```

Requires EIP-7819 for production. Tests override `_setDelegate` with `vm.etch`.

## Initcode factory (constructor + calldata actors)

`createAccount` never runs a constructor — Keystore wraps **runtime** in a `CODECOPY+RETURN` loader. If initcode must run, the factory CREATE2s the account itself, then the account imports.

Actors are not stored on the account. `{completeImport}` takes them as calldata, checks `keccak256(abi.encode(actors)) == ACTORS_HASH` (immutable from the constructor), stashes them in transient storage, and calls `Keystore.importAccount`. The Keystore's no-arg `getImportActors` STATICCALL reads that stash.

```
factory.deploy(userSalt, actors)              // owner + guardian, both scope 0
  1. CREATE2 InitcodeAccount(keystore, hash)  // constructor runs; ACTORS_HASH immutable
  2. account.completeImport(chainId, actors)  // calldata only
       tstore actors
       KEYSTORE.importAccount(chainId, "")
         actors = getImportActors()           // tload
         1271 confirms computeImportDigest
```

Recovery is the second admin in calldata — either key can rotate the other on the Keystore. No guardian list in account storage.

`completeImport` is permissionless and hash-bound: a deployed-but-not-imported account (`factory.create`) can be finished by anyone with the committed set. Wrong actors revert; the account stays uninitialized.

```bash
forge test --match-contract InitcodeFactoryTest
```
