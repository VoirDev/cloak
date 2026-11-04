# TypeScript client

`@voirdev/cloak-client` is the Cloak client for TypeScript. It talks to a host's `/cloak/v1`
endpoints and does every encryption, decryption, signature and log check on the device with
`@voirdev/cloak-crypto`; the server only stores ciphertext and signed entries, and nothing it
returns is used unchecked.

People are named by the host's own user ids everywhere: `register({ userId })`, `addMember`,
`members[].userId`, a write's `writerUserId`. The host's authentication must give the same id for
the request. Underneath, Cloak names each user by a UUID derived from it (`cloakUserId` in
`@voirdev/cloak-crypto`), and accepts a host id the server names only when it derives that UUID.

Install it from GitHub Packages, with a token that may read packages, after pointing the scope at
the registry in `.npmrc`:

```ini
@voirdev:registry=https://npm.pkg.github.com
```

It brings `@voirdev/cloak-crypto`, the protocol itself
([`cloak-ts/packages/crypto`](../cloak-ts/packages/crypto/README.md)), which apps rarely call
directly.

```ts
const cloak = createCloakClient({
  baseUrl: "/cloak/v1",
  storage: createIndexedDbStorage(),
});

// First time: show both codes once and ask the user to keep them.
const { session, secretKeyCode, recoveryKeyCode } = await cloak.register({
  userId: hostUserId, // the host's id of the signed-in user
  password,
});

// Later, on a new device: the code once, then the password alone if the device remembers it.
const session = await cloak.unlock({
  password,
  secretKeyCode,
  rememberSecretKey: true,
});

// Vaults hold access. A node lives in its home vault and may be shared, by name, into others.
const team = await session.createVault();
const shared = await session.createVault();
const node = await session.createNode(team.id, record.id); // keep it beside the record
await session.shareNode(node, shared.id, ["general"]);
await session.writeSections([
  {
    vaultId: team.id,
    node,
    name: "secrets",
    type: "server",
    content: { password },
  },
  {
    vaultId: shared.id,
    node,
    name: "general",
    type: "server",
    content: { ip },
  },
]);

// Adding someone new needs their fingerprint, compared in person or by QR code.
await session.confirmFingerprint(bobId, fingerprintBobShowed);
await session.addMember(shared.id, bobId, "viewer");
await session.rotate(shared.id, [bobId]); // removes Bob and gives the vault a new key

const read = await session.readNode(nodeIdFor(node)); // every section the user can read, checked
```

## Trust

- **Vault logs.** Before using a vault, a session replays its log (`PROTOCOL.md` §7.6): the hash
  chain, every signature against the author's committed and trusted keys, each kind's rules, the
  request shapes and checkpoints. Members, roles and key versions come from the log, not from the
  server's word; a disagreement throws `CloakVaultLogError` (`state_mismatch`).
- **Vault keys.** A key is used only after it matches the commitment in the signed log
  (`key_mismatch` otherwise), so neither the server nor an admin can hand a member another key.
- **Sections.** Every write is checked as §8.4 says: it cites a verified head, uses that head's
  key version, was signed by an editor's committed keys and, when a checkpoint follows, is in it;
  its ciphertext must hash to the digest it was signed with. A refused write comes back with
  `status: 'refused'` and the reason, never with its content.
- **Checkpoints.** What a checkpoint holds is verified against its signed root before use: a
  batch of proofs when a few sections are checked against it, or its whole leaf list, whose root
  the client recomputes, when many are. A proof or list that does not verify throws
  `CloakVaultLogError` (`state_mismatch`) rather than refusing the write it concerns. Building a
  checkpoint reads only section headers, never content, and a retry after `checkpoint_conflict`
  reads only the headers written since.
- **People.** The first time a device meets someone it pins their first key version and follows
  their key statements from there; other keys for a pinned version throw `CloakKeyChangedError`.
  Adding someone the device never met throws `CloakFingerprintRequiredError` until the user
  confirms their fingerprint. A confirmed fingerprint must lie on the person's key chain from
  version 1, which is then pinned; with a pin, it must lie on the chain from the pin. The newest
  version verified is kept, so a server that later hides newer statements raises
  `CloakKeyChangedError`.
- **Responses.** Every response is parsed with a schema before use; anything malformed, or a
  write served under another address than asked, throws `CloakApiError` (`unexpected_response`)
  or `CloakVaultLogError` (`state_mismatch`). A write's or entry's echo must match what this device
  signed.
- **Rollback and forks.** The device keeps the newest head of each vault log and the newest write
  of each section it saw (§15). An older log, or a log that does not pass through the kept head,
  throws `CloakVaultLogError` (`rollback`); an older write, or another write of a version seen,
  is refused as `rollback` or `fork`, and so is a write that the latest checkpoint after its head
  shows superseded. A section is not written on top of a write older than, or forking, the one
  seen.
- **Nodes.** A node belongs to whoever created it and lives in its home vault (`PROTOCOL.md`
  §7.7); its id derives from owner, home and key, so nobody can claim another's node. Its sections
  stand only where it lives: in its home from `createNode` on, and in vaults where the owner
  shared their names. A section written anywhere else is refused `not_shared`, however validly
  signed, and the client never writes content there: `writeSection` checks the verified log
  first and sends nothing. `readNode` reports `typeConflict` when live sections name different node
  types, and `duplicateNames` when one section name lives in more than one vault.
- **Residual risks** are in §16 of the protocol: the server can keep a device on its own branch of
  a vault's history, and content is JSON returned as `unknown`, so validate it before use.

## Key replacement

When identity keys may have leaked, `cloak.replaceKeys({ recoveryKeyCode, newPassword })` makes
new keys signed by the old recovery key, records them in every vault, and returns new codes. The
old keys lose their rights in each vault where the replacement is recorded. Admins then see
`rotationDue` and should `rotate`. A vault where recording failed is listed in `failedVaults`;
retry with `session.recordKeyReplacement(vaultId)`. `unrecognizedEntries` lists, per vault, the
log entries signed with the old keys that this device did not sign; show them for review, since
whoever held the old keys may have made them. When a rotation skipped the old keys, the
member records without the key and an admin calls `deliverEnvelopes(vaultId)`;
until then reads throw `CloakKeyUnavailableError`.

## Nodes

A node is the secrets of one record. `createNode(homeVaultId, key)` creates it, owned by the user,
in its home vault; keep the returned `NodeRef` (owner, home, key) beside the record and pass it to
writes. Create a node only when the user creates the record, after showing who will read it: the
home vault's members. Never create one because the server or host says a record lives somewhere
new; that would let a server choose who reads a new secret.

`shareNode(node, vaultId, names)` lets the members of another vault, where the user is an admin,
read the named sections; `'*'` shares every section, which also lets that vault's editors add
sections the owner never used. `unshareNode` takes names back: they stop counting for everyone,
though whoever read them keeps what they saw, so change those secrets themselves. A share ends when
its owner leaves the vault or is removed. Moving a record to another home is a new node: create it
there, write its sections, delete the old ones. `SectionInfo.node` tells which node, and so which
owner, each section belongs to, and `writerUserId` who wrote it.

## Invitations

A person an admin adds to a vault is a member by the log at once, but the vault is **pending** for
them: `listVaults({ pending: true })` lists it, and the host's access checks do not count it, until
they accept it with `acceptVault(vaultId)`, or accept everything one person adds them to with
`acceptInvitationsFrom(hostUserId)`. Show pending vaults with who added them
(`VaultSummary.addedBy`) and let the user decide. `createNode` refuses a vault the user has not
accepted. Acceptance is the server's help against being added unasked: what a member may read and
write depends on the vault's log alone. How invitations reach people before they have an account
is the app's own flow; Cloak adds only registered users.

An owner deletes a vault with `deleteVault(vaultId)`, which signs `vault_deleted`; every member's
device verifies it and forgets the vault.

## Reading vaults

`session.readVault(vaultId)` returns every live section of a vault, checked. The device keeps
what it read (§15), encrypted like the rest of its state, so a later session reads only what
changed: a write's signature is checked once, and its standing again whenever the log adds a
checkpoint. Deleted sections and sections the host removed are left out. A kept record lost or
put back from an older copy only makes the device read more. `changes(vaultId, afterChange)`
reads the raw feed instead, with `removed` listing what the host removed.

## Groups of vaults

Vaults are independent, so sharing a project means the same change in each of its vaults.
`openVaults(ids)` verifies many at once. `addMemberToVaults(ids, person, role)` adds vault by
vault and reports where it failed: stopping halfway gives less access, never more.
`removeFromVaults(ids, people)` removes from up to 100 vaults in one request the server applies to
all or none, so nobody is left half removed; a refusal names the vault in `CloakApiError.vaultId`.
Always pass the vaults the user chose: which vaults form a project is the host's unsigned record,
and a server that slipped another vault into it would otherwise get people added there.

Removing someone builds a checkpoint. The client builds it first, then asks the server to pause
writes to the vault for a moment, reads only what came since and sends it, so a member who keeps
writing cannot make the removal fail. Writers meanwhile get `busy` and their writes go through
right after.

## Deleting accounts

`session.deleteAccount()` deletes every vault where the user is the only member left, leaves every
other vault they accepted, deletes the identity and clears what this device keeps for the user. It
changes nothing and throws `CloakAccountNotEmptyError` (with `vaultIds`) while the user is the only
owner of a vault that has other members: appoint another owner first. Vaults the user never accepted
do not hold the deletion up. The deletion is signed and valid for a few minutes, so the host's
session alone cannot delete an account. The host can also erase a user who cannot do this
themselves; their memberships then stay, and `VaultMember.deleted` marks them. Nobody seals a vault
key to a deleted member again; an admin removes them with `rotate(vaultId, [], { removeDeleted: true
})`, which also covers one this device never knew by name (their `userId` is then `undefined`). The
mark is the server's word, so show it before the admin chooses this. Deleting does not revoke keys:
for leaked keys, replace them instead.

## Storage

Pins, checked host user ids, verified heads and vault snapshots, section marks and this device's own
writes and entries live in the `CloakStorage` the app passes, per user, encrypted with a key from
the user's bundle, so the store can neither read nor forge them; it can only delete them, which
makes them unseen again. After a key replacement records move to the new key as they are read.
`createIndexedDbStorage()` suits browsers; elsewhere implement the methods over a file or the
keychain. The default, `createMemoryStorage()`, forgets everything on reload; use it in tests only.
A vault snapshot keeps one small record per log entry and per membership change, so a later session
verifies only the entries after it.

With `rememberSecretKey: true`, the secret key is kept in the same store as is, and unlocking
needs only the password; `forgetSecretKey(userId)` removes it.

A device drops a vault's records only on a signed fact: after `leave`, or once the vault's log ends
in an owner's `vault_deleted`, which `deleteVault` signs and every member verifies. It keeps the
vault's verified head even then, so a history shown later must continue it. A vault the server stops
listing or answers `not_found` for is kept, because hiding a vault now and showing an older history
later would otherwise pass; `session.forgetVault(vaultId)` drops it on the user's say-so.
`cloak.forgetUser(userId)` drops everything the device keeps for a user, for signing out for good. A
server restored from an older backup looks like a rollback, and is refused as one; only forgetting
the vault or the user lets the device trust it again, as a new device would.

## Sessions

A session holds the user's private keys, the vault keys it opened and the keys of its local
records in memory. `session.close()` turns away new calls at once, waits for running ones, then
overwrites those keys with zeros; every later call throws `CloakSessionClosedError`, and
`unlock` makes a new session. Close on sign-out, and to lock an idle app. The remembered secret
key stays unless `forgetSecretKey` removes it, and the host's own sign-in is untouched.
JavaScript cannot promise that no other copy of a key or of the typed password is left in memory:
closing shortens how long keys stay, it does not defend against code already reading the page.
`deleteAccount` closes the session itself.

## Password hashing off the main thread

Argon2id with 64 MiB or more takes a second or longer and freezes the page while it runs. Pass a
`passwordHasher` to run it in a Web Worker started from this package's `kdf-worker` entry; each
call starts a fresh worker and terminates it once the key arrives:

```ts
// Vite
import KdfWorker from "@voirdev/cloak-client/kdf-worker?worker";
const cloak = createCloakClient({
  baseUrl: "/cloak/v1",
  storage: createIndexedDbStorage(),
  passwordHasher: createWorkerPasswordHasher(() => new KdfWorker()),
});

// webpack 5
const passwordHasher = createWorkerPasswordHasher(
  () =>
    new Worker(new URL("@voirdev/cloak-client/kdf-worker", import.meta.url), {
      type: "module",
    }),
);
```

The worker receives the password, so serve it from your own origin as part of your build, never
from a URL that configuration or another origin decides. When it cannot start, crashes or answers
oddly, the call fails with `CloakPasswordWorkerError` and nothing changes; the client never falls
back to the main thread on its own.

## Errors

| Error                                                          | When                                                                                                                                                  |
| -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CloakUnlockError`                                             | `wrong_credentials`: the password or the secret key is wrong (the client cannot tell which); `wrong_recovery_key`. Ask the user to type them again    |
| `CloakApiError`                                                | The server refused, with the API's stable `code`; `network_error` (status 0) when no response arrived, with the cause kept                            |
| `CloakVaultLogError`, `CloakKeyChangedError`, refused sections | The server, or someone with it, is lying. Show it; never retry silently                                                                               |
| `CloakSessionClosedError`                                      | The session was closed                                                                                                                                |
| `CloakPasswordWorkerError`                                     | The password worker failed                                                                                                                            |
| `CloakCryptoError`                                             | Malformed input, such as a mistyped code (`bad_code`), or KDF parameters outside the protocol's bounds (`invalid_kdf`). Re-exported from this package |

An aborted request stays the `AbortError` the caller expects. A server that is busy (`503 busy`)
or rate-limited by the host (`429 rate_limited`) has applied nothing; the client sends the very
same request again after its `Retry-After`, within a minute in all, and never signs
anything again for it. A request that got no response is not retried, since a write may have
been applied. Changes refused because another device moved the log or rotated the key first are
redone up to three times on fresh state (a checkpoint up to six times, each retry quick), but only
when the vault really moved: a conflict the server claims without one is thrown, so it cannot
collect several signed versions of one change.

## Browser requirements

- **A secure context** (HTTPS, or `localhost`) and IndexedDB, for `createIndexedDbStorage`.
- **Content Security Policy:** `script-src 'wasm-unsafe-eval'` for Argon2id, which runs as
  WebAssembly, and `worker-src 'self'` (or the origin that serves your build) for the password
  worker.
- **Persistent storage.** A browser may evict IndexedDB under storage pressure. The device then
  loses its pins, verified heads and marks and trusts the server as a new device would, and a
  remembered secret key is gone. Call `requestPersistentStorage()` after sign-in and tell the user
  when it answers `denied`.
- **Integrity of the code.** The page that runs Cloak sees the password. Serve it so that its
  integrity can be checked independently of the server that stores the data
  ([security model](security.md)).
