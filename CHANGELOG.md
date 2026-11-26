# Changelog

Every release of Cloak, newest first, in the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
format. Changes collect under **Unreleased**; a release branch renames that heading to its version,
and the section becomes the notes of its GitHub Release. Versions follow
[docs/development.md](docs/development.md#versioning).

## Unreleased

Protocol v1, its test vectors, the HTTP API and the public Kotlin and TypeScript APIs change in
place, so data written by earlier versions is not readable by this one.

### Fixed

- **A new write's signature was skipped** when the server gave it the `writeHash` of a write the
  device kept, so a hostile server could get an unsigned write or deletion accepted in
  `readVault`. A write's hash is now computed from its header and one served with another is
  refused `bad_write_hash`.
- **People were pinned from data that did not verify**, so a server could have its own keys pinned
  for someone and get them added without a confirmed fingerprint. Keys are pinned only after an
  entry or write of theirs verifies.
- **Ed25519 was verified with the cofactored equation** in TypeScript, accepting signatures that
  OpenSSL, the JDK and the server refuse. Every implementation checks the cofactorless equation and
  refuses non-canonical encodings with `x` = 0 and the sign bit set.
- **X25519 keys of small order were accepted**, letting one member make every rotation that kept
  them fail. Identities may only carry usable X25519 keys (§5.1).
- **Malformed fields threw** instead of being refused; logs, sections and key statements refuse
  them as `malformed`. A checkpoint leaf list naming a section twice, fork evidence reported as
  `not_a_head`, strings with lone surrogates and out-of-range key commitment versions are refused.
- **Server reads had no memory bound**: a checkpoint-proof batch holds at most a vault's worth of
  leaves, and every response that carries ciphertext holds whole sections up to `maxPageBytes`.
  `GET /nodes/{nodeId}` pages with a cursor, and `POST /nodes/batch-get` shares one budget,
  returning `nextCursor` per node and `unreadNodeIds`.
- **Erasure left data behind**: vaults with no living member, accepted inviters and write pause
  requests are removed with the identity, and erasure locks in one order with requests.
- **Limits could be overshot by racing requests**, a registration race answered 500, and host purges
  checked a stale role.
- **The client forgot vaults and signed deletions on the server's word**: `leave` and `deleteVault`
  forget a vault only on a signed fact, and `deleteAccount` signs nothing because of deletion marks.
- **A lost response could lose an account**: registration and key replacement show the codes before
  anything is sent, and completing them again after a failure is safe.
- **A hostile server could stall the client**: every paged read must make progress and stays within
  the protocol's limits; every response is checked with a schema, including byte lengths.
- **The starter's size limit was skipped** under `spring.mvc.servlet.path`; JSON reading is strict
  about types and duplicate keys; ids in paths, queries and bodies must be canonical lowercase
  UUIDs; the unexpected-failure log names no id.
- Exposed 1.5.1, which fixes an SQL injection in 1.5.0.

### Added

- **Signed acceptance** (§9): accepting a vault or an inviter is a statement the user signs, the
  server keeps and returns with the vault's view. Only vaults the user accepted vouch for the keys of
  the people in them; anyone else is added only with a confirmed fingerprint.
- `prepareRegistration` and `prepareKeyReplacement` in `@voirdev/cloak-client`, returning the codes
  and a `complete()` step; `KeyReplacementResult.unrecognizedAcceptances`.
- `CloakStorage.keys`, which local state uses to move every record to a new key.
- Limits `maxKeyVersions` and `maxPageBytes` in `GET /meta`.
- `checkSigningKey`, `checkEncryptionKey`, `vaultAcceptanceMessage`, `inviterAcceptanceMessage` and
  `addedBy` in `@voirdev/cloak-crypto`.
- CI: actions pinned by commit, Dependabot for actions, the Gradle wrapper checksum and dependency
  verification. The dev server listens on 127.0.0.1 only.

### Removed

- `CloakClient.register` and `CloakClient.replaceKeys`; use `prepareRegistration` and
  `prepareKeyReplacement`.

### Migrating

- Register with `prepareRegistration`, show its codes, then call `complete()`; replace keys the same
  way with `prepareKeyReplacement`.
- Read nodes through `readNode`, which follows the new cursors; a host calling `nodes.get` or
  `POST /nodes/batch-get` directly follows `nextCursor` and asks again for `unreadNodeIds`.
- A `CloakStorage` of the app's own implements `keys(prefix)`.
- Show `unrecognizedAcceptances` after a key replacement, and let the user accept those vaults again.
- Hosts on PostgreSQL drop the `cloak` schema of earlier versions: its data cannot be read.

## 0.0.4

### Added

- `createNodes` in `@voirdev/cloak-client` creates up to 100 nodes with one request
  (`POST /vaults/{id}/node-entries/batch-append`), bounded by the `max_nodes` limit.

## 0.0.3

### Added

- Batch read of section headers: `POST /section-headers/batch-get` and `sections.headers(caller,
sections)` in the core.

## 0.0.2

### Added

- `identityStatus()` in `@voirdev/cloak-client`: whether the signed-in user is registered, never
  registered or deleted, before asking for a password.

## 0.0.1

The first release.

### Added

- **Protocol v1** (`cloak-protocol`): identities with key statements signed by the previous
  recovery key, and host user ids mapped to Cloak user ids by UUIDv5; vaults with versioned keys
  sealed to each member and a signed, hash-chained log; RFC 6962 checkpoints whenever someone loses
  the right to write; nodes owned by their creator, placed in a home vault and shared into others
  by name with signed log entries; sections encrypted, padded and signed against the log; key
  replacement with the recovery key; signed credentials changes, account deletions and vault
  deletions. The OpenAPI contract, test vectors with their reference generator, and an independent
  JDK verifier.
- **`cloak-server-core`**: every server check of the protocol for any JVM host, with PostgreSQL
  persistence in its own schema and Flyway history; invitations that a user accepts; write pauses
  so removals succeed while others write; batch rotations and reads across vaults; change feeds;
  bounded storage per vault; host APIs that tell what a user can read by node, and purge a node's
  sections; account erasure by the host; statement and lock timeouts; events without ids.
- **`cloak-spring-boot-starter`**: serves the API under `/cloak/v1` in a Spring Boot 4 host, with
  request size limits, a host-supplied request guard, RFC 9457 problems, Micrometer metrics and a
  health indicator.
- **`@voirdev/cloak-crypto`**: the protocol in TypeScript, including every check a reader makes on
  the log and on sections.
- **`@voirdev/cloak-client`**: a client that verifies everything the server returns: pinned keys
  and confirmed fingerprints, verified vault snapshots and section marks against rollbacks and
  forks, checkpoint proofs and leaf lists, nodes and their placement, invitations, groups of
  vaults, account and vault deletion, key replacement, encrypted local state in IndexedDB or a
  store of the app's own, and password hashing in a Web Worker.
