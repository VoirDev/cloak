# Changelog

Every release of Cloak, newest first. A release's section is written on its release branch and
becomes the notes of its GitHub Release. Versions follow
[docs/development.md](docs/development.md#versioning).

## 0.1.0

The first release, a preview: the protocol and its implementations are complete and tested, but
have not had an external security review yet, and the API may still change before 1.0.

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
