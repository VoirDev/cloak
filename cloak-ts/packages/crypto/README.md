# @voirdev/cloak-crypto

Cloak protocol v1 ([`PROTOCOL.md`](../../../cloak-protocol/PROTOCOL.md)) for TypeScript: everything
a client computes and checks around the server. No network, no storage, no framework.

| Area         | Functions                                                                                                                                                                                                                                     |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| User ids     | `cloakUserId` (UUIDv5 of the host's user id, §5.0), `uuidV5`                                                                                                                                                                                  |
| Identity     | `createIdentity`, `replaceIdentityKeys`, `deriveMasterKey` (Argon2id where a `PasswordHasher` says, `derivePasswordKey` by default), `wipeIdentitySecrets`, `seal`/`openPrivateKeyBundle`, `seal`/`openRecoveryKeyBundle`, `encryptionKeyFor` |
| Key versions | `keysDigest`, `fingerprint`, `signKeyStatement`, `verifyKeyStatement`, `followKeyChain`                                                                                                                                                       |
| Credentials  | `credentialsMessage`, `identityDeletionMessage`, `signIdentityStatement`, `verifyIdentityStatement` (signed credentials changes and account deletions, §5.4, §5.7)                                                                            |
| Vault keys   | `generateVaultKey`, `contentKey`, `keyCommitment`, `requireCommittedKey`, `seal`/`openEnvelope` (HPKE), `wrap`/`unwrapPreviousKey`                                                                                                            |
| Vault log    | `logMessage`, `entryHash`, `signLogEntry`, `replayVaultLog` (a compact state that continues a snapshot), `logHead`, `membershipAt`, `sharedSince`                                                                                             |
| Nodes        | `nodeIdOf`, `derivesNode`, `isValidNodeKey`, `parseSectionScope`, `formatSectionScope` (§7.7, §8.1)                                                                                                                                           |
| Checkpoints  | `checkpointRoot`, `leafHash`, `auditPath`, `verifyInclusion`, `verifyAbsence`, `resolveCheckpointProof`                                                                                                                                       |
| Sections     | `encryptSection`, `decryptSection` (padded to 256-byte blocks), `sectionWriteMessage`, `toSectionHeader`, `signSectionWrite`, `verifySectionStanding` (from a header), `openSectionContent`, `checkSectionOrder`                              |
| Signatures   | `sign`, `checkSignature` (strict RFC 8032), `verify`, `isSmallOrderKey`                                                                                                                                                                       |
| Codes        | `toSecretKeyCode`, `toRecoveryKeyCode` and their parsers, `toFingerprintCode`                                                                                                                                                                 |
| Local state  | `deriveLocalRecordKey`, `sealLocalRecord`, `openLocalRecord`                                                                                                                                                                                  |

Every ciphertext is bound to where it belongs: an envelope to its vault, key version, member and
member key version; section content to its vault, node, section and key version. Opening one with
any other address fails with `decryption_failed`. A vault key is never used directly, and a client
uses one only after `requireCommittedKey` matches it to the commitment in the signed log.

The package also holds the reader's rules, because the server is not trusted:

- `replayVaultLog` verifies a vault log entry by entry (`PROTOCOL.md` §7.6): the hash chain, each
  signature against the author's committed keys, who may author which kind, the request shapes, the
  fields each kind sets, the checkpoints, and where each node lives. It returns the vault's state
  after every entry, so a client keeps it as a snapshot and continues it with new entries.
- `verifySectionStanding` judges a write from its header against that state (§8.4): the head it
  cites, the key version, the writer's committed role, the signature, that its node derives from
  its signed origin and lives in the vault and, when a checkpoint follows the head, the write's
  leaf in it. `openSectionContent` then checks the ciphertext against the signed digest and opens
  it, and `checkSectionOrder` applies the device's section marks (§15).
- `followKeyChain` follows a user's key statements from a pinned version and raises a key alarm
  when the server shows different keys for a version (§5.2, §9).

Refusals of the log and of writes are results with a `reason`, not exceptions; the reasons match
the `reason` fields of the test vectors. Malformed input and failed primitives throw
`CloakCryptoError` with a stable `code`: `decryption_failed`, `invalid_format`, `bad_padding`,
`bad_code`, `bad_signature`, `key_mismatch` or `invalid_kdf`.

Primitives come from established libraries: `@noble/ciphers` (XChaCha20-Poly1305),
`@noble/curves` (X25519, Ed25519) and `@noble/hashes` (SHA-256, HKDF), which are independently
audited, plus `@hpke/*` (RFC 9180) and `hash-wasm` (Argon2id). This package only composes them as
the protocol specifies.

## Tests

`pnpm test` checks every file of `cloak-protocol/test-vectors/v1` byte for byte and verdict for
verdict: canonical encoding, codes, key derivation, encrypted and sealed blobs through the
functions that make them, strict signatures, key statements and their chains, the scenario vault
log with each of its negative logs, checkpoint trees and proofs, and every section write with its
expected reason. The same vectors are verified independently by the JDK verifier in
`cloak-protocol/tools` and by the Kotlin server, so the implementations agree. Apps use it through
`@voirdev/cloak-client` ([docs/client.md](../../../docs/client.md)).
