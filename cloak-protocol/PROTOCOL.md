# Cloak protocol, version 1

This document defines every byte that Cloak clients produce and the server checks: key
derivation, encryption, signatures, the vault log, and the human-readable codes users see. The
TypeScript packages and the Kotlin server match it exactly, and so must any other implementation. The test vectors
in [`test-vectors/v1`](test-vectors/v1) are the executable form of this document; when the two
disagree, fix whichever one is wrong.

The HTTP API that carries these bytes is [`openapi/cloak-api.v1.yaml`](openapi/cloak-api.v1.yaml).

## 1. Model and goals

Cloak stores encrypted **nodes** for registered users. A node belongs to the user who created it,
lives in a **home vault**, and is made of named **sections**. Each section lives in one **vault**:
the node's home, or another vault its owner shared the section's name into (§7.7), so the sections
of one node may live in different vaults. A vault has **members**, each with a role: viewer, editor, admin or owner. Vaults
are independent of each other: there is no nesting, no inheritance and no access without an
account.

The server is an active adversary. It may return any response, replay an old one, hide data, and
act together with a former or current member. Host authentication only tells Cloak who is
calling, and may be on the server's side too. Against that server, on the history a client is
shown:

1. **Confidentiality.** A section is readable only by members of its vault. The server cannot
   substitute a vault key, add a member nobody authorized, or swap the keys of a person a client has
   pinned.
2. **Membership integrity.** Every change to a vault's members, roles and keys is signed by someone
   who held the needed role, and every member's client checks it.
3. **Content integrity.** Every section write is signed by an editor of its vault, and is accepted
   only where its node's owner put the node, only while its writer stays an editor or if a signed
   checkpoint, made when the writer lost that right, contains it.
4. **Revocation.** A removed member gets no key created afterwards, and cannot add content that
   other members accept.
5. **Fork evidence.** Every write names the newest log head its writer saw. If the server shows
   members diverging histories of a vault, a member who reads a write made on another branch
   detects it.
6. **Key compromise recovery.** A user whose identity keys leak can replace them with the recovery
   key, which takes every right away from the old keys in every vault where the replacement is
   recorded.
7. **Interoperability.** Independent implementations produce byte-identical output for the same
   inputs and refuse the same inputs.

"On the history a client is shown": the server chooses what each device sees, and can keep a
device on its own branch of a vault's history. §16 says what that allows, together with the other
limits: code delivery, metadata, availability, what a person learned before losing access, and
trust on first contact.

## 2. Primitives (crypto suite 1)

| Purpose                          | Primitive                                                                             | Why                                                                           |
| -------------------------------- | ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Content, bundle and key wrapping | XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha)                                          | 24-byte random nonces are safe without a counter, across devices              |
| Sealing a key to a user          | HPKE, RFC 9180, mode_base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 | An IETF standard with associated data, built into the JDK, CryptoKit and Tink |
| Signatures                       | Ed25519 (RFC 8032)                                                                    | Deterministic, small, everywhere                                              |
| Password hashing                 | Argon2id (RFC 9106), parallelism 1                                                    | Memory-hard; parallelism 1 because libsodium supports only that               |
| Key derivation and commitments   | HKDF-SHA256 (RFC 5869)                                                                | Standard domain separation from one secret                                    |
| Hashing                          | SHA-256                                                                               | Digests in signatures, log hashes, checkpoints, fingerprints                  |
| Randomness                       | The platform CSPRNG                                                                   | Keys, nonces, HPKE ephemeral keys                                             |

**HKDF and HPKE labels.** `HKDF(ikm, salt, info)` is HKDF-SHA256 with `info` the raw UTF-8 bytes of
the label (no length prefix) and 32 bytes of output. HPKE `info` is likewise the raw UTF-8 bytes of
its label. An Ed25519 seed derived with HKDF is used as the RFC 8032 seed. A salt written as an id
is its 16 uuid bytes.

**Ed25519 is verified strictly** as RFC 8032 §5.1.7 says, without the ZIP-215 relaxations: `S`
must be below the group order, `R` and `A` must be canonical encodings, and the equation is the
cofactorless one. Public keys of small order are refused by the server when registered and by every
client when used. Every implementation must refuse the same signatures; the vectors include the
edge cases.

The suite number is stored per identity (`cryptoSuite`). A future suite adds new values; it never
changes these.

## 3. Canonical encoding

Associated data, signed messages, hashes, commitments and fingerprints are built with one binary
encoding, so that both clients and the server produce the same bytes. JSON is never signed.

A canonical message is a concatenation of fields, with no separators:

| Type                | Encoding                                                                                                       |
| ------------------- | -------------------------------------------------------------------------------------------------------------- |
| `label`             | Same as `str`. Always the first field, always starts with `cloak/v1/`                                          |
| `str`               | Length as u16 big-endian, then UTF-8 bytes; at most 65 535 bytes. Strings are used as given, not normalized    |
| `u8`, `u32`, `u64`  | Unsigned, big-endian, 1, 4 or 8 bytes                                                                          |
| `flag`              | One byte, 0 or 1; any other value is refused                                                                   |
| `uuid`              | 16 bytes in RFC 9562 order (the hex digits of the canonical form). An absent id is the nil UUID, 16 zero bytes |
| `key32`, `digest32` | Exactly 32 raw bytes. An absent value is 32 zero bytes                                                         |

Byte ranges such as `digest[0..20]` are half-open: bytes 0 to 19. The label gives every message
its own domain, so a signature or ciphertext made for one purpose can never be accepted for
another. Real ids and keys are random, so a nil UUID or a zero value never collides with a present
one. Ids of users, vaults and nodes are unique across the server. Where a message lists which
fields a kind sets, every other field must be absent; a verifier refuses one that is not.

Enumerations (0 means absent where a field is optional):

| Name           | Values                                                                                                                              |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Role           | `viewer` = 1, `editor` = 2, `admin` = 3, `owner` = 4                                                                                |
| Log entry kind | `vault_created` = 1, `member_added` = 2, `member_role_set` = 3, `member_removed` = 4, `member_keys_replaced` = 5, `key_rotated` = 6, `node_created` = 7, `node_shared` = 8, `node_unshared` = 9, `vault_deleted` = 10 |

## 4. Blob formats

Every binary value a client sends starts with a one-byte format version. The server checks this
byte and the length, and stores the rest without parsing it. Format 1 is the only format today.

| Blob           | Layout (format 1)                           | Size           |
| -------------- | ------------------------------------------- | -------------- |
| Encrypted blob | `0x01 ‖ nonce (24) ‖ ciphertext ‖ tag (16)` | 41 + plaintext |
| Sealed blob    | `0x01 ‖ enc (32) ‖ ciphertext ‖ tag (16)`   | 49 + plaintext |
| Signature blob | `0x01 ‖ Ed25519 signature (64)`             | 65             |

- **Encrypted blob:** XChaCha20-Poly1305 with a fresh random nonce. Associated data is given per
  use below and is never stored; the reader rebuilds it from context.
- **Sealed blob:** single-shot HPKE `Seal(pkR, info, aad, plaintext)` with a fresh ephemeral key.
  `enc` is the ephemeral X25519 public key.
- **Signature blob:** Ed25519 over a canonical message (§11). A message signed twice carries two
  signature blobs, sent as separate fields.

Concrete sizes: a vault key sealed to a user is 81 bytes; a vault key wrapped by another is 73
bytes; a private key bundle is 41 + 129 + 32·p bytes, where p is the number of earlier encryption
keys it carries (§5.4).

## 5. Identity

### 5.0 User ids

Cloak runs inside a host application, which authenticates its users; Cloak only decides what each
of them may read and write. The host names a user by its own **host user id**: any string of 1 to
255 bytes in UTF-8, exactly as the host's authentication gives it, compared byte for byte. Cloak
names the same user by a UUID derived from it:

```text
userNamespace = UUIDv5(NameSpace_URL, "urn:cloak:v1:user")
              = 715ec4b7-23ef-5724-a2a7-6bd5871ab13d
userId        = UUIDv5(userNamespace, hostUserId)          (RFC 9562 §5.5, lowercase)
```

Every signed message, the log and the API name users by `userId`. The server keeps each identity's
host user id and returns it beside the user's keys; a client accepts it only when it derives that
`userId`, so the server cannot attach one person's keys to another's name. A client shows people by
their host user id.

A deleted identity (§5.7) keeps its key statements, which the logs that name it still need, but not
its host user id: the server returns its keys marked deleted and without one. A client keeps the
host user ids it has checked (§15), so it goes on showing a person it knew by theirs, and shows one
it never knew as a deleted user. The mark is the server's word and is not signed: a client only ever
does less because of it, such as not sealing a vault key to that person, never accepts more.

### 5.1 Identity keys and versions

Each user has three key pairs:

- **Encryption:** X25519. Vault keys are sealed to its public key.
- **Signing:** Ed25519, kept as its 32-byte seed. It signs writes and log entries.
- **Recovery signing:** Ed25519, derived from the recovery key (§5.5). It signs only the next key
  version (§5.2), so a thief of the device keys alone cannot replace them.

The three public keys have an **identity key version**: 1 at registration and one more at each
replacement.

```text
fingerprintMessage = label "cloak/v1/fingerprint" ‖ uuid userId ‖ u8 cryptoSuite ‖ u32 keyVersion
                     ‖ key32 encryptionPublicKey ‖ key32 signingPublicKey
                     ‖ key32 recoverySigningPublicKey
keysDigest         = SHA-256(fingerprintMessage)
```

`keysDigest` is how the vault log commits to a person's keys (§7).

### 5.2 Key statements

Each key version is published as a **key statement**, which the server stores and serves for every
version of every user:

```text
keyStatement = label "cloak/v1/key-statement" ‖ uuid userId ‖ u32 keyVersion
               ‖ digest32 keysDigest ‖ digest32 previousKeysDigest
```

- Version 1 has no previous digest and is signed by its own signing key.
- Version n + 1 names the `keysDigest` of version n and is signed twice: by its own signing key, and
  by the **recovery signing key of version n**.

A client accepts version n + 1 of a user only through a statement chained to a version it already
trusts (§9). Only the holder of the previous recovery key can make a new version, so neither a
thief of device keys nor the server can. A version is **superseded** once a client has verified a
statement for a later one. A second, different statement for a version the client already trusts
does not replace it: the client keeps what it trusts and raises a key alarm (§9).

### 5.3 Secret key and master key

A random 16-byte **secret key** is generated at registration and never sent to the server. It
lives on each device (keychain or secure storage) and is shown once as a code (§10). A new device
needs it, typed in or scanned from a logged-in device; scanning also carries that device's pins and
verified vault heads (§15).

```text
passwordKey       = Argon2id(UTF-8(NFKC(password)), salt, memoryKib, iterations, parallelism = 1, length = 32)
secretKeyMaterial = HKDF(ikm = secretKey, salt = userId, info = "cloak/v1/secret-key")
masterKey         = passwordKey XOR secretKeyMaterial
```

A stolen database plus a guessed password is useless without the device-held secret key, and a
stolen device without the password is useless too. The server keeps `salt` (16 random bytes) and
the Argon2id parameters. A client refuses parameters below 65 536 KiB or 2 iterations, and above
1 048 576 KiB or 10 iterations, before deriving anything.

### 5.4 Private key bundle

```text
bundleKey        = HKDF(ikm = masterKey, salt = empty, info = "cloak/v1/private-key-bundle")
bundlePlaintext  = 0x01 ‖ X25519 private key (32) ‖ Ed25519 seed (32) ‖ localStateKey (32)
                   ‖ previousLocalStateKey (32, zero at version 1)
                   ‖ earlier X25519 private keys (32 each, newest first)
ad               = label "cloak/v1/private-key-bundle" ‖ uuid userId ‖ u8 cryptoSuite ‖ u32 keyVersion
privateKeyBundle = EncryptedBlob(bundleKey, ad, bundlePlaintext)
```

`localStateKey` is 32 random bytes that encrypt the device's local state (§15); a new one is made at
each key replacement, and the previous one is kept only so devices can move their state over. The
earlier encryption keys let a user open envelopes sealed to a replaced version until they are
resealed.

### 5.5 Recovery key

A random 32-byte **recovery key** is generated at registration and at each key replacement, and
shown once as a printable code (§10). Only the owner holds it.

```text
recoveryBundleKey   = HKDF(ikm = recoveryKey, salt = userId, info = "cloak/v1/recovery-key-bundle")
recoverySigningSeed = HKDF(ikm = recoveryKey, salt = userId, info = "cloak/v1/recovery-sign")
ad                  = label "cloak/v1/recovery-key-bundle" ‖ uuid userId ‖ u8 cryptoSuite ‖ u32 keyVersion
recoveryKeyBundle   = EncryptedBlob(recoveryBundleKey, ad, bundlePlaintext)
```

**Recovery** (lost password or secret key): the client opens `recoveryKeyBundle` with the recovery
key, picks a new password, generates a new secret key and salt, and replaces `privateKeyBundle`
with `PUT /identity/credentials`. Keys and the recovery key do not change.

**Changing credentials.** Every new `privateKeyBundle`, from a password change or a recovery, is
signed with the signing key of the current version, which the opened bundle holds:

```text
credentialsStatement = label "cloak/v1/credentials" ‖ uuid userId ‖ u32 keyVersion
                       ‖ u32 credentialsVersion ‖ digest32 SHA-256(privateKeyBundle)
                       ‖ digest32 SHA-256(salt) ‖ u32 memoryKib ‖ u32 iterations ‖ u8 parallelism
```

`credentialsVersion` is the version the change creates, one more than the current one, which the
request names. The server stores the bundle only if the signature verifies with the user's current
keys, so someone who holds only the host's session, and not the password, the secret key or the
recovery key, cannot replace a user's bundle and lock them out. A key replacement (§5.6) needs no
such statement: its new bundle comes with key statements the recovery key signs, and the
credentials version starts over at 1.

### 5.6 Key replacement

When identity keys may have leaked, the user, with the recovery key in hand:

1. opens the current bundle with the recovery key; generates new encryption and signing key pairs,
   a new recovery key, a new `localStateKey`, a new secret key and salt, and a new password;
2. signs the key statement of version n + 1 with the new signing key and the old recovery signing
   key, seals both bundles under version n + 1, and sends them with `PUT /identity/keys`;
3. in every vault where they are a member, signs `member_keys_replaced` (§7.2), with a checkpoint
   that leaves out writes signed with the old keys that this device did not make itself (§7.5),
   and reseals the current vault key to its new encryption key (§6.3); both go in one request,
   `POST /vaults/{id}/key-replacements`. A device that no longer holds the current key, because a
   rotation skipped the superseded keys (§7.4), records the replacement without an envelope, and
   an admin delivers one to the new keys (§6.3);
4. asks the admins of each vault to rotate (§7.4): until they do, the holder of the old keys still
   knows the current vault keys;
5. shows, per vault, the log entries signed with the old keys that this device did not sign (its
   own entries, §15), for the user to review. Another device of the user may have made them;
   otherwise the holder of the old keys did. Nothing undoes them automatically: an admin reverts
   unwanted member changes and rotates.

A client that sees a user committed at a superseded version in any vault (§7.6) shows it, and the
user's own client then repeats step 3 there.

### 5.7 Account deletion

Deleting an identity erases what unlocks it: both bundles, the KDF parameters and the host user id.
Its key statements stay, because the log entries and writes it signed name them and members still
verify those. What it signed stays valid: deletion does not revoke keys (§16).

- **By the user.** The client empties the account first: it deletes every vault where the user is
  the only member, leaves every other one (§12.4), and stops while the user is the only owner of a
  vault that has other members, until another owner is appointed. Then it signs
  `label "cloak/v1/identity-deletion" ‖ uuid userId ‖ u32 keyVersion ‖ u32 credentialsVersion ‖
  u64 notAfter` with the current signing key, where `credentialsVersion` is the current one and
  `notAfter` a Unix time in seconds at most 10 minutes ahead, and sends it to
  `POST /identity/deletion`. The server refuses a statement past `notAfter` or further ahead, so a
  captured one cannot be sent again later, and refuses with `identity_in_vaults` while the user is
  still a member of a vault that is not deleted and that they accepted; then the client clears the
  user's local state (§15). Vaults they never accepted do not hold the deletion up: their
  envelopes go, and their admins remove the deleted member as after a host's erasure. A refused
  statement stays valid until `notAfter`; the window is short so that whoever holds only the host's
  session can at most repeat what the user just asked for. A deletion is never made from the host's session alone.
- **By the host**, for a user who cannot or will not do it, such as on an erasure request or a
  closed account: the server erases the identity as above, removes the vault-key envelopes sealed to
  it, and deletes the vaults where the user was the only member. Nobody can sign for the user, so
  their memberships stay in the logs: members see them marked deleted, and an admin removes them
  with a rotation.

A deleted identity can do nothing. The server answers every request it makes with
`identity_deleted`, refuses to add it to a vault or deliver it an envelope, and refuses to register
its user id again: the same host user id derives the same `userId`, and the memberships a host
deletion left would pass to whoever registered it. No rotation seals to a deleted member (§6.3).

## 6. Vault keys

### 6.1 Versions and derived keys

Each vault has a random 32-byte **vault key** per key version. Version 1 is created with the vault;
each rotation (§7.4) creates the next. A vault key is never used directly:

```text
contentKey(v)    = HKDF(ikm = vaultKey(v), salt = vaultId, info = "cloak/v1/vault-content")
wrapKey(v)       = HKDF(ikm = vaultKey(v), salt = vaultId, info = "cloak/v1/vault-wrap")
keyCommitment(v) = HKDF(ikm = vaultKey(v), salt = uuid vaultId ‖ u32 v, info = "cloak/v1/vault-key-commit")
```

Every version's `keyCommitment` is in the signed entry that creates it: `vault_created` for version
1, `key_rotated` for the others. A client uses a vault key only after checking it against that
commitment, and refuses it otherwise with `key_mismatch`. The commitment reveals nothing about the
key and no other key matches it, so neither the server nor an admin can give a member a key of
their choosing.

### 6.2 Key chain

Each version after the first carries the previous key, so a holder of the current key can read
content written under an older one:

```text
ad                 = label "cloak/v1/vault-previous" ‖ uuid vaultId ‖ u32 version
previousWrappedKey = EncryptedBlob(wrapKey(version), ad, vaultKey(version - 1))
```

### 6.3 Envelopes

Each member receives the current vault key sealed to their committed encryption key:

```text
envelopeContext = label "cloak/v1/vault-key" ‖ uuid vaultId ‖ u32 keyVersion ‖ uuid userId
                  ‖ u32 userKeyVersion
envelope        = SealedBlob(pkR = member's X25519 key of userKeyVersion, info = "cloak/v1/vault-key",
                             aad = envelopeContext, plaintext = vaultKey)
```

A rotation reseals at once to every remaining member whose committed key version is not superseded
(§5.2) and who is not deleted (§5.7). Outside a rotation, a member may store a new envelope for
itself, and an admin for any member who is not deleted, at the current version, sealed to the member's committed keys (**envelope delivery**). It is
not signed: the member checks the key it opens against the commitment, so a wrong envelope can only
fail, never mislead.

## 7. Vault log

Every change to a vault's members, roles, committed keys and key versions is an entry in the
vault's append-only log. Members replay it to learn the vault's state, and accept nothing it does
not support.

### 7.1 Entry message

```text
logMessage = label "cloak/v1/vault-log" ‖ uuid vaultId ‖ u64 seq ‖ digest32 previousHash
             ‖ u8 kind ‖ uuid subjectUserId ‖ u8 role ‖ u32 keyVersion
             ‖ digest32 subjectKeys ‖ u32 subjectKeyVersion
             ‖ digest32 keyCommitment ‖ digest32 checkpoint ‖ flag requestEnd
             ‖ uuid authorUserId ‖ u32 authorKeyVersion
             ‖ uuid nodeId ‖ uuid homeVaultId ‖ str nodeKey ‖ str sections
entryHash  = SHA-256(logMessage)
```

- `seq` starts at 1 and increases by one. `previousHash` is the previous entry's `entryHash`, or
  absent for `seq` 1.
- `keyVersion` is the vault's key version once the entry applies.
- `subjectKeys` and `subjectKeyVersion` are the subject's `keysDigest` and key version, so a server
  that swaps a member's keys breaks the hash chain.
- `checkpoint` is set where §7.5 requires one.
- `nodeId`, `homeVaultId`, `nodeKey` and `sections` are set only by the node entries (§7.7):
  `sections` is either `*`, every section of the node, or the names it covers in ascending byte
  order, joined by `,`, without repeats. Absent, they are the nil UUID and empty strings, as §3
  says; a nil `homeVaultId` or an empty `nodeKey` is absent, never a value.
- `requestEnd` is 1 on the last entry of each request and 0 on the others. Only an entry with
  `requestEnd` 1 is a **head** that a write may cite (§8).

The author signs `logMessage` (§11).

### 7.2 Entry kinds

A **membership** is a user's role in the vault together with the key version it commits. An
author's rights come from their membership, and count only if the author signs with the committed
key version.

| Kind                   | Subject       | `role`   | `keyVersion` | Set fields                                                            | Required author role                                                                                          | Further rules                                                                                                                        |
| ---------------------- | ------------- | -------- | ------------ | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `vault_created`        | user = author | owner    | 1            | `subjectKeys`, `subjectKeyVersion`, `keyCommitment`                   | none                                                                                                          | `seq` 1 only, and only there; `authorKeyVersion` = `subjectKeyVersion`; the author becomes its owner                                 |
| `member_added`         | user          | new role | current      | `subjectKeys`, `subjectKeyVersion`                                    | admin; owner when `role` is owner                                                                             | Not yet a member; the version is not superseded                                                                                      |
| `member_role_set`      | user          | new role | current      | `subjectKeys`, `subjectKeyVersion` = committed; `checkpoint` per §7.5 | admin; owner when the old or new role is owner; none when the subject is the author and lowers their own role | A member; the role changes; the version is not superseded; the vault keeps an owner                                                  |
| `member_removed`       | user          | none     | current      | `subjectKeys`, `subjectKeyVersion` = committed; `checkpoint` per §7.5 | admin; owner when the subject is an owner; none when the subject is the author (leaving)                      | The vault keeps an owner                                                                                                             |
| `member_keys_replaced` | user = author | none     | current      | `subjectKeys`, `subjectKeyVersion` = new; `checkpoint` per §7.5       | none                                                                                                          | A member; `authorKeyVersion` = `subjectKeyVersion`; a chain of key statements leads from the committed version to the new one (§5.2) |
| `key_rotated`          | none          | none     | current + 1  | `keyCommitment`, `checkpoint`                                         | admin                                                                                                         | Last entry of a rotation request                                                                                                     |
| `node_created`         | none          | none     | current      | `nodeId`, `nodeKey`                                                   | editor, who is the node's owner                                                                               | §7.7: the node derives from the author, this vault and `nodeKey`, and is not created here yet                                        |
| `node_shared`          | none          | none     | current      | `nodeId`, `homeVaultId`, `nodeKey`, `sections`                        | admin, who is the node's owner                                                                                | §7.7: the node derives from the author, `homeVaultId` and `nodeKey`; the home vault is another vault                                 |
| `node_unshared`        | none          | none     | current      | `nodeId`, `sections`                                                  | admin, or the node's owner                                                                                    | §7.7: the node is shared here; names are taken back only when shared by name                                                         |
| `vault_deleted`        | none          | none     | current      | none                                                                  | owner                                                                                                         | §12.3: the last entry the log ever has, and not a head                                                                               |

"The vault keeps an owner" means it still has a member with role owner afterwards. "Not
superseded" is checked by the author's client and the server when the entry is made, and by a
member only as §7.6 rule 4 says: key statements carry no time, so a member cannot tell when a
version was superseded, and relies on the log's own record of the replacement where there is one.

### 7.3 Requests

Every request appends entries by one author, and its last entry has `requestEnd` 1. Rights are
checked in the vault's state right before the request. The allowed shapes are:

- `vault_created` alone;
- `member_added`, `member_role_set` or `member_keys_replaced` alone;
- `node_created`, `node_shared`, `node_unshared` or `vault_deleted` alone;
- `member_removed` alone with the author as subject (**leaving**);
- a **rotation request** (§7.4): zero or more `member_removed`, then `key_rotated`.

### 7.4 Rotation requests

Removing members, or simply renewing the vault key, is one rotation request by an admin. The
rotating client:

1. reads and verifies the log to its head;
2. generates the next key and its commitment, and wraps the current key by it (§6.2);
3. computes the checkpoint (§7.5);
4. seals the new key to every remaining member whose committed version is not superseded and who
   is not deleted (§5.7);
5. sends the request (`POST /vaults/{id}/rotations`).

Content is not re-encrypted: older sections stay readable through the key chain, and the
checkpoint fixes which of them stand. New writes use the new key.

When someone leaves on their own, or replaces their keys, they still know the current key; admins'
clients show that a rotation is due.

### 7.5 Checkpoints

A **checkpoint** fixes every section of the vault as it is at one moment, so that writes made by
someone before they lost the right to write stay valid, and nothing they write later does.

```text
leaf    = SHA-256(0x00 ‖ uuid nodeId ‖ str sectionName ‖ u64 dataVersion ‖ digest32 writeHash)
node    = SHA-256(0x01 ‖ left ‖ right)
checkpoint = RFC 6962 §2.1 Merkle tree hash over the leaves of the latest write of every live
             section of the vault, ordered by (nodeId bytes, sectionName bytes);
             SHA-256 of nothing when there are none
```

A checkpoint is required in every entry that takes away someone's right to write:

- every `key_rotated`;
- a `member_role_set` that takes the subject from editor or stronger to viewer;
- a `member_removed` that a member uses to leave, when they were an editor or stronger;
- a `member_keys_replaced` whose subject is an editor or stronger.

Its author lists the latest write of every live section, checks each one's standing (§8.4), and
includes exactly those that pass; a client making a `member_keys_replaced` checkpoint also leaves out writes signed
with its own old keys that it did not make itself (§15). The request names each latest write it
leaves out by `(nodeId, sectionName, writeHash)`, usually none. The server takes the stored latest
write of every live section, removes those named, computes the root, and refuses the request with
`checkpoint_conflict` unless it equals the signed checkpoint and every named write is still the
latest of its section; a write that slips in between makes the client build the checkpoint again.

Leaving out a write invalidates it for every reader, so only an author who may checkpoint can do it;
the writer of a valid write left out by mistake writes it again.

A deletion is never a leaf: a section whose latest write is a deletion is simply absent, which is
what makes any earlier write of it invalid from then on (§8.4). Its latest write stays stored as a
small record without content, so the next write of the section chains to it and its versions keep
rising; it does not count against the vault's section limit, which bounds live sections and so
every checkpoint.

A checkpoint has at most one leaf per section; its author and every reader refuse a leaf list or
proof that names a section twice.

The server keeps every checkpoint's leaf list, with its size, and serves it two ways:

- **proofs:** for up to 100 sections at once, each against any checkpoint of the vault, the
  section's leaf with its RFC 6962 audit path, the leaf index and the tree size, or the two
  neighbouring leaves with theirs to show it was absent;
- **leaves:** the whole leaf list in checkpoint order, in pages. A client that reads all of it
  recomputes the root, which must equal the signed checkpoint, and from then on knows what the
  checkpoint holds for every section of the vault without a proof.

A client picks either: proofs when it checks a few sections against a checkpoint, the leaf list
when it checks many. A checkpoint is immutable, so what a client verified about it stays true.

**Write pause.** The server takes a checkpoint only if it equals the stored latest writes, so a
member who keeps writing could make every attempt fail. Before it sends a request with a
checkpoint, a client may ask the server to pause section writes to the vault for a few seconds; it
builds the checkpoint beforehand, takes the pause, reads only what changed since, and sends. The server
cannot tell why a member pauses, so any editor may; an admin's pause takes the place of anyone
else's, a pause by anyone else never does, and each member below admin may pause a vault only once
in a while, so one editor cannot keep others from pausing for their own departure or key
replacement. Members who keep pausing together delay others; admins remove them. A pause ends
when the paused request is applied or its time runs out. Writes during a pause answer `busy` with the time left, and writers send them again. The pause is the server's help, not a
rule: nothing a client accepts depends on it.

### 7.6 Verifying the log

A member reads the log from `seq` 1, or from the head of a verified snapshot it keeps (§15), and
for each entry checks:

1. `seq` and `previousHash` continue the chain, and `entryHash` matches the message;
2. the signature, against the author's public keys of `authorKeyVersion`, whose `keysDigest` is the
   one committed for the author; for `vault_created` and `member_keys_replaced`, the entry's own
   `subjectKeys`, which for `member_keys_replaced` must chain to the committed version (§5.2);
3. the rules of the kind and the author's role (§7.2), the request shapes (§7.3), the fields each
   kind sets, and that each request ends with `requestEnd` 1;
4. that the author's key version is not superseded, for every entry the member had not verified
   before it learned of the newer version, unless the log records a later version for the author
   in a `member_keys_replaced`. Once the replacement is recorded, the old version has no rights
   after that entry, and its checkpoint settles which earlier writes stand; the rule only guards
   a vault where the server has not recorded a replacement the member knows of. A member does not
   apply it to its own entries: it must verify the log to record its replacement there, and lists
   what its old keys signed for review instead (§5.6 step 5).

It keeps the verified head per vault and refuses a log whose head is behind it or does not pass
through it (`rollback`).

### 7.7 Where a node lives

A node belongs to the user who created it and lives in a **home vault**; its id says both (§8.1).
Where its sections may be written and read is decided only by signed entries of the owner:

- `node_created`, by the owner as an editor or stronger of the home vault, creates the node there,
  with its `nodeKey`; the node must derive from the author, the vault and the key, and must not be
  created there already. A node's sections are valid in its home only from this entry on.
- `node_shared`, by the owner as an admin of another vault, makes the names in `sections`, or every
  name with `*`, valid in that vault. A name already shared stays shared from where it was; a name
  newly shared is shared from this entry's `seq`. The node's home must be another vault.
- `node_unshared`, by an admin of the vault or by the node's owner, takes the names back, or the
  whole node with `*`, whether it was shared by name or with `*`. A node shared with `*` cannot be
  taken back name by name.

A member keeps, per vault, the nodes created there with their owner and key, and per node shared
into it, its owner, home and key and the `seq` from which each name, and `*`, is shared. A share
ends when its owner stops being a member of the vault: a removal or a departure of the owner drops
every node they shared there, so sharing again starts anew. A write with content stands only where
its node lives (§8.4 rule 6): in its home from `node_created` on, or in a vault that shares its
name now and has since no later than the write's `logSeq`; its owner, home and key must be the ones
the creating or sharing entry recorded. Taking a name back and sharing it again therefore never
revives what was written before. A deletion carries no content, so it is valid wherever its writer
may write, as long as its node derives from its owner, home and key: a section that is no longer
shared can always be cleaned up. A share holds at most 1 000 names.

Only the owner creates and shares a node, so nobody else can make its sections valid anywhere. Every
editor of a vault where the node lives writes its sections there, by the vault's roles; with `*`,
that includes names the owner never used. An application that takes the home of an existing record
from the server, rather than from what it created, must check that `node_created` is in that
vault's log: a fresh vault would otherwise look like the home of a node never created there.

Entries are checked in this order, and refused with the first failure: the fields the kind sets
(`unexpected_field`); `keyVersion` (`bad_request_shape`); the node, home, key and `sections` being
well formed, the node existing or not as the kind requires (`invalid_entry`); then the author's
right (`not_authorized`), where a node that does not derive from the author is not theirs to create
or share. `node_unshared` checks the author's right before the names it takes back, which must be
shared by name (`invalid_entry`). A `nodeKey` is well-formed UTF-8 of 1 to 255 bytes.

A `nodeKey` should not be something another user chooses: ids are 122 bits, so someone who could
pick the key of a victim's node could search for a node of their own with the same id. An
application's own record ids qualify.

## 8. Sections

### 8.1 Section identity and content

A node is identified by who created it, its home vault and a key of the application's choice, such
as the id of the record it holds secrets for:

```text
nodeId = UUIDv5(ownerUserId, label "cloak/v1/node" ‖ uuid homeVaultId ‖ str nodeKey)
         (the canonical bytes as the name, RFC 9562 §5.5, lowercase)
```

`nodeKey` is 1 to 255 bytes of UTF-8. Every write carries the three, so every reader computes the
node's id and knows its claimed owner and home, which `node_created` and `node_shared` confirm
(§7.7). Moving a node to another home makes a new node: it is created there, its sections are
written anew under the new id, and the old ones deleted.

A section name is 1 to 64 characters: a lowercase letter, then lowercase letters, digits and `_`.

A section is identified by its vault, node id and name: `(vaultId, nodeId, sectionName)`. The same
node id and name in two vaults are two sections; a client that meets both live shows a conflict, as
it does for one node with two different types.

```text
plaintext  = pad(content)
ad         = label "cloak/v1/section-content" ‖ uuid vaultId ‖ uuid nodeId ‖ str sectionName
             ‖ u32 vaultKeyVersion
ciphertext = EncryptedBlob(contentKey(vaultKeyVersion), ad, plaintext)
```

`content` is whatever bytes the application stores (the client libraries default to UTF-8 JSON).

**Padding:** ISO/IEC 7816-4 to a multiple of 256 bytes: append `0x80`, then `0x00` until the length
is a multiple of 256. Unpadding strips trailing zeros and one `0x80`, and refuses anything else,
including more than one block (256 bytes) of padding.

### 8.2 Section write

Every change to a section, including its creation and its deletion, is a write that signs the
section's whole state:

```text
sectionWrite = label "cloak/v1/section-write" ‖ uuid vaultId ‖ uuid nodeId ‖ str nodeType
               ‖ uuid homeVaultId ‖ uuid ownerUserId ‖ str nodeKey
               ‖ str sectionName ‖ u32 vaultKeyVersion ‖ u64 dataVersion ‖ flag deleted
               ‖ u64 logSeq ‖ digest32 logHeadHash ‖ digest32 previousWriteHash
               ‖ uuid writerUserId ‖ u32 writerKeyVersion ‖ digest32 SHA-256(ciphertext)
writeHash    = SHA-256(sectionWrite)
```

- `vaultKeyVersion` is the vault's key version at `logSeq`; the content is encrypted with it.
- `dataVersion` is 1 for the first write and one more for each later one, deletions included.
- `deleted` is 1 for a deletion, which has no ciphertext (the digest field is absent).
- `logSeq` and `logHeadHash` are the head (§7.1) of the vault log the writer verified right before
  writing.
- `previousWriteHash` is the `writeHash` of the section's previous write, absent for the first.

A write's **header** is every field above with `ciphertextHash = SHA-256(ciphertext)` in place of
the ciphertext. The message signs only that digest, so a header is enough to check the signature,
compute `writeHash` and judge the write's standing (§8.4); only reading the content needs the
ciphertext, whose digest must then match.

### 8.3 Writing

The writer must be an editor or stronger of the vault. Right before writing, it reads and verifies
the vault log to the server's head, and reads the section's latest write. Its write cites that head,
uses its key version, and chains to the latest write, even one it does not accept: a refused write
never blocks the section, and the new write is judged on its own. Before it encrypts anything, the
writer checks rule 6 against the log it just verified: the vault is the node's home and the node
was created there, or the vault shares the section's name now (§7.7); otherwise it writes nothing,
whatever the application or the server says. A new node is created only on the application's
explicit request, which shows the user who will read it: the members of its home vault.

Moving a section to another vault where its node lives is one batch: a deletion in the old vault
and a first write in the new one.

### 8.4 Reading

A write **stands** when its header passes these rules:

1. **Head.** `logSeq` and `logHeadHash` are a head in the verified log; if the reader's log is
   shorter it reads and verifies the rest first; if the log has another hash at `logSeq` it
   refuses with `fork`.
2. **Key version.** `vaultKeyVersion` is the vault's key version at `logSeq`, and the write has
   a `ciphertextHash` unless it is a deletion.
3. **Writer.** The signature verifies with the writer's keys of `writerKeyVersion`, which were
   committed for the writer as an editor or stronger at `logSeq`, and are not superseded (§7.6
   rule 4 applies to writes too).
4. **Checkpoints.** If any entry carrying a checkpoint follows `logSeq` in the verified log, the
   write is in the first such checkpoint, as the leaf of its section with its `dataVersion` and
   `writeHash`. Every loss of the right to write carries a checkpoint, so a writer who lost it after
   `logSeq` is covered only for what they wrote before. The latest such checkpoint must hold this
   very write as its section's leaf: a leaf with a higher `dataVersion` means the server serves a
   superseded write (`rollback`), one with the same `dataVersion` and another `writeHash` is a
   `fork`, and no leaf refuses the write. A deletion is never a leaf, so for a deletion both
   checkpoints must hold no leaf for its section: a leaf with a higher `dataVersion` is a
   `rollback`, any other leaf shows the deletion was not in effect when that checkpoint was taken,
   and refuses it.
5. **Order.** Its `dataVersion` is not behind the one this device has seen; a write with the same
   `dataVersion` and another `writeHash` is a `fork`; a write right after the one seen chains to it
   (§15).
6. **Place.** `nodeKey` is 1 to 255 bytes and `nodeId` derives from `ownerUserId`, `homeVaultId`
   and `nodeKey` (§8.1), or the write is refused with `bad_node`. A write with content then stands
   only where its node lives (§7.7): the vault is its home and `node_created` for it came no later
   than `logSeq`, or the vault shares the section's name now, since no later than `logSeq`; in both
   cases with the owner, home and key the entry recorded. Otherwise it is refused with
   `not_shared`, however validly signed. A deletion is judged only for `bad_node`: it carries
   nothing to read, so it may go wherever its writer may write, but it still names its node
   truthfully.

A reader first refuses every write of a vault whose log ends in `vault_deleted` (`vault_deleted`),
then applies the rules in the order 1, 2, 3, 6, 4, and refuses with the first that fails; rule 5 follows, against the
device's marks, and only a write that stands raises a mark.

A member **reads** a write that stands when, in addition, its ciphertext hashes to
`ciphertextHash`, the vault key of `vaultKeyVersion` matches the log's commitment (§6.1), and the
content decrypts. A deletion shows the section as deleted.

A checkpoint's author judges standing only: a write that stands but whose content does not open is
still a valid write by an editor, and readers refuse its content on their own. Standing needs no
ciphertext, so an author reads the vault's headers (§12.5) and checks them against the checkpoints
with the leaf lists or proofs of §7.5.

## 9. Pins and first contact

A member's client pins each person's keys at the earliest version it meets, the first time it
verifies an entry about or by them or reads their writes, and follows their key statements from
there (§5.2). A different key for a pinned version, or a second statement for a version it trusts,
is a **key alarm**: the client keeps what it trusts and shows both fingerprints.

A client adds a person it has not pinned only with a fingerprint the user confirmed out of band, by
scanning or comparing it. Without that, the first time a person is added the server could hand over
its own keys under their name; the vault log would then commit those keys for everyone. Before
adding or changing a member, the client fetches their latest key statements and uses their newest
version.

A confirmed fingerprint must be on the person's verified key chain from version 1; the client then
pins version 1 and follows the chain, so confirming a later version does not skip the statements
before it. When a pin already exists, the confirmed keys must be on the chain from it, or it is a
key alarm. The client keeps the newest version it verified for each person; a server that later
serves fewer statements, so that this version is no longer on the chain, raises a key alarm.

## 10. Human-readable codes

All codes use **Crockford base32**: alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, bytes read as one
big-endian bit string, the last group padded with zero bits. Decoders accept lowercase, map `O` to
`0` and `I`/`L` to `1`, ignore hyphens and spaces, require the prefix where the code has one, and
refuse non-zero padding bits.

| Code         | Bytes encoded                                   | Shape                   |
| ------------ | ----------------------------------------------- | ----------------------- |
| Secret key   | `secretKey (16) ‖ SHA-256(secretKey)[0..1]`     | `CS1-` + 7 groups of 4  |
| Recovery key | `recoveryKey (32) ‖ SHA-256(recoveryKey)[0..3]` | `CR1-` + 14 groups of 4 |
| Fingerprint  | `keysDigest[0..20]` of a key version (§5.1)     | 8 groups of 4           |

The checksum bytes catch typos before any network call.

## 11. Signatures

All signatures are Ed25519, verified strictly (§2), over a canonical message, sent as a signature
blob.

| Message               | Signer                                                                                            |
| --------------------- | ------------------------------------------------------------------------------------------------- |
| `keyStatement` (§5.2) | The version's signing key; for version 2 and up, also the previous version's recovery signing key |
| `logMessage` (§7.1)   | The author, as §7.2 says                                                                          |
| `sectionWrite` (§8.2) | The writer, as §8.3 and §8.4 say                                                                  |

The server verifies every signature before storing anything and refuses `bad_signature`. Clients
verify again on read, because the server is not trusted.

## 12. Flows

### 12.1 Register

1. Generate the encryption and signing key pairs, a 16-byte secret key, a 16-byte salt, a 32-byte
   recovery key and a 32-byte `localStateKey`.
2. Derive `masterKey`, build both bundles and the version-1 key statement.
3. `POST /identity`. Show the secret key and recovery key codes once.

### 12.2 Unlock

1. `GET /identity`. Check the KDF parameters, derive `masterKey` with the device's secret key.
2. Open `privateKeyBundle`. A wrong password or secret key fails the AEAD tag, nothing more. If the
   bundle carries a `previousLocalStateKey` the device's state still uses, the client re-encrypts
   that state under the new key.

### 12.3 Vaults

- **Create:** generate a vault id, key and commitment; seal the key to oneself; sign
  `vault_created`; `POST /vaults`.
- **Delete:** an owner signs `vault_deleted` and sends it to `POST /vaults/{id}/deletion`. The
  server removes the vault's keys, envelopes, sections and checkpoint leaves, and keeps its log and
  member list, so every member who verifies the log sees who deleted it and forgets it (§15); only
  those members may read it. Nothing can follow `vault_deleted` in the log, and it is not a head
  a write may cite. A deleted vault's members are no longer members anywhere: they do not hold up
  the deletion of their accounts, and the host does not count them. Someone with the host's session
  alone cannot delete a vault. The host itself still can, as when it erases a user (§5.7); that is unsigned, like any loss of
  availability (§16).

### 12.4 Members

- **Add:** check the person's pin or a confirmed fingerprint, take their newest key version (§9),
  seal the current key to it, sign `member_added`, `POST /vaults/{id}/members`.
- **Change a role:** sign `member_role_set`, with a checkpoint when it takes away the right to write.
- **Remove:** a rotation request (§7.4).
- **Leave:** sign `member_removed` with oneself as subject, with a checkpoint if one was an editor or
  stronger.
- **Accept:** a person added to a vault is a member at once, by the log, but the server lists the
  vault for them, and counts them for the host's access checks, only once they accept it, or accept
  everything from the person who added them. A person can hold only so many vaults they have not
  accepted, in all and from any one inviter, so nobody can fill another's list. This is the
  server's help against being added to vaults unasked, not a rule a client checks: the log alone
  decides what a member may read and write.
- **Share a node into another vault:** the node's owner, as an admin of that vault, signs
  `node_shared` with the names to share (§7.7); taking them back is `node_unshared`. A name taken
  back is no longer read there, but whoever read it keeps what they saw.
- **Many vaults at once.** Vaults are independent, so sharing a group of them, such as everything
  of one project, means the same change in each. Adding may go vault by vault: a change that stops
  halfway gives less access, not more. Removing goes as one request of up to 100 rotations, one per
  vault, which the server applies together or not at all, so nobody is left half removed. The vaults
  and people of such a change come from what the user chose: which vaults form a group is the host's
  unsigned record, and a server that added a vault to it would otherwise get people added there.
- **Reading many vaults.** One request returns the view and the next log entries of up to 100
  vaults; the server answers for every vault asked, with its data or `not_found`, and a vault
  missing from the answer fails the read rather than counting as one the user left.

### 12.5 Nodes and sections

Create a node with a signed `node_created` in its home vault (`POST /vaults/{id}/node-entries`,
§7.7), which also carries `node_shared` and `node_unshared`; then write its sections, each first
write with `dataVersion` 1. Writes, deletions and moves follow §8.3, one at a time
(`PUT /vaults/{id}/sections/{nodeId}/{name}`) or up to 100 at once in any of one's vaults
(`POST /sections/batch-write`), applied together or not at all. A move is a deletion in one vault
and a first write in another where the node lives, in one batch. A client keeps
a vault's replica current with `GET /vaults/{id}/sections?afterChange=…`, which returns every
section whose latest write is newer, deletions included. `GET /vaults/{id}/section-headers` lists
the same writes as headers (§8.2), in larger pages, for checking standing without the content.
Write responses echo the stored header.

### 12.6 Replace identity keys

As §5.6 says.

### 12.7 Delete an account

As §5.7 says.

## 13. Server checks

For every request the server, which holds no keys, checks:

- the first byte of every blob is an accepted format version, and each blob has its exact size:
  signature 65; envelope 81; previous-key wrap 73; commitments, checkpoints and digests 32;
- every signature, by rebuilding the canonical message from the request fields, the stored log
  head and the SHA-256 of each blob, against the stored public keys of the named version;
- every key statement chains to the user's current version and is signed as §5.2 says;
- every log entry exactly as a member checks it (§7.6), every request shape (§7.3), and that the
  request matches what it does: an envelope for every member a rotation keeps whose version is not
  superseded and who is not deleted, none for any other, and a checkpoint equal to the root over the stored latest writes
  of live sections minus the ones the request leaves out (§7.5);
- every section write as §8.4 says, plus: it cites the current log head, uses the current key
  version, chains to the stored latest write of the section, and its `dataVersion` is one more;
- section ciphertext is no larger than 1 MiB and holds whole padded blocks: 41 + 256·n bytes,
  n ≥ 1; a deletion has none;
- a write that makes a section live keeps the vault within its limit of live sections, so every
  checkpoint stays bounded; deletions stay stored without content and count only against a much
  larger limit of stored sections, which bounds the database;
- while a write pause (§7.5) holds a vault, its section writes answer `busy`;
- every write with content stands by rule 6 (§8.4): its node derives from its owner, home vault
  and key, and lives in the vault since no later than the write's head (§7.7); node entries as
  §7.2 says;
- nothing is appended after `vault_deleted`;
- a new private key bundle carries a `credentialsStatement` signed with the user's current keys,
  and an identity deletion is signed the same way (§5.4, §5.7);
- `credentialsVersion` and the identity key version as the API describes;
- the caller is not a deleted identity, and neither is a member being added or sent an envelope
  (§5.7);
- the request fits the server's request size limit, which is never below what the largest
  rotation and the largest checkpoint need, so taking access away always fits in one request.

The server applies each request in one transaction. Every request that changes a vault, log
appends and section writes alike, locks the vault exclusively, several vaults in id order: a
checkpoint covers exactly the writes stored before it, and a vault's change numbers commit in
order, so a client reading `afterChange` never skips a write.

## 14. Label registry

| Label                          | Used for                                                   |
| ------------------------------ | ---------------------------------------------------------- |
| `cloak/v1/secret-key`          | HKDF info: secret key material                             |
| `cloak/v1/private-key-bundle`  | HKDF info and AD: private key bundle                       |
| `cloak/v1/recovery-key-bundle` | HKDF info and AD: recovery bundle                          |
| `cloak/v1/recovery-sign`       | HKDF info: recovery signing seed                           |
| `cloak/v1/fingerprint`         | Fingerprint and keys digest                                |
| `cloak/v1/key-statement`       | Signature: key statement                                   |
| `cloak/v1/vault-content`       | HKDF info: content key                                     |
| `cloak/v1/vault-wrap`          | HKDF info: key wrapping key                                |
| `cloak/v1/vault-key-commit`    | HKDF info: key commitment                                  |
| `cloak/v1/vault-key`           | HPKE info and AD label: envelopes                          |
| `cloak/v1/vault-previous`      | AD: a vault key's previous version                         |
| `cloak/v1/vault-log`           | Signature and hash: vault log entry                        |
| `cloak/v1/section-content`     | AD: section ciphertext                                     |
| `cloak/v1/section-write`       | Signature and hash: section write                          |
| `cloak/v1/node`                | Name of a node's UUIDv5 id                                 |
| `cloak/v1/credentials`         | Signature: a new private key bundle                        |
| `cloak/v1/identity-deletion`   | Signature: deleting one's identity                         |
| `cloak/v1/local-state`         | HKDF info and AD: a client's local state (§15); never sent |

A label is never reused for another purpose. A new purpose gets a new label.

## 15. Client state

A member's client keeps, per user and device:

- **pins and key chains:** each person's pinned and newest verified key versions (§9);
- **vault snapshots:** for each vault, the verified state, so later sessions verify only new
  entries: per entry its `seq`, `entryHash`, whether it is a head, the key version after it and its
  author with their key version; each member's role and committed keys as they changed, by `seq`;
  the checkpoints; the key commitments; the newest key version each member's
  `member_keys_replaced` entries record; who left or replaced keys since the last rotation; the
  nodes created and shared there (§7.7); and whether the vault was deleted.
  It grows with the log, not with the log times the members. Entries up to a snapshot count as
  verified before for §7.6 rule 4;
- **section marks:** for each section, the highest `dataVersion` seen and the `writeHash` of that
  write. A write behind it, another write with the same `dataVersion`, or the next write not
  chaining to it is refused;
- **own writes:** the `writeHash` of the latest write this device made to each section, for the
  checkpoint of a key replacement (§5.6);
- **own entries:** the `entryHash` of every log entry this device signed that the server accepted,
  to tell them from entries made with leaked keys (§5.6 step 5);
- **verified sections:** each live section's latest write as read, with its verdict, in buckets
  that each say through which change number they are complete, so a later session reads only
  what changed since the least complete one; a bucket lost or put back from an older copy only
  makes it read more. A write's signature never changes, so it is checked once; the standing of a
  write that stood is judged again whenever the log adds a checkpoint or a node entry after it was
  judged. A
  section the host removed leaves the cache, which is no more than the server hiding it, and never
  lowers the section's mark;
- **host user ids:** each person's host user id the client checked derives their `userId` (§5.0);
- **forgotten vaults:** the verified head of each vault whose records the client dropped.

The records of a vault are dropped only on a signed fact: its verified log ends in
`vault_deleted`, the user left it, or the log removes them. The client then keeps the vault's verified head as a forgotten vault,
and a log it is shown later must pass through that head (§7.6). A vault the server stops listing,
or answers `not_found` for, is not forgotten on its own: the server could hide it now and show an
older history later. An app may still forget one on the user's say-so, which leaves the device as
new for that vault. Deleting the account (§5.7), or signing the user out of the device for good,
drops all of the user's records.

A server restored to an older state is a rollback to its clients, and they refuse it (§7.6); the
protocol does not tell an honest restore from an attack. Clearing a device's records for the vault,
or for the user, is the only way to trust such a server again, exactly as a new device would.

Each record is encrypted with `HKDF(localStateKey, salt = userId, info = "cloak/v1/local-state")`,
with associated data `label "cloak/v1/local-state" ‖ str recordName`, so local storage can neither
read, change nor move records. It can delete one, which resets it to unseen, or put back an older
copy, which lowers what the device remembers to that copy; either way the device is no worse off
than a new one. A client raises what it keeps only after the signatures behind it verify.

## 16. Security notes

- **Visible to the server:** vaults, members and their roles, who added whom and which vaults they
  accepted, node ids, owners, homes, keys and types, which names of a node are shared into which
  vault, section names, which vault each section is in, sizes rounded up to 256 bytes, and access
  times.
- **Code delivery.** A web client served by the same host can be replaced with code that leaks the
  password. The protocol cannot defend against the code that runs it; native clients, or web builds
  whose integrity is checked independently, can.
- **Branches.** The server chooses what each device sees. It can stop showing a device the newer
  entries of a vault and give it a branch of its own from that point, on any device and at any
  time. On such a branch, a person who had admin rights at the branch point can, together with the
  server, act as admin: rotate to a key they choose, add members, write content the device accepts.
  The device writes under that key. The branch shows only when the device reads a write made on the
  real history, which the server may never serve it. Nothing in the protocol closes this.
- **First contact.** A person added without a pin or a confirmed fingerprint may get the server's
  keys instead of their own (§9).
- **Checkpoints.** A section the server hides from a checkpoint's author is left out of it. Its
  current write then stops being accepted, whoever wrote it, until someone writes it again. Content
  is hidden, never forged.
- **Leaving and key replacement.** Whoever leaves, and the holder of replaced keys, still knows the
  current vault key until an admin rotates. The recovery key is the root of a replacement: whoever
  holds it can replace the user's keys. A vault where the server does not record the replacement
  keeps the old keys' rights until the user learns of it. What the holder of the old keys signed
  before the replacement stays valid; the client lists it for review (§5.6) but cannot tell it from
  what the user's other devices signed.
- **What is not signed.** Every change that gives access, moves a secret or destroys data is
  signed by a member's keys. The rest is the server's word and can only do less: hiding a section
  or a vault, the deletion mark of a user, envelope delivery (which fails if wrong), write pauses,
  accepting vaults, and what the host deletes itself, such as erasing a user or purging a node.
- **Deletion.** Deleting an identity does not revoke its keys: what it signed stays valid, and
  whoever holds them keeps knowing the vault keys they knew until admins remove the person and
  rotate. A deletion for a leak is a key replacement (§5.6) or a removal, not a deletion.
- **Lost credentials.** Without the recovery key, losing the password or the secret key loses the
  data. This is deliberate.
- **Knowledge.** What a person decrypted before losing access stays with them, and so does any old
  ciphertext they kept, which their old keys still open.

## 17. Versioning

- A new blob layout gets a new format byte. Readers keep reading old formats; the server can mark a
  format read-only through `GET /meta` and reject it on write.
- New algorithms get a new crypto suite number on the identity.
- A change to canonical messages or labels is a new protocol version with `cloak/v2/` labels.

## 18. Test vectors and tools

[`test-vectors/v1`](test-vectors/v1) holds one JSON file per area: `encoding`, `text`, `kdf`,
`aead`, `hpke`, `signatures`, `identity`, `vault-log`, `checkpoints` and `sections`. Every file has
positive cases and negative ones, which every implementation must refuse for the stated reason:
wrong associated data, bad padding, bad flags, non-canonical and small-order signatures, broken key
statement chains, malformed codes, and each rule of the vault log, checkpoints and section reading.
Inputs that are random in production (nonces, HPKE ephemeral keys) are fixed in the vectors;
implementations whose HPKE library cannot take a fixed ephemeral key must at least open every
sealed blob.

- [`tools/generate-vectors.mjs`](tools/generate-vectors.mjs) is the reference implementation that
  writes the vectors. It needs Node.js 24 or later and no packages, and it checks its primitives
  against published known-answer tests (RFC 5869, 7748, 8032, 9106 and draft-irtf-cfrg-xchacha)
  before writing anything, and checks its Merkle tree code against a second, independent
  computation.
- [`tools/VerifyVectors.java`](tools/VerifyVectors.java) is an independent check written against
  this document. It uses the JDK's own HPKE, Ed25519, X25519, ChaCha20-Poly1305 and HKDF, and needs
  JDK 27 or later. Argon2id is not in the JDK, so it takes `passwordKey` from the vectors.

```bash
node tools/generate-vectors.mjs
java tools/VerifyVectors.java test-vectors/v1
```
