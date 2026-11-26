# Security model

What Cloak protects against, what your application must do for those protections to hold, and
what stays your risk. The protocol's own account is [`PROTOCOL.md`](../cloak-protocol/PROTOCOL.md)
§1 and §16; this page is the integrator's view of it.

## Who Cloak assumes is hostile

- **Your server**, including the Cloak tables, the host application and its operators. It may
  return any response, replay old ones, hide data, and act together with a former or current
  member. Host authentication only tells Cloak who is calling; Cloak does not trust it for access.
- **Former members and people whose identity keys leaked**, alone or with the server.
- **Local storage** on the device: it may lose, roll back or tamper with what the client keeps.

## What holds against them

On the history a device is shown:

- Section content is readable only by members of its vault. The server never sees plaintext,
  vault keys or private keys.
- The server cannot hand anyone a vault key of its choosing, add a member nobody authorized, or
  swap the keys of a person a device has pinned.
- Every change to members, roles and keys is signed by someone who held the needed role, and
  every member's client checks it.
- Content is accepted only from someone who was an editor when they wrote it, and stays accepted
  after they lose that right only if a signed checkpoint holds it. A removed or demoted editor
  cannot add content, not even backdated.
- A section counts only where its node's owner put the node: in its home vault, or in a vault the
  owner shared its name into. Nobody else can make a node's sections count anywhere, and a client
  writes no content where its node does not live.
- Changing a user's credentials, deleting their account and deleting a vault need the user's
  signature; the host's session alone cannot do them.
- A device refuses a vault log or a section older than one it has seen, and another version of
  something it has seen.
- After a key replacement is recorded in a vault, the old identity keys have no rights there.

The client's hostile-server suite
([`maliciousServer.e2e.ts`](../cloak-ts/packages/client/test/maliciousServer.e2e.ts)) puts a lying
server in front of real clients and shows it failing to hand out a vault key of its choosing, add
a member nobody authorized, swap a pinned person's keys, get a demoted editor's backdated write or
a write signed with replaced keys accepted, make a write stand by claiming nodes were created, or
roll back or fork a vault log or a section a device has seen. The rest is tested where it is
enforced: the log rules against the protocol's negative vectors in `@voirdev/cloak-crypto`'s
tests and the server core's `ProtocolVectorsTest`, and the section reading rules against them in
the former; where a node's
sections count in the core's `NodeEntriesTest` and `NodeAccessTest` and the client's
`client.e2e.ts`; the user's signature on credentials changes, account deletion and vault deletion
in the core's `IdentityOperationsTest`, `IdentityDeletionTest` and `VaultDeletionTest`; and the
rights of replaced keys in its `MemberOperationsTest`. Content and keys stay on the device because
the client encrypts and seals them there, in the formats the vectors fix (`PROTOCOL.md` §4, §6).

## What your application must do

| Do                                                                                                                                               | Why                                                                                                                                                                                                                                                               |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Persist `CloakStorage` (`createIndexedDbStorage()` or your own)                                                                                  | Pins, verified heads and section marks are how a device catches rollbacks, forks and key swaps. The in-memory default forgets them on reload                                                                                                                      |
| Show fingerprints and let users confirm them before adding someone new (`fingerprint`, `fingerprintOf`, `confirmFingerprint`)                    | Without a confirmed fingerprint, the server could give its own keys for a person the device never met; Cloak refuses with `CloakFingerprintRequiredError` until the user confirms                                                                                 |
| Show `CloakKeyChangedError`, `CloakVaultLogError` and refused sections to the user, never retry them silently                                    | They mean the server, or someone with it, is lying. Nothing it returned is used                                                                                                                                                                                   |
| Rotate when `rotationDue` is set, and right after removing someone                                                                               | Someone who left or replaced their keys still knows the current vault key until a rotation                                                                                                                                                                        |
| Give users the recovery kit at registration and make them keep it                                                                                | Without the recovery key, a lost password or secret key loses the data, and leaked keys cannot be replaced                                                                                                                                                        |
| Treat section content as untrusted input and validate it                                                                                         | It is whatever a member wrote; Cloak returns it as `unknown`                                                                                                                                                                                                      |
| Serve the web client with integrity you can check independently, or ship native clients                                                          | Code the server delivers can leak the password; the protocol cannot defend against the code that runs it                                                                                                                                                          |
| Keep your own authentication sound                                                                                                               | Cloak takes the user id from `CloakPrincipalResolver`; someone who can sign in as a user can act as them in Cloak once they also have the password and secret key                                                                                                 |
| Make `CloakPrincipalResolver` return an id unique across every identity provider the host accepts, never one taken from a header the client sets | An OIDC `sub` is unique only within its issuer, so two providers can give two people the same one; whoever chooses the id acts as that user                                                                                                                       |
| Normalize host user ids, such as their case, before handing them to Cloak                                                                        | Cloak compares them byte for byte (`PROTOCOL.md` §5.0): two spellings of one user are two users, and an id the host's authentication spells differently names nobody                                                                                              |
| With cookie authentication, keep a credentialed CORS policy that allows only trusted origins, and accept no `text/plain` bodies                  | A page on another origin can send a `text/plain` request with the user's cookies and without a CORS preflight. Cloak's own converter reads its bodies only as JSON; a host converter that also reads them from `text/plain` would let such a page act as the user |
| Pass the vaults the user chose to `addMemberToVaults` and `removeFromVaults`, never a list taken from the server alone                           | Which vaults form a project is the host's unsigned record; a server that added a vault to it would get people added there                                                                                                                                         |
| Let users accept vaults themselves (`listVaults({ pending: true })`, `acceptVault`, `acceptInvitationsFrom`)                                     | Until a user accepts, a vault is not listed for them and the host's access checks do not count it, so nobody is placed in vaults unasked. An accepted vault vouches for the keys of the people in it                                                              |
| Create a node only when the user creates its record, and keep its `NodeRef` beside the record                                                    | A node's home decides who reads its secrets; a server that named the home of an existing record would otherwise get a new secret written where it chose                                                                                                           |
| Never show one user what another can read (`access.readableNodes`, `readableSections`, `canRead`)                                                | Who shares what with whom is private. These answers follow the owners' signed node entries in the vaults the user accepted, and are about that user alone                                                                                                         |
| Call `requestPersistentStorage()` after sign-in and warn when it is denied                                                                       | A browser that evicts the store makes the device forget its pins and verified heads, so it no longer catches rollbacks and key swaps                                                                                                                              |
| Close sessions on sign-out and when the app locks (`session.close()`)                                                                            | Keys stay in the page's memory for as long as a session is open                                                                                                                                                                                                   |
| Never restore the `cloak` schema to an older point; keep it durable with replication and point-in-time recovery                                  | Clients refuse a server that went back in time as a rollback; the only way out is each device forgetting the vault or the user. Backups of the data are its owners' job: they read it in plaintext                                                                |
| Use account deletion for leaving, key replacement for leaks                                                                                      | Deleting an identity, by the user or by the host, does not revoke its keys: what they signed stays valid and they keep the vault keys they knew until admins remove them and rotate                                                                               |

## What stays your risk

- **Metadata.** The server sees vaults, members and roles, who added whom and which vaults they
  accepted, node ids, owners, homes, keys and types, which names of a node are shared into which
  vault, section names, which vault each section is in, sizes rounded up to 256 bytes, and access
  times. Name sections and types by category, never by content, and use node keys that say nothing,
  such as your own record ids.
- **Branches.** The server can keep a device on its own branch of a vault's history from some
  point on; there, someone who was an admin at that point can act as admin with it. The branch
  shows when the device reads a write made on the real history, which the server may never serve.
- **Who has an identity.** Any signed-in user can learn whether a host user id has a Cloak
  identity, and whether it was deleted: adding people needs their keys, which `getUserKeys` and
  `batchGetUserKeys` serve by the user id derived from the host's id. Limit how often one caller
  asks with a `CloakRequestGuard`, which sees each request's caller and `operationId`.
- **First contact.** A person added without a confirmed fingerprint gets the keys a vault the user
  accepted commits for them: as trustworthy as that vault's admins, who may have added them with
  the server's keys.
- **Hidden sections.** A section the server hides from a checkpoint's author is left out of it, and
  its current write stops being accepted until someone writes it again. Content is hidden, never
  forged.
- **Availability.** The server can delete or withhold anything.
- **Deletion marks.** Whether a person is deleted is the server's word. A client only does less
  because of it, such as not sealing vault keys to them, but an admin who trusts a false mark may
  remove a member who was not deleted.
- **What people saw.** What a person decrypted before losing access stays with them, and so does
  old ciphertext they kept.
