# How Cloak works

This page explains the model; [`PROTOCOL.md`](../cloak-protocol/PROTOCOL.md) defines every byte
and rule of it, and the section numbers below point there.

## Where it runs

Cloak is a library, not a service. It runs in two places of the host application:

- **On the backend**, the Spring Boot starter (or the core, in any JVM host) serves the Cloak API
  under `/cloak/v1` next to the host's own endpoints, and keeps its tables in a PostgreSQL schema
  of its own ([backend](backend.md)).
- **In the client**, the TypeScript client does all cryptography on the device and checks
  everything the server returns ([client](client.md)).

The host keeps its own sign-in. It tells Cloak who is calling, by its own user id, and Cloak
decides what that user may read and write. The server is treated as an active adversary: it may
lie, replay old answers, hide data, and act together with a member, and clients refuse what does
not verify ([security model](security.md)).

## Users and their keys

Cloak names a user by a UUID derived from the host's user id (§5.0), so the host never maps ids.
Each user has an identity (§5.1):

- an encryption key pair (X25519) and a signing key pair (Ed25519), kept in a **private key
  bundle** that the server stores encrypted;
- a **master key** derived from the user's password and a random **secret key** that stays on the
  user's devices (§5.3), which opens the bundle: the server holds neither, so guessing the password
  alone opens nothing;
- a **recovery key**, shown once at registration, which opens a second copy of the bundle and signs
  key replacements (§5.5).

Every key version is vouched for by a signed key statement, so a client follows a person's keys
from the version it first saw (§5.2). The first time a device meets someone it pins their keys;
adding someone new needs their **fingerprint**, compared in person or by QR code (§9).

## Vaults

A vault is the unit of access. It has members, each with a role:

| Role   | May                                                                                       |
| ------ | ----------------------------------------------------------------------------------------- |
| viewer | Read the vault's sections                                                                 |
| editor | Also write sections, and create nodes whose home is the vault                             |
| admin  | Also add and remove members, change roles, rotate the key, share own nodes into the vault |
| owner  | Also appoint and remove owners, and delete the vault                                      |

Each vault has a **versioned key**, sealed with HPKE to every member (§6). Every change to members,
roles, keys and node placement is an entry in the vault's **log**: signed by its author and
chained by hash to the one before (§7). The server checks each entry before storing it, and every
member's client replays the log and checks every rule again, so neither the server nor anyone
without the needed role can add a member, change a role or hand out a key.

Removing someone is a **rotation**: one signed request that removes the members and gives the
vault a new key (§7.4). Old content is not re-encrypted; it stays readable through the key chain.
Someone who leaves on their own, or replaces their keys, still knows the current key, so admins'
clients show that a rotation is due.

Vaults are independent: there is no nesting, no inheritance and no access without an account. A
person an admin adds is a member at once by the log, but the vault is **pending** for them until
they accept it, or everything from the person who added them (§12.4); only then is it listed for
them and counted by the host's access checks.

## Nodes and sections

A **node** holds the secrets of one record of the host application, such as a server or an
account. It is made of named **sections**, each a JSON document encrypted on the device, padded to
256-byte blocks, and signed by its writer (§8). A section's write names the newest log head its
writer saw, so a reader checks it against the log at that point: the writer must have been an
editor, and the key version must be the vault's at that head.

A node belongs to the user who created it. Its id derives from its owner, its **home vault** and a
key the application chooses, usually its own record id (§7.7, §8.1). The owner places it with
signed log entries:

- `node_created` in the home vault makes all its sections valid there;
- `node_shared` into another vault, where the owner is an admin, makes chosen section names, or
  all of them, valid there; `node_unshared` takes them back.

So a record can show its address to a contractor's vault while its password stays in the team's
vault. A section written anywhere else is refused by every reader, however validly signed, and a
client never writes content there. A share ends when its owner leaves the vault or is removed.

## Checkpoints

Whenever someone loses the right to write (a removal, a demotion, leaving, a key replacement), the
change carries a **checkpoint**: a Merkle tree (RFC 6962) over the latest write of every live
section, signed with it (§7.5). From then on, a write by someone who lost the right stands only if
the checkpoint holds it. A removed or demoted editor therefore cannot add content others accept,
not even backdated to before their removal. Readers check a write against a checkpoint with an
audit path, or rebuild the root from its leaf list when they check many.

A member who keeps writing could make every checkpoint fail, since the server takes one only if it
matches the stored writes. A client therefore pauses writes to the vault for a moment, reads what
came since, and sends; writers meanwhile get `busy` and retry.

## Key replacement

When identity keys may have leaked, the user makes new ones with the recovery key, which signs
them (§5.6). The replacement is recorded in every vault as a log entry with a checkpoint; from
then on, the old keys have no rights there. What the old keys signed earlier stays valid, and the
client lists entries it did not make for the user to review.

## What a device remembers

A device keeps, encrypted under a key from the user's bundle (§15):

- the people it pinned and the key versions it verified;
- the newest verified head of each vault's log, with a snapshot of the vault's state, so a later
  session verifies only the entries after it;
- the newest write it saw of each section.

An older log, a log that does not continue the kept head, or an older or different write of a
version it saw is refused as a **rollback** or a **fork**. The store can lose these records, which
only makes the device trust as a new device would; it cannot forge them.

## Deleting

- **An account** is deleted by the user, with a signed request valid for a few minutes, once they
  belong to no vault they accepted (§5.7). The host can also erase a user from its own code. The
  identity becomes a tombstone and its id never registers again. Deletion does not revoke keys:
  for leaked keys, replace them.
- **A vault** is deleted by an owner with a signed `vault_deleted`, the last entry of its log
  (§12.3). Its content goes; its log stays, so members verify who deleted it.
- **A node's sections** are removed by the host when it deletes the record, in the vaults the user
  administers (`nodes.purge`). This is unsigned, like any loss of availability.

Cloak has no backup of its own. Never restore its schema to an older point: clients see that as a
rollback. The data's owners keep their own copies, since they read it in plaintext.
