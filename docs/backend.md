# Backend

Cloak's server side is a library the host backend embeds. It never decrypts anything and holds no
keys: it checks every request against the protocol (`PROTOCOL.md` §13) and stores ciphertext and
signed records.

| Artifact                    | Use it when                                                                                    |
| --------------------------- | ---------------------------------------------------------------------------------------------- |
| `cloak-spring-boot-starter` | The host is a Spring Boot 4 servlet application: it serves the API under `/cloak/v1`           |
| `cloak-server-core`         | Any other JVM host: the same operations without a web framework, for the host's own HTTP layer |
| `cloak-api-models`          | The wire models, generated from the OpenAPI spec; the starter brings them in                   |

The API is [`cloak-api.v1.yaml`](../cloak-protocol/openapi/cloak-api.v1.yaml).

## Installation

Releases are published to GitHub Packages of `VoirDev/cloak`, which needs a token that may read
packages. Every artifact of a release has the same version.

```kotlin
repositories {
    maven {
        url = uri("https://maven.pkg.github.com/VoirDev/cloak")
        credentials {
            username = providers.gradleProperty("githubPackagesUser").get()
            password = providers.gradleProperty("githubPackagesToken").get()
        }
    }
}

dependencies {
    implementation("dev.voir.cloak:cloak-spring-boot-starter:<version>")
}
```

## Spring Boot

The starter maps HTTP to the core and renders failures as RFC 9457 problems. Request and response
bodies are the generated models, read and written with Cloak's own JSON settings, so the host's
Jackson configuration does not affect them.

### What the host provides

| Bean                     | Required | Purpose                                                                              |
| ------------------------ | -------- | ------------------------------------------------------------------------------------ |
| `DataSource`             | yes      | PostgreSQL; Cloak keeps its tables in the `cloak` schema with its own Flyway history |
| `CloakPrincipalResolver` | yes      | Maps a request to the host's own user id, a string. Startup fails without it         |
| `java.time.Clock`        | no       | Time source; defaults to the system clock                                            |
| `CloakRequestGuard`      | no       | Limits requests per caller and operation, such as with the host's rate limiter       |
| `CloakEvents`            | no       | Any number of listeners of Cloak's events                                            |

```kotlin
@Bean
fun cloakPrincipalResolver(): CloakPrincipalResolver = CloakPrincipalResolver { request ->
    request.userPrincipal?.name // the host's user id, or null without a session
}
```

The resolver returns the host's id of the user exactly as its authentication gives it: any string
of 1 to 255 bytes in UTF-8, such as an OIDC `sub` or a database key. The resolver is a plain
interface, so a Java host implements it as well.

Every endpoint needs the host's session except `GET /cloak/v1/meta`. Cloak has no guests: only
registered users are members of vaults. Do not component-scan `dev.voir.cloak.spring`: the
auto-configuration creates the controllers and wires them to the resolver.

### Configuration

| Property                                      | Default   | Meaning                                                                                 |
| --------------------------------------------- | --------- | --------------------------------------------------------------------------------------- |
| `cloak.migrate-on-startup`                    | `true`    | Migrate the `cloak` schema when the context starts                                      |
| `cloak.max-request-size`                      | `16MB`    | Largest Cloak request body; startup fails below `4MB`, which the largest rotation needs |
| `cloak.database.statement-timeout`            | `5s`      | Most time per statement of an ordinary operation                                        |
| `cloak.database.checkpoint-statement-timeout` | `60s`     | The same for operations that build or read checkpoints                                  |
| `cloak.database.lock-timeout`                 | `5s`      | Most time a statement waits for a lock; running out answers `503 busy`                  |
| `cloak.max-stored-sections-per-vault`         | `1000000` | Most sections one vault stores, deleted ones included; never below the live limit       |
| `cloak.max-pending-invitations`               | `1000`    | Most vaults one user may be added to without accepting them; at least 1                 |
| `cloak.max-pending-invitations-per-inviter`   | `100`     | Most of those one person may have added the user to; at least 1                         |
| `cloak.write-pause.duration`                  | `30s`     | How long a write pause holds a vault at most                                            |
| `cloak.write-pause.interval`                  | `5m`      | Least time between two pauses of one vault by the same member who is not an admin       |

The 4 MB floor is what the largest legitimate requests need: a rotation that removes every member
of a full vault, a key replacement, and one write of the largest section. A limit below it would
make taking access away impossible, so it is refused.

### Admission

Every Cloak request passes, in order:

1. a filter that refuses a body over `cloak.max-request-size` with `413 payload_too_large` before
   any of it is parsed: at once by `Content-Length`, or as soon as a body without one passes it;
2. one interceptor that resolves the caller (`401 unauthenticated`), asks the host's
   `CloakRequestGuard` with the caller's host id and the `operationId` only, never the body
   (`429 rate_limited` with `Retry-After`), and refuses a deleted caller (`410 identity_deleted`).
   The operation checks deletion again in its transaction, which is what counts.

```kotlin
@Bean
fun cloakRequestGuard(limiter: MyRateLimiter): CloakRequestGuard = CloakRequestGuard { principal, operationId ->
    if (limiter.tryAcquire(principal, operationId)) null else Duration.ofSeconds(1)
}
```

### Metrics, health and logs

With Micrometer on the classpath, Cloak reports to the host's `MeterRegistry`, when it has one:
`cloak.requests` (timer; tags `operation`, `outcome`), `cloak.refusals` (counter; `code`),
`cloak.checkpoint.conflicts` (counter; `operation`), `cloak.log.entries` (counter; `kind`) and
`cloak.checkpoint.size` (distribution). Tags take closed sets of values, never an id.

With Spring Boot's health support on the classpath, a `cloak` health indicator is up when the
database answers and the `cloak` schema is at the version this build expects, with no details.

Refusals that suggest an attack or a broken client (`bad_signature`, `log_rejected`) are logged at
WARN on `dev.voir.cloak.server.refusals`, at most 10 per code a minute, with a count of those held
back; other refusals at DEBUG, with their detail. A line names the operation and the code only:
never a user id (a Cloak user id is a hash of the host's id, which a dictionary reverses), a host
id, a vault id, a key or a body. Unexpected failures are logged at ERROR with the request's path
and a trace id the problem carries.

## Other JVM hosts

`CloakServer` is the whole server without a web framework. The host migrates the schema once at
startup, then maps its own HTTP layer to the operations:

```kotlin
CloakMigrations.migrate(dataSource) // before serving requests
val cloak = CloakServer(dataSource, clock, CloakSettings.builder().events(listener).build())

val node = cloak.nodes.get(HostUserId.of(hostUserId).userId, NodeId(id))
```

It exposes one group per area, plus `meta()`:

| Group      | Does                                                                                                                                                                                   |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `identity` | Register, change credentials (signed), replace keys, delete (signed, expiring); users' key versions with their statements; the host's `erase`                                          |
| `vaults`   | Create, list (accepted or pending), read and delete (signed); node entries; up to 100 vaults with their next log entries at once; logs, key versions, checkpoint proofs and leaf lists |
| `members`  | Add members, accept a vault or an inviter, change roles, deliver envelopes, leave, rotate one vault or up to 100 together, record key replacements, pause section writes               |
| `sections` | Write, delete and read sections, one at a time or in batches across vaults; a vault's changes since a number, in full or as headers, with the sections the host removed                |
| `nodes`    | All sections of a node the caller can read, across vaults; the host's `purge`                                                                                                          |
| `access`   | The host's own checks: `role`, `readableNodes`, `readableSections`, `canRead`                                                                                                          |

Each call is one transaction and blocks the calling thread. A failure throws `CloakException` with
a stable `CloakErrorCode`, which the starter renders as the API's problem codes. A vault the caller
is not a member of answers `not_found`. Operations other than registration take the `UserId`
derived from the host's id (`HostUserId.of(id).userId`).

The host-facing entry points are callable from Java: `new CloakServer(dataSource)` (or with a clock
and `CloakSettings.builder()…build()`), `CloakMigrations.migrate(dataSource)`,
`CloakMigrations.isSchemaCurrent(dataSource)`, `cloak.getAccess().canRead(hostUserId, nodeId)` and
`cloak.getIdentity().erase(HostUserId.of(id))`.

`CloakSettings` holds the same settings as the starter's properties (`maxRequestBytes`,
`statementTimeout`, `checkpointStatementTimeout`, `lockTimeout`, `maxStoredSectionsPerVault`,
`maxPendingInvitations`, `maxPendingInvitationsPerInviter`, `writePause`, `writePauseInterval`),
plus `events`, a `CloakEvents` listener. The host's web layer enforces `maxRequestBytes`, which
`GET /meta` publishes. `CloakEvents` reports, after each operation: the operation with its outcome
(`ok` or the error code) and duration, checkpoint conflicts, stored log entries by kind, and stored
checkpoints by size. Events of a transaction that rolled back are dropped, a listener that throws
is logged and never fails the request, and events carry no ids.

## Users

The host names its users by its own ids (`HostUserId`). Cloak names the same user by `UserId`, the
UUIDv5 of that string (`PROTOCOL.md` §5.0), and keeps the host id beside the identity, so clients
show people by the host's ids and accept one only when it derives the user id.

## Deleting users and vaults

A user deletes their own identity with `POST /cloak/v1/identity/deletion` once they belong to no
vault they accepted that is not deleted; their client deletes or leaves those first. A vault they
never accepted does not hold the deletion up: its membership stays in the log without an envelope,
as after an erasure, until an admin removes it (`PROTOCOL.md` §5.7). The request is signed with
the user's current signing key over their user id, key version, current credentials version and
`notAfter`, which must lie between now and 10 minutes ahead (`validation_failed`, rules `expired`
and `maximum` on `/notAfter`). So the host's session alone cannot delete an account, a statement
from before a credentials change no longer counts (`credentials_version_conflict`), and a captured
one expires. A credentials change is signed the same way over the new version, the bundle's and the
salt's digests and the KDF parameters; a key replacement starts the credentials versions again at 1.

The host erases a user who cannot or will not do it, such as on an erasure request, with
`identity.erase(HostUserId.of(id))` from its own code, behind its own authorization; no endpoint
serves it. Erasure deletes the vaults where the user was the only member, removes the vault-key
envelopes sealed to them, and keeps their other memberships in the logs, where members see them
marked deleted until an admin removes them with a rotation. It is idempotent.

Either way the identity becomes a tombstone: its host user id, KDF parameters and bundles are
erased, its key versions stay (signed entries name them), every request of the user answers
`identity_deleted`, nobody can add them to a vault or seal a key to them, and their user id never
registers again: the same host id derives the same user id. **Deletion does not revoke keys**: what
the user signed stays valid, and whoever holds their keys keeps the vault keys they knew until
admins remove them and rotate. For leaked keys, replace them (§5.6) or remove the member.

An owner deletes a vault with a signed `vault_deleted` (`POST /cloak/v1/vaults/{vaultId}/deletion`),
the last entry it ever has (§12.3). Its keys, envelopes, sections, leaves, nodes, shares, pauses and
removals go; its log and members stay, so members verify who deleted it. Its view
(`deleted = true`), log and batch reads still answer; everything else answers `not_found`, and it is
listed and counted nowhere.

## Invitations

A person added to a vault is a member by the log at once, but **pending** until they accept the
vault (`PUT …/vaults/{vaultId}/acceptance`) or everything from the person who added them
(`POST …/invitations/acceptance`). `GET …/vaults?pending=true` lists pending vaults; only accepted
ones are listed without it, and only they count for the host APIs below. The creator of a vault has
accepted it. A user holds at most `max-pending-invitations` pending vaults, and at most
`max-pending-invitations-per-inviter` from one person (`409 too_many_invitations`). Acceptance is
unsigned help against being added unasked; the log alone decides rights.

## Nodes

The server stores a node's placement from its signed log entries (`PROTOCOL.md` §7.7):
`node_created` in its home, `node_shared` and `node_unshared` elsewhere, all sent to
`POST …/vaults/{vaultId}/node-entries`. Every section write signs its node's origin, and a write
with content is stored only where the node lives since the write's head; otherwise it answers
`validation_failed` with rule `not_shared` on `/nodeId`, or `bad_node` on `/nodeKey` for an id that
does not derive from the origin. A deletion carries nothing to read, so its place is not judged,
but its node must still derive from its origin. A share holds at most 1 000 distinct names; a
`node_shared` past it is refused (`log_rejected`, `invalid_entry`).

## Host APIs

Call these from the host's own code, behind its own authorization; none of them is served over
HTTP.

`access.readableNodes(hostUserId, after, limit)`, `readableSections(hostUserId, nodeId)` and
`canRead(hostUserId, nodeId)` tell the host what a user can read by node, so it can show its own
plaintext about a resource, such as a "shared with me" list, without keeping a second copy of the
rights. They follow the owners' signed node entries only, in vaults the user accepted and that are
not deleted:

- `canRead` answers a `NodeAccess`: each vault where the user reads the node, whether it is the
  home (every section) or a share (`*` or by name), and the user's role there; `null` when they
  read it nowhere. Writing a section under someone else's node id opens nothing, since such a write
  is refused unless the owner shared it.
- `readableSections` lists the live sections the user reads under the same rule, each written in
  its vault since it was shared there; `readableNodes` pages the node ids of their homes and shares.
- Partial access, such as one login of a server, shows in `NodeVaultAccess.sectionNames` and in
  `readableSections`; which host fields such a user sees is the host's decision.
- These answers tell who shares with whom. Use them for the user they are about; never show one
  user what another can read.

`access.role(hostUserId, vaultId)` gives the user's role in an accepted vault.

`nodes.purge(hostUserId, nodeId)` removes every stored section of a node, live and deleted, in the
vaults that are not deleted where that user is an admin or owner, when the host deletes the
resource the node names. Each removal takes a new change number, so members' change feeds drop it;
sections in other vaults stay, and the call returns those vaults. It is unsigned, like any loss of
availability. Authorize it as the deletion of the resource, and never reuse the node id.

## Write pauses

A request carrying a checkpoint is applied only if its checkpoint equals the stored latest writes,
so a member who keeps writing could make every attempt fail (`PROTOCOL.md` §7.5). A client may
pause section writes to up to 100 vaults, all or none, for at most `write-pause.duration`; it needs
an editor or stronger in each. Each member holds their own pause. An admin's pause replaces
anyone's; a member who is not an admin pauses a vault only where nobody else's pause holds it
(`pause_held`) and once per `write-pause.interval` (`rate_limited`), so no member can keep a vault
paused or keep an admin from pausing it. While a pause holds, every section write to the vault
answers `503 busy` with a `Retry-After` of at most 2 seconds, since the pause usually ends as soon
as its holder's request is applied. Pauses are liveness help for honest members only; nothing a
client accepts depends on them.

## Limits

`GET /meta` publishes the limits clients see: 1 MiB per section, 100 items per batch and page,
1 000 items per index page (section headers, checkpoint leaves), 1 000 members and 100 000 live
sections per vault, and `max-stored-sections-per-vault` stored ones, deletions included. A write
that would make one more live section answers `validation_failed`, rule `max_sections`, so a
checkpoint stays bounded; a new section past the stored limit answers rule `max_stored_sections`,
while writing an existing one never does. A batch rotation and a batch read take up to 100 vaults.
The Argon2id bounds are those of `PROTOCOL.md` §5.3.

Batch writes are atomic and never split, so the app keeps each batch within the request body limit
(a batch of 100 full sections is about 140 MB in base64); a batch rotation must fit it too, and the
limit guarantees only one rotation of the largest size. A request that carries a checkpoint reads
every latest write of its vault, without the ciphertext, and a proof batch loads each checkpoint it
names once and builds its tree once, so both cost at most one vault's worth of rows. Writes echo the
stored header, never the ciphertext.

Running out of statement or lock time, or losing a deadlock, rolls the request back and answers
`503 busy` with a time to retry after; Cloak never retries a transaction itself. The TypeScript
client sends the very same request again on `503` and `429`. Rate limits, connection timeouts and
other HTTP limits belong to the host.

## Data

Cloak keeps fourteen tables in the PostgreSQL schema `cloak`, migrated by Flyway with a history of
its own, so it never touches the host's tables or migrations:

| Table                                      | Holds                                                                                                                                                                                               |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `identities`, `identity_keys`              | The host user id, the current key version and credentials, or a tombstone once deleted; every key version with its statement                                                                        |
| `vaults`, `vault_keys`, `vault_members`    | Vaults with their log head, last change number, section counts, write pause and deletion time; key versions with commitments; members with committed keys, envelopes, acceptance and who added them |
| `accepted_inviters`                        | The people whose every vault a user accepts, now and later                                                                                                                                          |
| `nodes`, `node_shares`, `node_share_names` | The nodes created in each vault with owner, key and seq; the nodes shared into each vault, with `*` or by name, each from the seq of its share                                                      |
| `write_pause_requests`                     | When each member who is not an admin last paused a vault                                                                                                                                            |
| `vault_log`, `checkpoint_leaves`           | The signed log, each checkpoint with its size; each section's leaf over a span of checkpoints                                                                                                       |
| `sections`                                 | The latest write of every section, deletions included, with its signed node origin and the SHA-256 of its ciphertext                                                                                |
| `section_removals`                         | Sections the host purged, each with the change number it took, for the change feed                                                                                                                  |

**Deletions.** A deleted section stays stored as a small row without content, so its next write
chains to it and its versions keep rising, but it is never a checkpoint leaf: a checkpoint holds
live sections only (`PROTOCOL.md` §7.5).

**Checkpoint leaves.** A row is one section's leaf over the checkpoints `from_seq <= s < until_seq`
(open-ended while `until_seq` is null). A new checkpoint compares its leaves with the open spans and
closes or opens rows only where a leaf changed, so storage grows with the writes checkpointed, not
with checkpoints times sections. A checkpoint's leaves are its rows in `(node_id, section_name)`
byte order, which the `C` collation gives. In the transaction that stores a checkpoint, the server
reads its leaves back and fails the request unless they give the signed root and size, so it never
commits a checkpoint it could not serve.

**Concurrency.** Every request that changes a vault locks its `vaults` row first, several vaults in
id order, so log appends, rotations and section writes of one vault run one at a time and never
deadlock. A checkpoint therefore covers exactly the writes stored before it, and a vault's change
numbers commit in order. Optimistic checks (`log_conflict`, `stale_head`, `version_conflict`,
`credentials_version_conflict`, `identity_version_conflict`) tell a client to read and retry.

## Running in production

- **Instances.** Several instances may run at once. Migrations are serialized by Flyway's lock, and
  every request that changes a vault locks the vault's row, so its log, rotations and section
  writes stay consistent across instances. There is no background work.
- **Backups.** Never restore the `cloak` schema to an older point. Clients keep what they verified
  and treat an older state as a rollback (`PROTOCOL.md` §7.6, §15); the only way out is clearing
  each device's local state for the vault or the user, as on a new device. For durability use
  replication and point-in-time recovery that loses no committed transaction. Users who want a copy
  of their data keep it themselves.
- **Timeouts** apply per statement of Cloak's transactions only, never to the host's work.
