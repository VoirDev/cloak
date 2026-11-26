# Development

## Layout

| Path                                                        | What it is                                                                                                   |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| [`cloak-protocol`](../cloak-protocol)                       | The contract: `PROTOCOL.md`, the OpenAPI spec, test vectors, their generator and an independent JDK verifier |
| [`cloak-api-models`](../cloak-api-models)                   | Kotlin API models, generated from the OpenAPI spec by fabrikt at build time                                  |
| [`cloak-server-core`](../cloak-server-core)                 | The server without a web framework: the protocol's server checks, persistence, migrations                    |
| [`cloak-spring-boot-starter`](../cloak-spring-boot-starter) | Serves the API under `/cloak/v1` in a Spring Boot 4 app                                                      |
| [`cloak-dev-server`](../cloak-dev-server)                   | A throwaway Spring Boot host for the client's end-to-end tests; never deploy it                              |
| [`cloak-ts/packages/crypto`](../cloak-ts/packages/crypto)   | `@voirdev/cloak-crypto`: the protocol in TypeScript, including the reader's checks; no network               |
| [`cloak-ts/packages/client`](../cloak-ts/packages/client)   | `@voirdev/cloak-client`: the TypeScript client apps use                                                      |
| [`build-logic`](../build-logic)                             | Gradle convention plugins shared by the Kotlin modules                                                       |
| [`ci`](../ci)                                               | `ci/verify` and the release scripts the workflows call                                                       |

Dependencies run one way: the protocol feeds the API models, the core, the starter and the
TypeScript packages; nothing depends on a host.

`cloak-server-core` groups its code by area, not by layer:

| Package                                            | Holds                                                                                                                 |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `identity`, `vault`, `section`                     | Operations; `domain/` public models and commands; `persistence/` internal Exposed tables and repositories             |
| `vault`                                            | Also `LogAppender`, which verifies, checkpoints and stores the entries of one request                                 |
| `protocol`                                         | Canonical messages, strict Ed25519, X25519 key checks, the log rules, where nodes live, Merkle trees, blob size rules |
| `access`, `error`, `paging`, `persistence`, `meta` | Access checks and validation, error codes, keyset, leaf and node cursors, transactions and migrations, limits         |
| `observability`                                    | `CloakEvents`, what the server reports for the host's metrics, and the rate-limited log of refusals                   |

The server checks every log entry with the same rules each member's client applies
(`protocol/LogRules`), so it stores nothing a member would refuse.

## Requirements

- A JDK for Gradle (the Kotlin modules compile on a Java 21 toolchain).
- Docker, for PostgreSQL in Testcontainers.
- Node.js 24 or later, as `cloak-ts/.nvmrc` and the workspace's `engines` field say; the vector
  generator needs it too.
- pnpm, the version `packageManager` in `cloak-ts/package.json` names, and jq, for `ci/verify`.
- JDK 27 or later for the independent vector verifier only.

## Checks

`ci/verify` runs everything a pull request must pass, in this order: the protocol's vectors match
their generator, the Kotlin build with every test, the TypeScript checks (format, lint, types,
tests, build), the client's end-to-end suites against the Kotlin server, and that every package
still publishes.

```bash
./ci/verify
```

Parts of it on their own:

```bash
./gradlew build
```

```bash
cd cloak-ts && pnpm install && pnpm check
```

```bash
cd cloak-ts && pnpm test:e2e
```

## Supply chain

- **Actions.** Every `uses:` in `.github/workflows` names a full commit SHA, with its release in a
  `# vX.Y.Z` comment. Dependabot (`.github/dependabot.yml`) proposes new releases of them weekly.
- **Gradle Wrapper.** `gradle/wrapper/gradle-wrapper.properties` holds the SHA-256 of the Gradle
  distribution, so the wrapper refuses a download that does not match. When the Gradle version
  changes, take the new value from `https://services.gradle.org/distributions/gradle-<version>-bin.zip.sha256`.
- **Dependencies.** `gradle/verification-metadata.xml` holds the SHA-256 of every plugin, library
  and POM the build resolves, and Gradle fails a build that resolves anything not listed or not
  matching. The release consumer (`ci/release/consumer`) is a separate build and is not covered.

When a dependency or plugin is added or changes version, regenerate the file with every task
`ci/verify` runs in Gradle, so every configuration resolves, then review the diff, which names each
artifact the build now trusts. Run it with an empty Gradle home, as CI starts: with a filled cache
Gradle does not read the parent POMs and BOMs again, so it leaves them out and CI fails on them.

```bash
GRADLE_USER_HOME="$(mktemp -d)" ./gradlew --write-verification-metadata sha256 \
  --no-configuration-cache \
  build publishAllPublicationsToReleaseRepository -PreleaseVersion="$(cat VERSION)"
```

Regeneration adds entries and keeps old ones. To drop the entries of dependencies the build no
longer uses, delete the file and run the command again. `./gradlew build` then passes with
verification on.

## Protocol vectors

`cloak-protocol/test-vectors/v1` is the executable form of `PROTOCOL.md`. The generator writes it
and checks its own primitives against published known-answer tests; the JDK verifier checks it
again, independently, with the JDK's own primitives:

```bash
node cloak-protocol/tools/generate-vectors.mjs
```

```bash
cd cloak-protocol && java tools/VerifyVectors.java test-vectors/v1
```

A change to the protocol changes `PROTOCOL.md`, the generator, the vectors, and every
implementation in the same pull request; `ci/verify` fails while the vectors differ from what the
generator writes.

## Generated code

- `cloak-api-models` is generated from the OpenAPI spec at build time.
- `cloak-ts/packages/client/src/generated/cloakApi.ts` is generated by `pnpm generate` and checked
  in. `pnpm typecheck` generates it again into a temporary file and fails when the checked-in copy
  differs.

## Tests

**Protocol in TypeScript** (`cloak-ts/packages/crypto`, `pnpm test`) checks every vector file byte
for byte and verdict for verdict: canonical encoding, codes and fingerprints, user ids, key
derivation, encrypted and sealed blobs through the functions that make them, padding, envelopes
and small-order X25519 keys, strict signatures, key statements and their chains, signed
credentials changes, acceptances and deletions, node ids, the scenario vault log with each of its
negative logs, checkpoint trees and proofs, and every section write with its expected reason. It
also covers what the vectors cannot: fields outside their types refused as `malformed`, lone
surrogates, log snapshots continued with new entries, and section marks.

**Server core** (`cloak-server-core`, against PostgreSQL 17 in Testcontainers) covers schema drift
between the migration and the Exposed tables, every named constraint, every vector file, each
operation's rules, and races between concurrent writes and between a rotation and a write. Merkle
trees are checked against RFC 6962's recursive definition; checkpoint spans against the latest
writes over a random history of writes, deletions, left-out and re-included sections and rotations;
a vault at its 100 000-section limit rotates twice within the default budgets, and a proof batch
naming both of its checkpoints is refused; the change feed, node reads and batch node reads of
sections near 1 MiB stay within one page's budget and their cursors cover everything once. Also
covered: deletion and erasure, an erasure racing the user's new vault, registrations racing for one
user id or one signing key, parallel additions of one user against the invitation limits, busy
answers, settings and events, write pauses, batch rotations and reads, change feeds, batch section
headers, live and stored section limits, purges and a role changed while one waits, node entries
and the place rule of writes, vault deletion, acceptance and its limits, signed credentials changes
and deletions, and access by node. `testFixtures` provides a fresh database and a test client that
signs like a real one.

**Spring Boot starter.** `CloakAdmissionTest` checks, with the limit at its 4 MB floor, that every
handler names its `operationId`, that a deleted user is refused by every operation, the guard and
its `Retry-After`, the size limit, that the largest rotation, key replacement and section write
fit, that logs of refusals and unexpected failures name no user and no id, that meters carry no
ids, and health. `CloakServletPathTest` checks the size limit under `spring.mvc.servlet.path`.
`CloakAutoConfigurationTest` covers startup failures, the pending invitations limit taken from the
properties, and the optional Micrometer and health support. `CloakApiTest` drives the whole API
over MockMvc, checks every response against the OpenAPI contract, including pages of sections near
1 MiB and their cursors, checks that the starter maps exactly the contract's operations, and that
bodies are read without coercing JSON types or repeating keys and ids only in canonical form, in
paths and bodies; `ParamsTest` checks the same of query ids, and `OpenApiContractTest` that the
contract check itself rejects a missing field, a status the operation does not list and an unknown
problem code. `JavaHostTest` is a host written in Java, so a public signature Java cannot call
fails the build.

**TypeScript client** (`cloak-ts/packages/client`):

- `pnpm test`: unit tests without a server: local state (sealing, moving every record to a new
  key, snapshots, forgetting, vouching), the keyring (pinning, chains, host user ids that do not
  derive the person, key alarms, a pinned person left out, confirmed fingerprints as typed, deleted
  people), the checkpoint index (answers by root, dropped with their vault, proof batches kept
  within a vault's worth of leaves), `identityStatus`, the client overwriting the secret key it
  read, the transport (retries of the same bytes, `network_error`, aborts), that every API error
  code is named, the session gate, the password worker and persistent storage.
- `pnpm test:e2e`: the whole client against the real Kotlin server, through `cloak-dev-server`.
  `client.e2e.ts` runs the honest flows: identity status, registration, password changes and
  recovery, roles and checkpoints, rotations, nodes across vaults and their placement, many nodes
  at once, moves and the change feed, deleted sections written again, leaving, key replacement,
  account and vault deletion, erasure, purges, forgetting vaults, closing sessions, groups of
  vaults and invitations, and a node larger than one page read completely.
  `maliciousServer.e2e.ts` puts a lying server between client and server and shows each attack is
  caught: a vault key of the server's choosing, a member nobody added, a pinned person's keys
  swapped, another person's identity passed off as the user's, a demoted editor's backdated write,
  a section rolled back or forked, or rolled back to a write a later checkpoint superseded, nodes
  claimed created that the log does not hold, the latest writes a writer chains to rolled back,
  forked or answered for other sections, a vault log rolled back or forked with a validly signed
  branch, a false role or head, writes signed with replaced keys, entries the replaced keys signed
  hidden from the key replacement, a write echoed other than signed or served under another
  address, a new write's signature check skipped by naming a write the device checked, a forged
  leaf list, swapped or false proofs, a ciphertext other than the signed one, people met through
  something that does not verify, vouched for by a vault the user never accepted or by an
  acceptance of something else, or added unconfirmed by asking twice, a departure or vault
  deletion answered but never applied, a dropped response to a registration or key replacement, a
  write a viewer or uncommitted keys signed taken as stored, a latest write at the highest
  version, a vault hidden from a batch read, a log, change feed, leaf list or vault list that
  stalls or pages forever, a node read that holds more than one page or pages forever, malformed
  responses and keys, signatures and listings of the wrong size or shape, and conflicts or busy
  answers faked to collect a second signed version of a write, a change or a rotation.
  `scale.e2e.ts` counts the requests of checkpoints built from headers and leaf lists on a vault of
  1 300 sections, of a batch of 100 writes chained with one lookup, of 100 nodes created with one
  append, of a later session continuing from its snapshot and of a vault read again checking
  signatures only once, and shows a write pause keeping a racing writer from making a checkpoint
  fail.

## Versioning

`VERSION` holds the version of the repository; every artifact of a release carries it, and
[`CHANGELOG.md`](../CHANGELOG.md) says what each release changed. Versions follow semantic
versioning over the public API of the packages: a minor release adds, a major release removes or
reshapes. Before 1.0.0, a minor release may break. The wire protocol has versions of its own
(`PROTOCOL.md` §17): a release that changes it says so, and the server's `GET /meta` names the
protocol and API versions it speaks.

## Releases

A release goes through a reviewed pull request, and what was verified is what is published:

1. **Prepare Release** (run by hand on `main`, choosing patch, minor or major) opens
   `release/vX.Y.Z`, which changes only `VERSION`. On that branch, rename the `## Unreleased`
   heading of `CHANGELOG.md` to `## X.Y.Z`; changes collect under `Unreleased` as they land.
2. **Verify** runs `ci/verify` on it, then **Build release artifacts**
   (`ci/release/build-artifacts`) builds the Maven artifacts of `ci/release/packages` and the npm
   packages once, resolves and runs them in consumers, and keeps them.
3. Merging it runs **Publish Release**, which, after approval in the `release` environment,
   uploads exactly those artifacts to GitHub Packages, tags `vX.Y.Z` and creates the GitHub Release
   with the `CHANGELOG.md` section and the published coordinates.

The repository needs a `release` environment with required reviewers, the secret
`RELEASE_BOT_TOKEN` and the variables `RELEASE_BOT_NAME` and `RELEASE_BOT_EMAIL` (a pull request
opened with the workflow's own token would start no workflow), and branch protection on `main` that
requires **Build and check whole repository** and **Build release artifacts** on an up-to-date
branch.
