# TODO

Planned work, in rough order. The residual risks the protocol accepts are in
[`PROTOCOL.md`](cloak-protocol/PROTOCOL.md) §16 and [docs/security.md](docs/security.md).

## Device linking

**Why.** The server can keep a device on its own branch of a vault's history (§16, Branches). A
device that compares its verified heads with another of the same user's devices notices.

- [ ] Link a new device by scanning a QR code from a signed-in one: it carries the secret key, the
      pins and the verified vault heads (§5.3, §15), so the new device starts from the same trust.
- [ ] Linked devices exchange verified heads now and then over the host's own channel and raise an
      alarm when they diverge.

## Encrypted export

**Why.** The server can delete data (§16, Availability), and Cloak has no backup of its own: a
restored server is a rollback to every client. The data's owners keep their copies, and an export
encrypted under the user's keys lets them.

- [ ] Export every readable section with the logs that vouch for it; import checks it like a read.

## KMP client

A Kotlin Multiplatform client (`cloak-kmp`) for Android, iOS and JVM apps, with the same
capabilities as `@voirdev/cloak-client`.

- [ ] Crypto module that reproduces every file in `cloak-protocol/test-vectors/v1`, including the
      log, checkpoint and section verdicts. Pick audited libraries per platform.
- [ ] API client generated from `cloak-protocol/openapi/cloak-api.v1.yaml`, with a drift check.
- [ ] Session API matching the TS client, local state as in §15 over a pluggable store.
- [ ] End-to-end tests against `cloak-dev-server`, honest and hostile, plus a cross test: data the
      TS client writes is read and verified by the KMP client, and the reverse.

## Ktor plugin

A Ktor server plugin (`cloak-ktor`) that serves the same API as `cloak-spring-boot-starter` over
the same `CloakServer`.

- [ ] Routes for every operation under `/cloak/v1`, using the fabrikt models from
      `cloak-api-models`.
- [ ] Host-supplied principal resolver and clock; migration at startup.
- [ ] RFC 9457 problem responses with the same error codes and field pointers as the starter.
- [ ] Reuse the starter's contract tests so both adapters are validated against the OpenAPI spec.
