# Repository Instructions

## Release stage

**Pre-release.** No application or tester holds Cloak data. Protocol v1, its test vectors, the HTTP
API, the public Kotlin and TypeScript APIs and the `V1` migration change in place: no data
migrations, compatibility shims, deprecated aliases or fallbacks for old shapes.

## Before changing code

- Read [docs/development.md](docs/development.md) for the layout, the checks and the tests, and
  [`cloak-protocol/PROTOCOL.md`](cloak-protocol/PROTOCOL.md) for every byte and rule.
- Run `./ci/verify` before proposing a change; CI runs exactly it.
- A change to the protocol changes `PROTOCOL.md`, the vector generator, the vectors, the JDK
  verifier and every implementation together.
- A change to the HTTP API changes `cloak-protocol/openapi/cloak-api.v1.yaml` and regenerates the
  TypeScript client with `pnpm generate`.
