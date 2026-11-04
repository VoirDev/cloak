# Cloak

End-to-end encrypted storage and sharing that any application can embed. Users' secrets are
encrypted and signed on their devices; the server stores only ciphertext and signed records, and
clients check everything it returns, treating it as an adversary that may lie, replay or hide.

An application uses Cloak to keep the sensitive part of its data, such as passwords, keys or
private notes, out of reach of its own servers and operators, and to share it between its users
with roles they control, without writing any cryptography itself:

- **Vaults** hold access: members with roles (viewer, editor, admin, owner), a key sealed to each
  member, and a signed log of every change that every member verifies.
- **Nodes** are the secrets of one record, made of named sections. A node lives in a home vault,
  and its owner can share some of its sections into other vaults, so a record can show its address
  to a contractor and keep its password for the team.
- **Removal is real**: removed or demoted members cannot add content others accept, a removal gives
  the vault a new key, and leaked identity keys are replaced with the recovery key.

Cloak is a library, not a service. The host application keeps its own sign-in and business logic;
it embeds Cloak on its backend (a Spring Boot starter, or the core in any JVM host) and in its
clients (TypeScript packages).

## Packages

Releases are published to GitHub Packages of `VoirDev/cloak`; every artifact of a release has the
same version.

| Package                                    | For                                                      |
| ------------------------------------------ | -------------------------------------------------------- |
| `dev.voir.cloak:cloak-spring-boot-starter` | Spring Boot 4 backends: serves the API under `/cloak/v1` |
| `dev.voir.cloak:cloak-server-core`         | Any other JVM backend                                    |
| `dev.voir.cloak:cloak-api-models`          | The wire models, which the starter brings in             |
| `@voirdev/cloak-client`                    | TypeScript clients                                       |
| `@voirdev/cloak-crypto`                    | The protocol in TypeScript, which the client brings in   |

## Documentation

- [How Cloak works](docs/how-it-works.md): users and keys, vaults, nodes and sections,
  checkpoints, key replacement, what devices remember, deletion.
- [Backend](docs/backend.md): installing the starter or the core, configuration, host APIs,
  deleting users, limits, data and operations.
- [TypeScript client](docs/client.md): sessions, vaults, nodes, invitations, storage, errors and
  browser requirements.
- [Security model](docs/security.md): what Cloak protects against, what the application must do,
  and what stays its risk.
- [Protocol](cloak-protocol/PROTOCOL.md): every byte and rule, with the
  [HTTP API](cloak-protocol/openapi/cloak-api.v1.yaml) and the
  [test vectors](cloak-protocol/test-vectors/v1).
- [Development](docs/development.md): repository layout, checks, tests, versioning and releases.

## License

[Apache License 2.0](LICENSE).
