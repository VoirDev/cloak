# cloak-dev-server

A throwaway Spring Boot host for the client's end-to-end tests: PostgreSQL in a Testcontainers
container and "authentication" by the `X-Cloak-Dev-User` header, whose value is the caller's host
user id. It is not secure. Never deploy it, and never copy its endpoints into a real host.

It serves the Cloak API under `/cloak/v1` through `cloak-spring-boot-starter` with the starter's
defaults, including the 16MB request size limit (`cloak.max-request-size`), which a test may change
with `--cloak.max-request-size=<size>`.

## Test-only hooks

| Endpoint                                                                                | Stands in for                                                                                                                                                                                    |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `POST /dev/users/{hostUserId}/erase` → 204                                              | The host erasing a user from its own code (`IdentityOperations.erase`, `PROTOCOL.md` §5.7). Idempotent.                                                                                          |
| `POST /dev/nodes/{nodeId}/purge?user={hostUserId}` → 200 `{"remainingVaultIds": [...]}` | The host removing a node's sections on a user's behalf when it deletes the resource (`NodeOperations.purge`): only in vaults that user administers; the vaults where sections remain are listed. |

These hooks exist only here: the starter never serves them, and a real host calls
`CloakServer.identity.erase` and `CloakServer.nodes.purge` from its own code, behind its own
authorization.

```bash
./gradlew :cloak-dev-server:run --args='--server.port=8080'
```
