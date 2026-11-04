# @voirdev/cloak-client

The Cloak client for TypeScript. It talks to a host's `/cloak/v1` endpoints and does every
encryption, decryption, signature and log check on the device; the server only stores ciphertext
and signed entries, and nothing it returns is used unchecked.

```ts
const cloak = createCloakClient({ baseUrl: '/cloak/v1', storage: createIndexedDbStorage() });

const { session, secretKeyCode, recoveryKeyCode } = await cloak.register({
  userId: hostUserId, // the host's id of the signed-in user
  password,
});

const team = await session.createVault();
const node = await session.createNode(team.id, record.id); // keep it beside the record
await session.writeSections([
  { vaultId: team.id, node, name: 'secrets', type: 'server', content: { password } },
]);
```

The full guide (sessions, vaults, nodes, invitations, storage, errors, browser requirements) is
[docs/client.md](../../../docs/client.md), and what the application must do for Cloak's
protections to hold is [docs/security.md](../../../docs/security.md).
