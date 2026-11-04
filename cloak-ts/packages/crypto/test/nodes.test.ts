import { describe, expect, it } from 'vitest';

import {
  credentialsMessage,
  formatSectionScope,
  identityDeletionMessage,
  nodeIdOf,
  parseSectionScope,
  verifyIdentityStatement,
} from '../src/index.ts';
import { IDENTITIES } from './fixtures.ts';
import { child, fromHex, num, objects, text, toHex, vectors } from './vectors.ts';

const IDENTITY = vectors('identity.json');

describe('nodes', () => {
  it('derives node ids from owner, home vault and key as the vectors do', () => {
    for (const vector of objects(IDENTITY, 'nodeIds')) {
      expect(
        nodeIdOf({
          ownerUserId: text(vector, 'ownerUserId'),
          homeVaultId: text(vector, 'homeVaultId'),
          nodeKey: text(vector, 'nodeKey'),
        }),
      ).toBe(text(vector, 'nodeId'));
    }
  });

  it('refuses node keys that are empty or longer than 255 bytes', () => {
    const base = {
      ownerUserId: '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d0e',
      homeVaultId: '0192f5a3-0000-7aaa-8bbb-0123456789ab',
    };
    expect(() => nodeIdOf({ ...base, nodeKey: '' })).toThrow();
    expect(() => nodeIdOf({ ...base, nodeKey: 'é'.repeat(128) })).toThrow();
    expect(nodeIdOf({ ...base, nodeKey: 'é'.repeat(127) })).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('reads and writes section scopes in one canonical form', () => {
    expect(parseSectionScope('*')).toBe('*');
    expect(parseSectionScope('notes,secrets')).toEqual(['notes', 'secrets']);
    for (const bad of ['', 'secrets,notes', 'notes,notes', 'Notes', 'notes,', ',notes', '*,notes'])
      expect(parseSectionScope(bad)).toBeUndefined();
    expect(formatSectionScope(['secrets', 'notes', 'secrets'])).toBe('notes,secrets');
    expect(formatSectionScope('*')).toBe('*');
  });
});

describe('identity statements', () => {
  const credentials = child(IDENTITY, 'credentials');
  const signer = child(credentials, 'signer');
  const owner = IDENTITIES.find(
    (identity) =>
      identity.keys.userId === text(signer, 'userId') &&
      identity.keys.keyVersion === num(signer, 'keyVersion'),
  );

  it('builds and verifies a signed credentials change as the vectors do', () => {
    const change = child(credentials, 'change');
    const kdf = child(change, 'kdf');
    const message = credentialsMessage({
      userId: text(signer, 'userId'),
      keyVersion: num(signer, 'keyVersion'),
      credentialsVersion: num(change, 'credentialsVersion'),
      privateKeyBundle: fromHex(text(change, 'privateKeyBundle')),
      kdf: {
        salt: fromHex(text(kdf, 'salt')),
        memoryKib: num(kdf, 'memoryKib'),
        iterations: num(kdf, 'iterations'),
        parallelism: num(kdf, 'parallelism'),
      },
    });
    expect(toHex(message)).toBe(text(change, 'message'));
    const signature = fromHex(text(change, 'signature'));
    if (owner === undefined) throw new Error('No signer');
    expect(verifyIdentityStatement(message, signature, owner.keys.signingPublicKey)).toBe(true);
    const other = message.slice();
    other[other.length - 1] = (other[other.length - 1] ?? 0) ^ 1;
    expect(verifyIdentityStatement(other, signature, owner.keys.signingPublicKey)).toBe(false);
  });

  it('builds a signed identity deletion as the vectors do', () => {
    const deletion = child(credentials, 'deletion');
    const message = identityDeletionMessage(
      text(signer, 'userId'),
      num(signer, 'keyVersion'),
      num(deletion, 'credentialsVersion'),
      num(deletion, 'notAfter'),
    );
    expect(toHex(message)).toBe(text(deletion, 'message'));
  });
});
