import { describe, expect, it } from 'vitest';

import {
  deriveMasterKey,
  encryptionKeyFor,
  followKeyChain,
  keyStatementMessage,
  keysDigest,
  openPrivateKeyBundle,
  openRecoveryKeyBundle,
  publicKeysOf,
  replaceIdentityKeys,
  createIdentity,
  signKeyStatement,
  verifyKeyStatement,
  type KeyStatement,
  type PublicKeys,
} from '../src/index.ts';
import { IDENTITIES, identityNamed, keysOf } from './fixtures.ts';
import {
  child,
  hex,
  num,
  objects,
  optionalHex,
  text,
  toHex,
  vectors,
  type Json,
} from './vectors.ts';

const IDENTITY = vectors('identity.json');

/** Reads a statement of identity.json against the trusted keys. */
function toStatement(json: Json): KeyStatement {
  const keys = keysOf(text(json, 'userId'), num(json, 'keyVersion'));
  if (keys === undefined) throw new Error('statement keys');
  return {
    keys,
    signature: hex(json, 'signature'),
    recoverySignature: optionalHex(json, 'recoverySignature'),
  };
}

/** The version a statement follows, if any. */
function previousOf(keys: PublicKeys): PublicKeys | undefined {
  return keys.keyVersion === 1 ? undefined : keysOf(keys.userId, keys.keyVersion - 1);
}

describe('identity keys', () => {
  it.each(IDENTITIES.map((identity) => [identity.name, identity] as const))(
    'derives the public keys and digest of %s',
    (_, identity) => {
      const keys = publicKeysOf(
        identity.keys.userId,
        identity.keys.keyVersion,
        identity,
        identity.recoveryKey,
      );
      expect(keys).toEqual(identity.keys);
      expect(toHex(keysDigest(keys))).toBe(identity.keysDigest);
    },
  );
});

describe('key statements', () => {
  it.each(
    objects(IDENTITY, 'statements').map(
      (json) => [`${text(json, 'userId')} v${String(num(json, 'keyVersion'))}`, json] as const,
    ),
  )('verifies the statement of %s', (_, json) => {
    const statement = toStatement(json);
    const previous = previousOf(statement.keys);
    expect(toHex(keyStatementMessage(statement.keys, previous))).toBe(text(json, 'message'));
    expect(verifyKeyStatement(statement, previous)).toBe(true);
  });

  it('signs statements as the vectors do', () => {
    const ownerV1 = identityNamed('owner-v1');
    const ownerV2 = identityNamed('owner-v2');
    const json = objects(IDENTITY, 'statements')[1];
    if (json === undefined) throw new Error('statement');
    const statement = signKeyStatement(ownerV2.keys, ownerV2.signingSeed, {
      keys: ownerV1.keys,
      recoverySigningSeed: ownerV1.recoverySigningSeed,
    });
    expect(toHex(statement.signature)).toBe(text(json, 'signature'));
    expect(toHex(statement.recoverySignature ?? new Uint8Array())).toBe(
      text(json, 'recoverySignature'),
    );
  });

  it.each(objects(IDENTITY, 'negatives').map((json) => [text(json, 'name'), json] as const))(
    'refuses %s',
    (_, json) => {
      const statement = toStatement(child(json, 'statement'));
      expect(text(json, 'reason')).toBe('bad_statement');
      expect(verifyKeyStatement(statement, previousOf(statement.keys))).toBe(false);
    },
  );

  it('follows a chain of statements from a pinned version and raises a key alarm', () => {
    const statements = objects(IDENTITY, 'statements').map(toStatement);
    const ownerV1 = identityNamed('owner-v1').keys;
    const ownerV2 = identityNamed('owner-v2').keys;

    expect(followKeyChain(ownerV1, statements)).toEqual({ ok: true, versions: [ownerV1, ownerV2] });
    expect(
      followKeyChain(
        ownerV1,
        statements.filter((s) => s.keys.keyVersion === 1),
      ),
    ).toEqual({
      ok: true,
      versions: [ownerV1],
    });

    const swapped = { ...ownerV1, signingPublicKey: identityNamed('bob-v1').keys.signingPublicKey };
    expect(followKeyChain(swapped, statements)).toEqual({
      ok: false,
      reason: 'key_alarm',
      keyVersion: 1,
    });

    const negative = objects(IDENTITY, 'negatives')[0];
    if (negative === undefined) throw new Error('negative');
    const broken = statements.map((s) =>
      s.keys.keyVersion === 2 ? toStatement(child(negative, 'statement')) : s,
    );
    expect(followKeyChain(ownerV1, broken)).toEqual({
      ok: false,
      reason: 'bad_statement',
      keyVersion: 2,
    });

    const otherV2 = { ...ownerV2, signingPublicKey: identityNamed('bob-v1').keys.signingPublicKey };
    const twoForVersion2 = [...statements, { ...statements[1], keys: otherV2 } as KeyStatement];
    expect(followKeyChain(ownerV1, twoForVersion2)).toEqual({
      ok: false,
      reason: 'key_alarm',
      keyVersion: 2,
    });
  });
});

describe('creating and replacing identity keys', () => {
  it('creates version 1 and replaces it with version 2 signed by the old recovery key', async () => {
    const userId = '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d4c';
    const first = await createIdentity(userId, 'first password');
    expect(verifyKeyStatement(first.statement)).toBe(true);
    expect(first.keys.keyVersion).toBe(1);

    const opened = openRecoveryKeyBundle(first.recoveryKey, first.keys, first.recoveryKeyBundle);
    expect(opened).toEqual({ ...first.secrets, previousLocalStateKey: undefined });

    const second = await replaceIdentityKeys({
      current: first.keys,
      currentSecrets: opened,
      currentRecoveryKey: first.recoveryKey,
      password: 'second password',
    });
    expect(second.keys.keyVersion).toBe(2);
    expect(verifyKeyStatement(second.statement, first.keys)).toBe(true);
    expect(followKeyChain(first.keys, [first.statement, second.statement])).toEqual({
      ok: true,
      versions: [first.keys, second.keys],
    });

    const masterKey = await deriveMasterKey({
      password: 'second password',
      secretKey: second.secretKey,
      userId,
      kdf: second.kdf,
    });
    const secrets = openPrivateKeyBundle(masterKey, second.keys, second.privateKeyBundle);
    expect(secrets.previousLocalStateKey).toEqual(first.secrets.localStateKey);
    expect(encryptionKeyFor(secrets, 2, 1)).toEqual(first.secrets.encryptionPrivateKey);
    expect(encryptionKeyFor(secrets, 2, 2)).toEqual(second.secrets.encryptionPrivateKey);
    expect(encryptionKeyFor(secrets, 2, 3)).toBeUndefined();
  }, 30_000);
});
