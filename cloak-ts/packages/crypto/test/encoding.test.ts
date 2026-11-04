import { describe, expect, it } from 'vitest';

import {
  Canonical,
  LABELS,
  bundleAd,
  envelopeContext,
  fingerprintMessage,
  keyStatementMessage,
  localRecordAd,
  logMessage,
  previousKeyAd,
  sectionContentAd,
  sectionWriteMessage,
  nodeIdOf,
} from '../src/index.ts';
import { identityNamed } from './fixtures.ts';
import { fromHex, objects, text, toHex, vectors, type Json } from './vectors.ts';

const CASES = objects(vectors('encoding.json'), 'cases');
const VAULT = '0192f5a3-0000-7aaa-8bbb-0123456789ab';
const OWNER = '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d0e';
/** The scenario's node: owned by the owner, homed in the vault, keyed `server-1`. */
const NODE = nodeIdOf({ ownerUserId: OWNER, homeVaultId: VAULT, nodeKey: 'server-1' });
const BOB = '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d1f';

/** Expected bytes of a named case. */
function expected(name: string): string {
  const found = CASES.find((vector) => text(vector, 'name') === name);
  if (found === undefined) throw new Error(name);
  return text(found, 'expected');
}

/** Field values of a named case, by position. */
function fieldValue(name: string, index: number): string {
  const found = CASES.find((vector) => text(vector, 'name') === name);
  if (found === undefined) throw new Error(name);
  const field = objects(found, 'fields')[index];
  if (field === undefined) throw new Error(`${name}[${String(index)}]`);
  return String(field['value']);
}

/** Encodes one typed field of a vector. */
function encodeField(builder: Canonical, field: Json): Canonical {
  const value = field['value'];
  switch (text(field, 'type')) {
    case 'label':
    case 'str':
      return builder.str(String(value));
    case 'u8':
      return builder.u8(Number(value));
    case 'u32':
      return builder.u32(Number(value));
    case 'u64':
      return builder.u64(BigInt(String(value)));
    case 'flag':
      return builder.flag(value === 1);
    case 'uuid':
      return builder.uuid(String(value));
    case 'key32':
      return builder.key32(fromHex(String(value)));
    case 'digest32':
      return builder.digest32(fromHex(String(value)));
    default:
      throw new Error(`Unknown field type ${text(field, 'type')}`);
  }
}

describe('canonical encoding', () => {
  it.each(CASES.map((vector) => [text(vector, 'name'), vector] as const))(
    'encodes the fields of %s',
    (_, vector) => {
      const built = objects(vector, 'fields').reduce(encodeField, new Canonical()).build();
      expect(toHex(built)).toBe(text(vector, 'expected'));
    },
  );

  it('builds every protocol message as the vectors do', () => {
    const ownerV1 = identityNamed('owner-v1').keys;
    const ownerV2 = identityNamed('owner-v2').keys;

    expect(toHex(bundleAd(LABELS.privateKeyBundle, OWNER, 2))).toBe(
      expected('private-key-bundle-ad'),
    );
    expect(toHex(bundleAd(LABELS.recoveryKeyBundle, OWNER, 1))).toBe(
      expected('recovery-key-bundle-ad'),
    );
    expect(toHex(fingerprintMessage(ownerV1))).toBe(expected('fingerprint-message'));
    expect(toHex(keyStatementMessage(ownerV2, ownerV1))).toBe(expected('key-statement-v2'));
    expect(toHex(envelopeContext(VAULT, 2, { userId: BOB, userKeyVersion: 1 }))).toBe(
      expected('envelope-context'),
    );
    expect(toHex(previousKeyAd(VAULT, 2))).toBe(expected('vault-previous-ad'));
    expect(
      toHex(
        sectionContentAd({
          vaultId: VAULT,
          nodeId: NODE,
          sectionName: 'billing',
          vaultKeyVersion: 3,
        }),
      ),
    ).toBe(expected('section-content-ad'));
    expect(toHex(localRecordAd(`cloak/v1/${OWNER}/pins`))).toBe(expected('local-record-ad'));
  });

  it('builds the section write and log entry messages', () => {
    // The vector gives only the ciphertext's digest, so compare everything before that last field.
    const write = 'section-write-message';
    expect(
      toHex(
        sectionWriteMessage({
          vaultId: VAULT,
          nodeId: NODE,
          nodeType: 'compute.vps',
          homeVaultId: VAULT,
          ownerUserId: OWNER,
          nodeKey: 'server-1',
          sectionName: 'general',
          vaultKeyVersion: 2,
          dataVersion: 7,
          deleted: false,
          logSeq: 9,
          logHeadHash: fromHex(fieldValue(write, 12)),
          previousWriteHash: fromHex(fieldValue(write, 13)),
          writerUserId: BOB,
          writerKeyVersion: 1,
        }),
      ).slice(0, -64),
    ).toBe(expected(write).slice(0, -64));

    const log = 'vault-log-message';
    expect(
      toHex(
        logMessage({
          vaultId: VAULT,
          seq: 5,
          previousHash: fromHex(fieldValue(log, 3)),
          kind: 'key_rotated',
          keyVersion: 2,
          keyCommitment: fromHex(fieldValue(log, 10)),
          checkpoint: fromHex(fieldValue(log, 11)),
          requestEnd: true,
          authorUserId: OWNER,
          authorKeyVersion: 1,
        }),
      ),
    ).toBe(expected(log));
  });

  it('refuses values the encoding cannot hold', () => {
    expect(() => new Canonical().u8(256)).toThrow(RangeError);
    expect(() => new Canonical().u32(-1)).toThrow(RangeError);
    expect(() => new Canonical().u64(2n ** 64n)).toThrow(RangeError);
    expect(() => new Canonical().key32(new Uint8Array(31))).toThrow(RangeError);
    expect(() => new Canonical().str('x'.repeat(65_536))).toThrow(RangeError);
  });
});
