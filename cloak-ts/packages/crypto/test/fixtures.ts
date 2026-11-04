import {
  CRYPTO_SUITE,
  type CheckpointLeaf,
  type LogEntry,
  type LogEntryKind,
  type PublicKeys,
  type Role,
  type SectionWrite,
} from '../src/index.ts';
import {
  child,
  fromHex,
  hex,
  num,
  objects,
  optionalHex,
  optionalNum,
  optionalText,
  text,
  vectors,
  type Json,
} from './vectors.ts';

/** A vector identity: one key version with its private keys. */
export interface VectorIdentity {
  /** Name such as `owner-v1`. */
  readonly name: string;
  /** Public keys. */
  readonly keys: PublicKeys;
  /** X25519 private key. */
  readonly encryptionPrivateKey: Uint8Array;
  /** Ed25519 seed. */
  readonly signingSeed: Uint8Array;
  /** Recovery key. */
  readonly recoveryKey: Uint8Array;
  /** Recovery signing seed. */
  readonly recoverySigningSeed: Uint8Array;
  /** Expected `keysDigest`. */
  readonly keysDigest: string;
}

/** Reads an identity as the vectors write it. */
export function toIdentity(json: Json): VectorIdentity {
  return {
    name: text(json, 'name'),
    keys: {
      userId: text(json, 'userId'),
      keyVersion: num(json, 'keyVersion'),
      cryptoSuite: CRYPTO_SUITE,
      encryptionPublicKey: hex(json, 'encryptionPublicKey'),
      signingPublicKey: hex(json, 'signingPublicKey'),
      recoverySigningPublicKey: hex(json, 'recoverySigningPublicKey'),
    },
    encryptionPrivateKey: hex(json, 'encryptionPrivateKey'),
    signingSeed: hex(json, 'signingSeed'),
    recoveryKey: hex(json, 'recoveryKey'),
    recoverySigningSeed: hex(json, 'recoverySigningSeed'),
    keysDigest: text(json, 'keysDigest'),
  };
}

/** Every identity of identity.json. */
export const IDENTITIES: readonly VectorIdentity[] = objects(
  vectors('identity.json'),
  'identities',
).map(toIdentity);

/**
 * A vector identity by name.
 *
 * @param name Name such as `owner-v1`.
 * @returns The identity.
 */
export function identityNamed(name: string): VectorIdentity {
  const found = IDENTITIES.find((identity) => identity.name === name);
  if (found === undefined) throw new Error(`No vector identity ${name}`);
  return found;
}

/**
 * The trusted keys of the vectors: every key version in identity.json.
 *
 * @param userId User.
 * @param keyVersion Key version.
 * @returns The keys, or `undefined` for a version nobody vouched for.
 */
export function keysOf(userId: string, keyVersion: number): PublicKeys | undefined {
  return IDENTITIES.find(
    (identity) => identity.keys.userId === userId && identity.keys.keyVersion === keyVersion,
  )?.keys;
}

/** Sentinel for a vector `requestEnd` that is neither 0 nor 1. */
export class BadFlag extends Error {}

/** Reads a checkpoint leaf. */
export function toLeaf(json: Json): CheckpointLeaf {
  return {
    nodeId: text(json, 'nodeId'),
    sectionName: text(json, 'sectionName'),
    dataVersion: num(json, 'dataVersion'),
    writeHash: hex(json, 'writeHash'),
  };
}

/**
 * Reads a log entry as the vectors write it.
 *
 * @param json One element of a `log` array.
 * @returns The entry.
 * @throws {BadFlag} When `requestEnd` is not 0 or 1, which decoding must refuse.
 */
export function toLogEntry(json: Json): LogEntry {
  const entry = child(json, 'entry');
  const requestEnd = num(entry, 'requestEnd');
  if (requestEnd !== 0 && requestEnd !== 1) throw new BadFlag();
  const leaves = json['checkpointLeaves'];
  return {
    vaultId: text(entry, 'vaultId'),
    seq: num(entry, 'seq'),
    previousHash: hex(json, 'previousHash'),
    kind: text(entry, 'kind') as LogEntryKind,
    subjectUserId: optionalText(entry, 'subjectUserId'),
    role: optionalText(entry, 'role') as Role | undefined,
    keyVersion: num(entry, 'keyVersion'),
    subjectKeys: optionalHex(entry, 'subjectKeys'),
    subjectKeyVersion: optionalNum(entry, 'subjectKeyVersion'),
    keyCommitment: optionalHex(entry, 'keyCommitment'),
    checkpoint: optionalHex(entry, 'checkpoint'),
    requestEnd: requestEnd === 1,
    authorUserId: text(entry, 'authorUserId'),
    authorKeyVersion: num(entry, 'authorKeyVersion'),
    nodeId: optionalText(entry, 'nodeId'),
    homeVaultId: optionalText(entry, 'homeVaultId'),
    nodeKey: optionalText(entry, 'nodeKey'),
    sections: optionalText(entry, 'sections'),
    signature: hex(json, 'signature'),
    entryHash: hex(json, 'entryHash'),
    checkpointLeaves: Array.isArray(leaves)
      ? objects(json, 'checkpointLeaves').map(toLeaf)
      : undefined,
  };
}

/**
 * Reads a section case's write.
 *
 * @param json One element of `cases` in sections.json.
 * @returns The write.
 */
export function toSectionWrite(json: Json): SectionWrite {
  const write = child(json, 'write');
  const previous = hex(write, 'previousWriteHash');
  return {
    vaultId: text(write, 'vaultId'),
    nodeId: text(write, 'nodeId'),
    nodeType: text(write, 'nodeType'),
    homeVaultId: text(write, 'homeVaultId'),
    ownerUserId: text(write, 'ownerUserId'),
    nodeKey: text(write, 'nodeKey'),
    sectionName: text(write, 'sectionName'),
    vaultKeyVersion: num(write, 'vaultKeyVersion'),
    dataVersion: num(write, 'dataVersion'),
    deleted: num(write, 'deleted') === 1,
    logSeq: num(write, 'logSeq'),
    logHeadHash: hex(write, 'logHeadHash'),
    previousWriteHash: previous.every((byte) => byte === 0) ? undefined : previous,
    writerUserId: text(write, 'writerUserId'),
    writerKeyVersion: num(write, 'writerKeyVersion'),
    ciphertext: optionalHex(json, 'ciphertext'),
    signature: hex(json, 'signature'),
  };
}

/** The vault keys of vault-log.json, by version. */
export function vaultKeyOf(keyVersion: number): Uint8Array | undefined {
  const found = objects(vectors('vault-log.json'), 'vaultKeys').find(
    (key) => num(key, 'keyVersion') === keyVersion,
  );
  return found === undefined ? undefined : fromHex(text(found, 'vaultKey'));
}
