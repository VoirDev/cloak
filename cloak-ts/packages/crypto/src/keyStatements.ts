import { Canonical } from './canonical.ts';
import { LABELS } from './labels.ts';
import {
  CRYPTO_SUITE,
  isWellFormedKeys,
  keysDigest,
  sameKeys,
  type PublicKeys,
} from './publicKeys.ts';
import { checkEncryptionKey } from './hpke.ts';
import { checkSignature, checkSigningKey, sign } from './signatures.ts';

/** A key version as published, with its signatures (`PROTOCOL.md` §5.2). */
export interface KeyStatement {
  /** The key version. */
  readonly keys: PublicKeys;
  /** Signature by the version's own signing key. */
  readonly signature: Uint8Array;
  /** Signature by the previous version's recovery signing key; absent for version 1. */
  readonly recoverySignature?: Uint8Array | undefined;
}

/**
 * Builds the message of a key statement.
 *
 * @param keys The key version it publishes.
 * @param previous The version it follows; absent for version 1.
 * @returns Canonical message.
 */
export function keyStatementMessage(keys: PublicKeys, previous?: PublicKeys): Uint8Array {
  return Canonical.of(LABELS.keyStatement)
    .uuid(keys.userId)
    .u32(keys.keyVersion)
    .digest32(keysDigest(keys))
    .digest32(previous === undefined ? undefined : keysDigest(previous))
    .build();
}

/**
 * Signs a key statement: by the new signing key, and from version 2 on by the recovery signing key
 * of the version it follows.
 *
 * @param keys The new key version.
 * @param signingSeed Seed of the new signing key.
 * @param previous The version it follows, with that version's recovery signing seed; absent for
 *   version 1.
 * @returns The statement.
 */
export function signKeyStatement(
  keys: PublicKeys,
  signingSeed: Uint8Array,
  previous?: { readonly keys: PublicKeys; readonly recoverySigningSeed: Uint8Array },
): KeyStatement {
  const message = keyStatementMessage(keys, previous?.keys);
  return {
    keys,
    signature: sign(signingSeed, message),
    ...(previous === undefined
      ? {}
      : { recoverySignature: sign(previous.recoverySigningSeed, message) }),
  };
}

/**
 * Checks a key statement against the version it follows (`PROTOCOL.md` §5.2).
 *
 * @param statement Statement to check.
 * @param previous The trusted version it must follow; absent for version 1.
 * @returns Whether it is valid: fields that fit their types (§3), the right user and version, keys
 *   of usable shape, its own signature and, after version 1, the previous recovery key's signature.
 */
export function verifyKeyStatement(statement: KeyStatement, previous?: PublicKeys): boolean {
  const { keys } = statement;
  // A field outside its type has no canonical message to verify.
  if (!isWellFormedKeys(keys) || (previous !== undefined && !isWellFormedKeys(previous)))
    return false;
  const expectedVersion = previous === undefined ? 1 : previous.keyVersion + 1;
  if (keys.keyVersion !== expectedVersion || keys.cryptoSuite !== CRYPTO_SUITE) return false;
  if (previous !== undefined && previous.userId !== keys.userId) return false;
  // Every key must be usable before anyone relies on it: a member whose encryption key cannot be
  // sealed to would make every rotation that keeps them fail (`PROTOCOL.md` §5.1).
  if (
    checkSigningKey(keys.signingPublicKey) !== undefined ||
    checkSigningKey(keys.recoverySigningPublicKey) !== undefined ||
    checkEncryptionKey(keys.encryptionPublicKey) !== undefined
  )
    return false;
  const message = keyStatementMessage(keys, previous);
  if (checkSignature(keys.signingPublicKey, message, statement.signature) !== undefined)
    return false;
  if (previous === undefined) return statement.recoverySignature === undefined;
  return (
    statement.recoverySignature !== undefined &&
    checkSignature(previous.recoverySigningPublicKey, message, statement.recoverySignature) ===
      undefined
  );
}

/** Outcome of following a user's key statements from a trusted version. */
export type KeyChainResult =
  | {
      /** Discriminant. */
      readonly ok: true;
      /** Every trusted version, oldest first, from the pinned one to the newest. */
      readonly versions: readonly PublicKeys[];
    }
  | {
      /** Discriminant. */
      readonly ok: false;
      /**
       * `key_alarm` when the served version the client already trusts differs from it;
       * `bad_statement` when a later statement does not chain.
       */
      readonly reason: 'key_alarm' | 'bad_statement';
      /** Version where the chain broke. */
      readonly keyVersion: number;
    };

/**
 * Follows a user's key statements from the version a client trusts (`PROTOCOL.md` §5.2, §9).
 *
 * @param trusted The version the client pinned or verified before.
 * @param statements Every statement the server serves for the user, in any order.
 * @returns The trusted chain up to the newest version, or where it breaks: a statement of the user
 *   whose fields do not fit their types (§3) breaks it at its version as `bad_statement`.
 */
export function followKeyChain(
  trusted: PublicKeys,
  statements: readonly KeyStatement[],
): KeyChainResult {
  // Only the user's own statements count; two different ones for a version are a key alarm.
  const byVersion = new Map<number, KeyStatement>();
  for (const statement of statements) {
    if (statement.keys.userId !== trusted.userId) continue;
    const version = statement.keys.keyVersion;
    // Checked before digesting, which needs a canonical message.
    if (!isWellFormedKeys(statement.keys))
      return { ok: false, reason: 'bad_statement', keyVersion: version };
    const seen = byVersion.get(version);
    if (seen !== undefined && !sameKeys(seen.keys, statement.keys)) {
      return { ok: false, reason: 'key_alarm', keyVersion: version };
    }
    byVersion.set(version, statement);
  }
  const pinned = byVersion.get(trusted.keyVersion);
  if (pinned !== undefined && !sameKeys(pinned.keys, trusted)) {
    return { ok: false, reason: 'key_alarm', keyVersion: trusted.keyVersion };
  }
  const versions: PublicKeys[] = [trusted];
  let current = trusted;
  for (;;) {
    const next = byVersion.get(current.keyVersion + 1);
    if (next === undefined) return { ok: true, versions };
    if (!verifyKeyStatement(next, current)) {
      return { ok: false, reason: 'bad_statement', keyVersion: current.keyVersion + 1 };
    }
    versions.push(next.keys);
    current = next.keys;
  }
}
