import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { argon2id } from 'hash-wasm';

import { CloakCryptoError } from './CloakCryptoError.ts';
import { decryptBlob, encryptBlob } from './blobs.ts';
import { concatBytes, isAbsent, randomBytes, utf8, uuidBytes, xorBytes } from './bytes.ts';
import { Canonical } from './canonical.ts';
import { hkdf } from './kdf.ts';
import { signKeyStatement, type KeyStatement } from './keyStatements.ts';
import { LABELS } from './labels.ts';
import { CRYPTO_SUITE, type PublicKeys } from './publicKeys.ts';
import { signingPublicKey } from './signatures.ts';

/** Argon2id parameters stored with an identity (`PROTOCOL.md` §5.3). */
export interface KdfParams {
  /** 16 random bytes. */
  readonly salt: Uint8Array;
  /** Memory cost in KiB, within {@link KDF_LIMITS}. */
  readonly memoryKib: number;
  /** Iterations, within {@link KDF_LIMITS}. */
  readonly iterations: number;
  /** Lanes; suite 1 accepts only 1. Typed wider because the value comes from the server. */
  readonly parallelism: number;
}

/** Bounds a client checks before deriving anything, so a server cannot weaken or stall it. */
export const KDF_LIMITS = {
  /** Least memory, in KiB. */
  minMemoryKib: 65_536,
  /** Most memory, in KiB. */
  maxMemoryKib: 1_048_576,
  /** Fewest iterations. */
  minIterations: 2,
  /** Most iterations. */
  maxIterations: 10,
} as const;

/** Argon2id cost for new identities: 64 MiB and 3 iterations. */
export const DEFAULT_KDF_COST = { memoryKib: 65_536, iterations: 3 } as const;

/**
 * A user's private keys at one key version: what both bundles hold (`PROTOCOL.md` §5.4).
 * Only an unlocked session has them.
 */
export interface IdentitySecrets {
  /** X25519 private key of this version. */
  readonly encryptionPrivateKey: Uint8Array;
  /** Ed25519 seed of this version's signing key. */
  readonly signingSeed: Uint8Array;
  /** 32 random bytes that protect the device's local state (§15). */
  readonly localStateKey: Uint8Array;
  /** The previous version's `localStateKey`, so devices can move their state; absent at version 1. */
  readonly previousLocalStateKey?: Uint8Array | undefined;
  /** X25519 private keys of earlier versions, newest first: index 0 is version n − 1. */
  readonly earlierEncryptionKeys: readonly Uint8Array[];
}

/**
 * Overwrites every private key of {@link IdentitySecrets} with zeros, once nothing will use them
 * again. JavaScript keeps no promise that no other copy exists, so this shortens how long keys
 * stay in memory rather than guaranteeing they are gone.
 *
 * @param secrets Secrets to wipe; unusable afterwards.
 */
export function wipeIdentitySecrets(secrets: IdentitySecrets): void {
  secrets.encryptionPrivateKey.fill(0);
  secrets.signingSeed.fill(0);
  secrets.localStateKey.fill(0);
  secrets.previousLocalStateKey?.fill(0);
  for (const key of secrets.earlierEncryptionKeys) key.fill(0);
}

/** Everything a client creates for a new key version. Only public parts and bundles leave the device. */
export interface NewKeyVersion {
  /** The public keys of the version. */
  readonly keys: PublicKeys;
  /** The private keys. */
  readonly secrets: IdentitySecrets;
  /** The signed key statement. */
  readonly statement: KeyStatement;
  /** 16-byte secret key; shown once as a code and kept on devices. */
  readonly secretKey: Uint8Array;
  /** 32-byte recovery key; shown once in the printable kit. */
  readonly recoveryKey: Uint8Array;
  /** KDF parameters with a fresh salt. */
  readonly kdf: KdfParams;
  /** Private keys under the master key. */
  readonly privateKeyBundle: Uint8Array;
  /** Private keys under the recovery key. */
  readonly recoveryKeyBundle: Uint8Array;
}

/** Version byte of the bundle plaintext. */
const BUNDLE_VERSION = 1;

/** Size of a bundle plaintext without earlier encryption keys. */
const BUNDLE_BASE_BYTES = 129;

/**
 * Checks Argon2id parameters against {@link KDF_LIMITS}.
 *
 * @param kdf Parameters, usually as the server returned them.
 * @throws {CloakCryptoError} `invalid_kdf` when they are outside the bounds or not suite 1's.
 */
export function requireKdfParams(kdf: KdfParams): void {
  const inBounds =
    Number.isInteger(kdf.memoryKib) &&
    Number.isInteger(kdf.iterations) &&
    kdf.memoryKib >= KDF_LIMITS.minMemoryKib &&
    kdf.memoryKib <= KDF_LIMITS.maxMemoryKib &&
    kdf.iterations >= KDF_LIMITS.minIterations &&
    kdf.iterations <= KDF_LIMITS.maxIterations &&
    kdf.parallelism === 1 &&
    kdf.salt.length === 16;
  if (!inBounds) throw new CloakCryptoError('invalid_kdf', 'KDF parameters are out of bounds');
}

/**
 * Computes `passwordKey = Argon2id(UTF-8(NFKC(password)), salt, …)` (`PROTOCOL.md` §5.3), the slow
 * half of the master key. {@link derivePasswordKey} does it in the calling thread; a client may run
 * it elsewhere, such as in a Web Worker, as long as it computes exactly this.
 *
 * @param password Master password, as typed.
 * @param kdf Parameters, already checked against {@link KDF_LIMITS}.
 * @returns 32 bytes.
 */
export type PasswordHasher = (password: string, kdf: KdfParams) => Promise<Uint8Array>;

/**
 * Computes `passwordKey` in the calling thread (`PROTOCOL.md` §5.3).
 *
 * @param password Master password, as typed; normalized to NFKC here.
 * @param kdf Parameters; checked against {@link KDF_LIMITS} first.
 * @returns The 32-byte password key.
 * @throws {CloakCryptoError} `invalid_kdf` for parameters out of bounds.
 */
export async function derivePasswordKey(password: string, kdf: KdfParams): Promise<Uint8Array> {
  requireKdfParams(kdf);
  return argon2id({
    password: utf8(password.normalize('NFKC')),
    salt: kdf.salt,
    parallelism: kdf.parallelism,
    iterations: kdf.iterations,
    memorySize: kdf.memoryKib,
    hashLength: 32,
    outputType: 'binary',
  });
}

/** Inputs of {@link deriveMasterKey}. */
export interface DeriveMasterKeyOptions {
  /** Master password, as typed. */
  readonly password: string;
  /** 16-byte secret key. */
  readonly secretKey: Uint8Array;
  /** Owner of the identity; binds the derivation to the account. */
  readonly userId: string;
  /** Stored KDF parameters. */
  readonly kdf: KdfParams;
  /** Where Argon2id runs; {@link derivePasswordKey}, in the calling thread, by default. */
  readonly passwordHasher?: PasswordHasher | undefined;
}

/**
 * Derives the master key from the password and the device-held secret key (`PROTOCOL.md` §5.3):
 * `Argon2id(NFKC(password)) XOR HKDF(secretKey, salt = userId)`. Neither secret alone is enough.
 *
 * @param options Password, secret key, user and KDF parameters.
 * @returns The 32-byte master key.
 * @throws {CloakCryptoError} `invalid_kdf` for parameters out of bounds; `invalid_format` for a
 *   secret key that is not 16 bytes.
 */
export async function deriveMasterKey(options: DeriveMasterKeyOptions): Promise<Uint8Array> {
  const { password, secretKey, userId, kdf } = options;
  requireKdfParams(kdf);
  if (secretKey.length !== 16)
    throw new CloakCryptoError('invalid_format', 'Secret keys have 16 bytes');
  const passwordKey = await (options.passwordHasher ?? derivePasswordKey)(password, kdf);
  if (!(passwordKey instanceof Uint8Array) || passwordKey.length !== 32)
    throw new CloakCryptoError('invalid_format', 'A password key has 32 bytes');
  const material = secretKeyMaterial(secretKey, userId);
  const masterKey = xorBytes(passwordKey, material);
  passwordKey.fill(0);
  material.fill(0);
  return masterKey;
}

/**
 * The secret key's contribution to the master key.
 *
 * @param secretKey 16-byte secret key.
 * @param userId Owner.
 * @returns `HKDF(secretKey, salt = userId, "cloak/v1/secret-key")`.
 */
export function secretKeyMaterial(secretKey: Uint8Array, userId: string): Uint8Array {
  return hkdf(secretKey, uuidBytes(userId), LABELS.secretKey);
}

/**
 * Key of the private key bundle.
 *
 * @param masterKey 32-byte master key.
 * @returns `HKDF(masterKey, salt = empty, "cloak/v1/private-key-bundle")`.
 */
export function privateKeyBundleKey(masterKey: Uint8Array): Uint8Array {
  return hkdf(masterKey, new Uint8Array(0), LABELS.privateKeyBundle);
}

/**
 * Key of the recovery key bundle.
 *
 * @param recoveryKey 32-byte recovery key.
 * @param userId Owner.
 * @returns `HKDF(recoveryKey, salt = userId, "cloak/v1/recovery-key-bundle")`.
 */
export function recoveryBundleKey(recoveryKey: Uint8Array, userId: string): Uint8Array {
  requireRecoveryKey(recoveryKey);
  return hkdf(recoveryKey, uuidBytes(userId), LABELS.recoveryKeyBundle);
}

/**
 * Derives the recovery signing key, which signs only the next key version (`PROTOCOL.md` §5.5).
 *
 * @param recoveryKey 32-byte recovery key.
 * @param userId Owner.
 * @returns The Ed25519 seed and its public key.
 */
export function deriveRecoverySigningKey(
  recoveryKey: Uint8Array,
  userId: string,
): { readonly seed: Uint8Array; readonly publicKey: Uint8Array } {
  requireRecoveryKey(recoveryKey);
  const seed = hkdf(recoveryKey, uuidBytes(userId), LABELS.recoverySign);
  return { seed, publicKey: signingPublicKey(seed) };
}

/**
 * Builds a bundle's associated data (`PROTOCOL.md` §5.4, §5.5).
 *
 * @param label Which bundle.
 * @param userId Owner.
 * @param keyVersion Key version the bundle holds.
 * @returns Canonical associated data.
 */
export function bundleAd(
  label: typeof LABELS.privateKeyBundle | typeof LABELS.recoveryKeyBundle,
  userId: string,
  keyVersion: number,
): Uint8Array {
  return Canonical.of(label).uuid(userId).u8(CRYPTO_SUITE).u32(keyVersion).build();
}

/**
 * Encrypts the private keys under the master key (`PROTOCOL.md` §5.4).
 *
 * @param masterKey 32-byte master key.
 * @param keys The key version's public keys, which name the owner and version.
 * @param secrets Keys to protect.
 * @param nonce Fixed nonce for tests; random by default.
 * @returns The private key bundle.
 */
export function sealPrivateKeyBundle(
  masterKey: Uint8Array,
  keys: Pick<PublicKeys, 'userId' | 'keyVersion'>,
  secrets: IdentitySecrets,
  nonce?: Uint8Array,
): Uint8Array {
  return encryptBlob(
    privateKeyBundleKey(masterKey),
    bundleAd(LABELS.privateKeyBundle, keys.userId, keys.keyVersion),
    bundlePlaintext(secrets),
    nonce,
  );
}

/**
 * Opens the private key bundle; a wrong password or secret key fails here and nowhere else.
 *
 * @param masterKey 32-byte master key.
 * @param keys Owner and key version the server says the bundle holds.
 * @param bundle Private key bundle.
 * @returns The private keys.
 * @throws {CloakCryptoError} `decryption_failed` for a wrong password, secret key or version;
 *   `invalid_format` for a malformed plaintext.
 */
export function openPrivateKeyBundle(
  masterKey: Uint8Array,
  keys: Pick<PublicKeys, 'userId' | 'keyVersion'>,
  bundle: Uint8Array,
): IdentitySecrets {
  return secretsFromPlaintext(
    decryptBlob(
      privateKeyBundleKey(masterKey),
      bundleAd(LABELS.privateKeyBundle, keys.userId, keys.keyVersion),
      bundle,
    ),
  );
}

/**
 * Encrypts the private keys under the recovery key (`PROTOCOL.md` §5.5).
 *
 * @param recoveryKey 32-byte recovery key of the same version.
 * @param keys Owner and key version.
 * @param secrets Keys to protect.
 * @param nonce Fixed nonce for tests; random by default.
 * @returns The recovery key bundle.
 */
export function sealRecoveryKeyBundle(
  recoveryKey: Uint8Array,
  keys: Pick<PublicKeys, 'userId' | 'keyVersion'>,
  secrets: IdentitySecrets,
  nonce?: Uint8Array,
): Uint8Array {
  return encryptBlob(
    recoveryBundleKey(recoveryKey, keys.userId),
    bundleAd(LABELS.recoveryKeyBundle, keys.userId, keys.keyVersion),
    bundlePlaintext(secrets),
    nonce,
  );
}

/**
 * Opens the recovery key bundle, for recovery or key replacement.
 *
 * @param recoveryKey 32-byte recovery key.
 * @param keys Owner and key version.
 * @param bundle Recovery key bundle.
 * @returns The private keys.
 * @throws {CloakCryptoError} `decryption_failed` for a wrong recovery key or version.
 */
export function openRecoveryKeyBundle(
  recoveryKey: Uint8Array,
  keys: Pick<PublicKeys, 'userId' | 'keyVersion'>,
  bundle: Uint8Array,
): IdentitySecrets {
  return secretsFromPlaintext(
    decryptBlob(
      recoveryBundleKey(recoveryKey, keys.userId),
      bundleAd(LABELS.recoveryKeyBundle, keys.userId, keys.keyVersion),
      bundle,
    ),
  );
}

/**
 * Derives the X25519 public key of an encryption private key.
 *
 * @param encryptionPrivateKey 32-byte X25519 private key.
 * @returns The 32-byte public key.
 */
export function encryptionPublicKey(encryptionPrivateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(encryptionPrivateKey);
}

/**
 * Builds the public keys of a key version from its private keys and recovery key.
 *
 * @param userId Owner.
 * @param keyVersion Key version.
 * @param secrets Private keys of the version.
 * @param recoveryKey Recovery key of the version.
 * @returns The public keys.
 */
export function publicKeysOf(
  userId: string,
  keyVersion: number,
  secrets: Pick<IdentitySecrets, 'encryptionPrivateKey' | 'signingSeed'>,
  recoveryKey: Uint8Array,
): PublicKeys {
  return {
    userId,
    keyVersion,
    cryptoSuite: CRYPTO_SUITE,
    encryptionPublicKey: x25519.getPublicKey(secrets.encryptionPrivateKey),
    signingPublicKey: signingPublicKey(secrets.signingSeed),
    recoverySigningPublicKey: deriveRecoverySigningKey(recoveryKey, userId).publicKey,
  };
}

/**
 * Picks the X25519 private key that opens an envelope sealed to a given key version.
 *
 * @param secrets Private keys of the current version.
 * @param currentVersion Current key version.
 * @param userKeyVersion Key version the envelope was sealed to.
 * @returns The private key, or `undefined` when the bundle no longer carries it.
 */
export function encryptionKeyFor(
  secrets: IdentitySecrets,
  currentVersion: number,
  userKeyVersion: number,
): Uint8Array | undefined {
  if (userKeyVersion === currentVersion) return secrets.encryptionPrivateKey;
  if (userKeyVersion > currentVersion || userKeyVersion < 1) return undefined;
  return secrets.earlierEncryptionKeys[currentVersion - userKeyVersion - 1];
}

/**
 * Creates key version 1 of a new identity (`PROTOCOL.md` §12.1).
 *
 * @param userId Host user registering.
 * @param password Chosen master password.
 * @param passwordHasher Where Argon2id runs; the calling thread by default.
 * @returns The identity; show the secret key and recovery key codes once.
 */
export async function createIdentity(
  userId: string,
  password: string,
  passwordHasher?: PasswordHasher,
): Promise<NewKeyVersion> {
  return newKeyVersion({
    userId,
    password,
    passwordHasher,
    keyVersion: 1,
    previousLocalStateKey: undefined,
    earlierEncryptionKeys: [],
  });
}

/** Inputs of {@link replaceIdentityKeys}. */
export interface ReplaceIdentityKeysOptions {
  /** The current key version. */
  readonly current: PublicKeys;
  /** Its private keys, opened with the recovery key. */
  readonly currentSecrets: IdentitySecrets;
  /** Its recovery key, which signs the new version. */
  readonly currentRecoveryKey: Uint8Array;
  /** New master password. */
  readonly password: string;
  /** Where Argon2id runs; the calling thread by default. */
  readonly passwordHasher?: PasswordHasher | undefined;
}

/**
 * Creates the next key version after a suspected leak (`PROTOCOL.md` §5.6): new key pairs, a new
 * recovery key, a new `localStateKey`, a new secret key and salt, and a statement signed by the new
 * signing key and the current recovery signing key.
 *
 * @param options Current version, its secrets and recovery key, and the new password.
 * @returns The new key version.
 */
export async function replaceIdentityKeys(
  options: ReplaceIdentityKeysOptions,
): Promise<NewKeyVersion> {
  const { current, currentSecrets, currentRecoveryKey, password } = options;
  return newKeyVersion({
    userId: current.userId,
    password,
    passwordHasher: options.passwordHasher,
    keyVersion: current.keyVersion + 1,
    previousLocalStateKey: currentSecrets.localStateKey,
    earlierEncryptionKeys: [
      currentSecrets.encryptionPrivateKey,
      ...currentSecrets.earlierEncryptionKeys,
    ],
    previous: {
      keys: current,
      recoverySigningSeed: deriveRecoverySigningKey(currentRecoveryKey, current.userId).seed,
    },
  });
}

/** Inputs of {@link newKeyVersion}. */
interface NewKeyVersionOptions {
  /** Owner. */
  readonly userId: string;
  /** Master password for the new bundle. */
  readonly password: string;
  /** Where Argon2id runs; the calling thread when absent. */
  readonly passwordHasher: PasswordHasher | undefined;
  /** Version to create. */
  readonly keyVersion: number;
  /** `localStateKey` of the previous version. */
  readonly previousLocalStateKey: Uint8Array | undefined;
  /** Earlier X25519 private keys, newest first. */
  readonly earlierEncryptionKeys: readonly Uint8Array[];
  /** The version followed, with its recovery signing seed; absent for version 1. */
  readonly previous?: { readonly keys: PublicKeys; readonly recoverySigningSeed: Uint8Array };
}

/** Generates a key version with fresh secrets, bundles and its statement. */
async function newKeyVersion(options: NewKeyVersionOptions): Promise<NewKeyVersion> {
  const { userId, password, keyVersion } = options;
  const secrets: IdentitySecrets = {
    encryptionPrivateKey: x25519.utils.randomSecretKey(),
    signingSeed: ed25519.utils.randomSecretKey(),
    localStateKey: randomBytes(32),
    previousLocalStateKey: options.previousLocalStateKey,
    earlierEncryptionKeys: options.earlierEncryptionKeys,
  };
  const secretKey = randomBytes(16);
  const recoveryKey = randomBytes(32);
  const kdf: KdfParams = { salt: randomBytes(16), ...DEFAULT_KDF_COST, parallelism: 1 };
  const keys = publicKeysOf(userId, keyVersion, secrets, recoveryKey);
  const masterKey = await deriveMasterKey({
    password,
    secretKey,
    userId,
    kdf,
    passwordHasher: options.passwordHasher,
  });
  const privateKeyBundle = sealPrivateKeyBundle(masterKey, keys, secrets);
  masterKey.fill(0);
  return {
    keys,
    secrets,
    statement: signKeyStatement(keys, secrets.signingSeed, options.previous),
    secretKey,
    recoveryKey,
    kdf,
    privateKeyBundle,
    recoveryKeyBundle: sealRecoveryKeyBundle(recoveryKey, keys, secrets),
  };
}

/** Bundle plaintext (`PROTOCOL.md` §5.4). */
function bundlePlaintext(secrets: IdentitySecrets): Uint8Array {
  return concatBytes(
    Uint8Array.of(BUNDLE_VERSION),
    requireKey32(secrets.encryptionPrivateKey),
    requireKey32(secrets.signingSeed),
    requireKey32(secrets.localStateKey),
    secrets.previousLocalStateKey === undefined
      ? new Uint8Array(32)
      : requireKey32(secrets.previousLocalStateKey),
    ...secrets.earlierEncryptionKeys.map(requireKey32),
  );
}

/** Parses a bundle plaintext. */
function secretsFromPlaintext(plaintext: Uint8Array): IdentitySecrets {
  if (
    plaintext.length < BUNDLE_BASE_BYTES ||
    (plaintext.length - BUNDLE_BASE_BYTES) % 32 !== 0 ||
    plaintext[0] !== BUNDLE_VERSION
  ) {
    throw new CloakCryptoError('invalid_format', 'Unsupported key bundle');
  }
  const previous = plaintext.slice(97, 129);
  return {
    encryptionPrivateKey: plaintext.slice(1, 33),
    signingSeed: plaintext.slice(33, 65),
    localStateKey: plaintext.slice(65, 97),
    previousLocalStateKey: isAbsent(previous) ? undefined : previous,
    earlierEncryptionKeys: Array.from(
      { length: (plaintext.length - BUNDLE_BASE_BYTES) / 32 },
      (_, index) =>
        plaintext.slice(BUNDLE_BASE_BYTES + index * 32, BUNDLE_BASE_BYTES + (index + 1) * 32),
    ),
  };
}

/** Fails unless a value is 32 bytes; returns it. */
function requireKey32(key: Uint8Array): Uint8Array {
  if (key.length !== 32) throw new CloakCryptoError('invalid_format', 'Keys have 32 bytes');
  return key;
}

/** Fails unless a recovery key has 32 bytes. */
function requireRecoveryKey(recoveryKey: Uint8Array): void {
  if (recoveryKey.length !== 32)
    throw new CloakCryptoError('invalid_format', 'Recovery keys have 32 bytes');
}
