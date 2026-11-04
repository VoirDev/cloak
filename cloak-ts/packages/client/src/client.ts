import {
  cloakUserId,
  createIdentity,
  CRYPTO_SUITE,
  DEFAULT_KDF_COST,
  deriveMasterKey,
  encryptionPublicKey,
  equalBytes,
  fromBase64Url,
  fromRecoveryKeyCode,
  fromSecretKeyCode,
  isCloakCryptoError,
  openPrivateKeyBundle,
  openRecoveryKeyBundle,
  randomBytes,
  replaceIdentityKeys,
  requireKdfParams,
  sealPrivateKeyBundle,
  signingPublicKey,
  toBase64Url,
  toRecoveryKeyCode,
  toSecretKeyCode,
  wipeIdentitySecrets,
  credentialsMessage,
  signIdentityStatement,
  type IdentitySecrets,
  type KdfParams,
  type PasswordHasher,
  type PublicKeys,
} from '@voirdev/cloak-crypto';

import { CloakApiError } from './CloakApiError.ts';
import { CloakKeyChangedError } from './CloakKeyChangedError.ts';
import { CloakSecretKeyMissingError } from './CloakSecretKeyMissingError.ts';
import { CloakUnlockError, type CloakUnlockErrorReason } from './CloakUnlockError.ts';
import { body, createApi, type CloakHttpOptions, type Schemas } from './api.ts';
import { createKeyring } from './keyring.ts';
import { createSession, type CloakSession } from './session.ts';
import { createMemoryStorage, type CloakStorage } from './storage/CloakStorage.ts';
import { openLocalState, secretKeyRecord, userRecords } from './storage/localState.ts';
import { fromWireKdf, fromWireKeys, toWireKdf } from './wire.ts';

/** Options of {@link createCloakClient}. */
export interface CloakClientOptions extends CloakHttpOptions {
  /**
   * Where pins, verified vault heads, section marks, this device's own writes and, on request,
   * the secret key are kept (`PROTOCOL.md` §15). Defaults to memory, which forgets them on
   * reload: rollbacks and key changes then go unnoticed across reloads, so persist it in
   * production.
   */
  readonly storage?: CloakStorage | undefined;
  /**
   * Where Argon2id runs when a password is set or checked. By default it runs in the calling
   * thread, which freezes a browser page for a second or more; pass
   * {@link createWorkerPasswordHasher} to run it in a Web Worker instead.
   */
  readonly passwordHasher?: PasswordHasher | undefined;
}

/** Whether to keep the secret key on this device, so later unlocks need only the password. */
export interface RememberSecretKeyOption {
  /**
   * Keep the secret key in {@link CloakClientOptions.storage}. It is stored as is: anyone who
   * can read the store then needs only the password. Off by default.
   */
  readonly rememberSecretKey?: boolean | undefined;
}

/** A session together with the codes to show the user exactly once. */
export interface CredentialsResult {
  /** The unlocked session. */
  readonly session: CloakSession;
  /** Secret key code (`CS1-…`); every new device needs it. */
  readonly secretKeyCode: string;
  /** Recovery key code (`CR1-…`) for the printable kit. */
  readonly recoveryKeyCode: string;
}

/** The result of a key replacement. */
export interface KeyReplacementResult extends CredentialsResult {
  /** Vaults where recording the new keys failed; retry with `recordKeyReplacement`. */
  readonly failedVaults: readonly string[];
  /**
   * Per vault, `seq` of log entries signed with the replaced keys that this device did not sign;
   * only vaults that have any. Show them for review (`PROTOCOL.md` §5.6).
   */
  readonly unrecognizedEntries: Readonly<Record<string, readonly number[]>>;
}

/** Entry point of a Cloak client. */
export interface CloakClient {
  /**
   * Registers the signed-in host user, named by the host's own id of them (`userId`), which the
   * server's authentication must give for the same request. Show both codes once and ask the user
   * to save them.
   */
  register(
    options: { readonly userId: string; readonly password: string } & RememberSecretKeyOption,
  ): Promise<CredentialsResult>;

  /**
   * Unlocks the signed-in user's identity on this device.
   *
   * @throws {CloakSecretKeyMissingError} when no code was given and none is remembered.
   * @throws {CloakUnlockError} `wrong_credentials` for a wrong password or secret key.
   * @throws {CloakCryptoError} `invalid_kdf` when the server serves KDF parameters outside the
   *   protocol's bounds; `bad_code` for a mistyped secret key code.
   */
  unlock(
    options: {
      readonly password: string;
      readonly secretKeyCode?: string | undefined;
    } & RememberSecretKeyOption,
  ): Promise<CloakSession>;

  /**
   * Recovers a lost password or secret key with the recovery key (`PROTOCOL.md` §5.5): sets a new
   * password and a new secret key. Keys and the recovery key stay.
   *
   * @throws {CloakUnlockError} `wrong_recovery_key` for a recovery key that is not the user's.
   */
  recover(
    options: {
      readonly recoveryKeyCode: string;
      readonly newPassword: string;
    } & RememberSecretKeyOption,
  ): Promise<CredentialsResult>;

  /**
   * Changes the master password; keys, the secret key and the recovery key stay.
   *
   * @throws {CloakUnlockError} `wrong_credentials` for a wrong password or secret key.
   */
  changePassword(options: {
    readonly password: string;
    readonly newPassword: string;
    readonly secretKeyCode?: string | undefined;
  }): Promise<void>;

  /**
   * Replaces identity keys that may have leaked (`PROTOCOL.md` §5.6), with the recovery key: new
   * keys, a new recovery key, secret key and password, recorded in every vault. Admins should
   * then rotate those vaults.
   *
   * @throws {CloakUnlockError} `wrong_recovery_key` for a recovery key that is not the user's.
   */
  replaceKeys(
    options: {
      readonly recoveryKeyCode: string;
      readonly newPassword: string;
    } & RememberSecretKeyOption,
  ): Promise<KeyReplacementResult>;

  /** Tells whether this device remembers a user's secret key, by host user id. */
  remembersSecretKey(hostUserId: string): Promise<boolean>;

  /** Forgets a user's remembered secret key, by host user id. */
  forgetSecretKey(hostUserId: string): Promise<void>;

  /**
   * Drops everything this device keeps for a user, by host user id: the remembered secret key,
   * pins, verified heads, snapshots and marks (`PROTOCOL.md` §15). Use it to sign a user out of
   * the device for good. Afterwards the device trusts the server as a new device would: it no
   * longer notices a rollback to anything older than what it reads next.
   */
  forgetUser(hostUserId: string): Promise<void>;
}

/**
 * Creates a Cloak client for one host application.
 *
 * @param options How to reach `/cloak/v1` and where to keep local state.
 * @returns The client.
 */
export function createCloakClient(options: CloakClientOptions): CloakClient {
  const api = createApi(options);
  const storage = options.storage ?? createMemoryStorage();
  const { passwordHasher } = options;

  /** Opens a session for unlocked keys. */
  function sessionFor(
    keys: PublicKeys,
    secrets: IdentitySecrets,
    hostUserId: string,
  ): CloakSession {
    const local = openLocalState(
      storage,
      keys.userId,
      secrets.localStateKey,
      secrets.previousLocalStateKey,
    );
    const keyring = createKeyring(api, local, keys, hostUserId);
    return createSession({
      api,
      local,
      keyring,
      self: { userId: keys.userId, hostUserId, keyVersion: keys.keyVersion, secrets, keys },
    });
  }

  /**
   * Reads the signed-in user's identity. The host user id the server names must derive the
   * identity's Cloak id (`PROTOCOL.md` §5.0).
   */
  async function currentIdentity() {
    const identity = await body(api.GET('/identity'));
    const keys = fromWireKeys(identity.keys);
    if (!derives(identity.hostUserId, keys.userId)) throw new CloakApiError(0, undefined);
    return { identity, keys, hostUserId: identity.hostUserId };
  }

  /** Keeps a secret key when asked. */
  async function remember(
    userId: string,
    secretKey: Uint8Array,
    wanted: boolean | undefined,
  ): Promise<void> {
    if (wanted === true) await storage.set(secretKeyRecord(userId), secretKey);
  }

  /** Checks that opened private keys are the ones the served public keys describe. */
  function requireOwnKeys(keys: PublicKeys, secrets: IdentitySecrets, hostUserId: string): void {
    const matches =
      equalBytes(encryptionPublicKey(secrets.encryptionPrivateKey), keys.encryptionPublicKey) &&
      equalBytes(signingPublicKey(secrets.signingSeed), keys.signingPublicKey);
    if (!matches) throw new CloakKeyChangedError(hostUserId, keys.keyVersion, undefined, undefined);
  }

  /** Opens the signed-in user's private keys with the password and secret key. */
  async function openIdentity(password: string, secretKeyCode: string | undefined) {
    const { identity, keys, hostUserId } = await currentIdentity();
    const secretKey =
      secretKeyCode === undefined
        ? await storage.get(secretKeyRecord(keys.userId))
        : fromSecretKeyCode(secretKeyCode);
    if (secretKey === undefined) throw new CloakSecretKeyMissingError(hostUserId);
    const kdf = fromWireKdf(identity.kdf);
    requireKdfParams(kdf);
    const masterKey = await deriveMasterKey({
      password,
      secretKey,
      userId: keys.userId,
      kdf,
      passwordHasher,
    });
    const secrets = opening('wrong_credentials', () =>
      openPrivateKeyBundle(masterKey, keys, fromBase64Url(identity.privateKeyBundle)),
    );
    masterKey.fill(0);
    requireOwnKeys(keys, secrets, hostUserId);
    return { identity, keys, hostUserId, secretKey, secrets };
  }

  /** Seals private keys under a new password and secret key. */
  /**
   * Seals private keys under a new password and secret key, as the request that stores them:
   * signed with the current signing key for the credentials version it creates (`PROTOCOL.md`
   * §5.4), so the host's session alone cannot replace a bundle.
   */
  async function newCredentials(
    keys: PublicKeys,
    secrets: IdentitySecrets,
    password: string,
    secretKey: Uint8Array,
    currentVersion: number,
  ): Promise<Schemas['UpdateCredentialsRequest']> {
    const kdf: KdfParams = { salt: randomBytes(16), ...DEFAULT_KDF_COST, parallelism: 1 };
    const masterKey = await deriveMasterKey({
      password,
      secretKey,
      userId: keys.userId,
      kdf,
      passwordHasher,
    });
    const privateKeyBundle = sealPrivateKeyBundle(masterKey, keys, secrets);
    masterKey.fill(0);
    const statement = credentialsMessage({
      userId: keys.userId,
      keyVersion: keys.keyVersion,
      credentialsVersion: currentVersion + 1,
      privateKeyBundle,
      kdf,
    });
    return {
      expectedCredentialsVersion: currentVersion,
      kdf: toWireKdf(kdf),
      privateKeyBundle: toBase64Url(privateKeyBundle),
      signature: toBase64Url(signIdentityStatement(statement, secrets.signingSeed)),
    };
  }

  /** Reads the ids of every vault the server lists for the user, accepted or not. */
  async function allVaultIds(): Promise<string[]> {
    // Accepted or not: a key replacement must be recorded wherever the user is a member, and
    // acceptance is only the server's listing (`PROTOCOL.md` §12.4).
    const ids: string[] = [];
    for (const pending of [false, true]) {
      let cursor: string | undefined;
      do {
        const page: Schemas['VaultPage'] = await body(
          api.GET('/vaults', {
            params: {
              query: { limit: 100, pending, ...(cursor === undefined ? {} : { cursor }) },
            },
          }),
        );
        ids.push(...page.items.map((vault) => vault.id));
        cursor = page.nextCursor;
      } while (cursor !== undefined);
    }
    return [...new Set(ids)];
  }

  return {
    async register({ userId: hostUserId, password, rememberSecretKey }) {
      const identity = await createIdentity(cloakUserId(hostUserId), password, passwordHasher);
      await body(
        api.POST('/identity', {
          body: {
            cryptoSuite: CRYPTO_SUITE,
            encryptionPublicKey: toBase64Url(identity.keys.encryptionPublicKey),
            signingPublicKey: toBase64Url(identity.keys.signingPublicKey),
            recoverySigningPublicKey: toBase64Url(identity.keys.recoverySigningPublicKey),
            signature: toBase64Url(identity.statement.signature),
            kdf: toWireKdf(identity.kdf),
            privateKeyBundle: toBase64Url(identity.privateKeyBundle),
            recoveryKeyBundle: toBase64Url(identity.recoveryKeyBundle),
          },
        }),
      );
      await remember(identity.keys.userId, identity.secretKey, rememberSecretKey);
      return {
        session: sessionFor(identity.keys, identity.secrets, hostUserId),
        secretKeyCode: toSecretKeyCode(identity.secretKey),
        recoveryKeyCode: toRecoveryKeyCode(identity.recoveryKey),
      };
    },

    async unlock({ password, secretKeyCode, rememberSecretKey }) {
      const { keys, hostUserId, secretKey, secrets } = await openIdentity(password, secretKeyCode);
      if (secretKeyCode !== undefined) await remember(keys.userId, secretKey, rememberSecretKey);
      return sessionFor(keys, secrets, hostUserId);
    },

    async changePassword({ password, newPassword, secretKeyCode }) {
      const { identity, keys, secretKey, secrets } = await openIdentity(password, secretKeyCode);
      const request = await newCredentials(
        keys,
        secrets,
        newPassword,
        secretKey,
        identity.credentialsVersion,
      );
      // No session holds these keys; nothing needs them past sealing and signing the new bundle.
      wipeIdentitySecrets(secrets);
      await body(api.PUT('/identity/credentials', { body: request }));
    },

    async recover({ recoveryKeyCode, newPassword, rememberSecretKey }) {
      const { identity, keys, hostUserId } = await currentIdentity();
      const recoveryKey = fromRecoveryKeyCode(recoveryKeyCode);
      const secrets = opening('wrong_recovery_key', () =>
        openRecoveryKeyBundle(recoveryKey, keys, fromBase64Url(identity.recoveryKeyBundle)),
      );
      requireOwnKeys(keys, secrets, hostUserId);
      const secretKey = randomBytes(16);
      const request = await newCredentials(
        keys,
        secrets,
        newPassword,
        secretKey,
        identity.credentialsVersion,
      );
      await body(api.PUT('/identity/credentials', { body: request }));
      await storage.delete(secretKeyRecord(keys.userId));
      await remember(keys.userId, secretKey, rememberSecretKey);
      return {
        session: sessionFor(keys, secrets, hostUserId),
        secretKeyCode: toSecretKeyCode(secretKey),
        recoveryKeyCode,
      };
    },

    async replaceKeys({ recoveryKeyCode, newPassword, rememberSecretKey }) {
      const { identity, keys: current, hostUserId } = await currentIdentity();
      const recoveryKey = fromRecoveryKeyCode(recoveryKeyCode);
      const currentSecrets = opening('wrong_recovery_key', () =>
        openRecoveryKeyBundle(recoveryKey, current, fromBase64Url(identity.recoveryKeyBundle)),
      );
      requireOwnKeys(current, currentSecrets, hostUserId);
      const next = await replaceIdentityKeys({
        current,
        currentSecrets,
        currentRecoveryKey: recoveryKey,
        password: newPassword,
        passwordHasher,
      });
      await body(
        api.PUT('/identity/keys', {
          body: {
            expectedKeyVersion: current.keyVersion,
            encryptionPublicKey: toBase64Url(next.keys.encryptionPublicKey),
            signingPublicKey: toBase64Url(next.keys.signingPublicKey),
            recoverySigningPublicKey: toBase64Url(next.keys.recoverySigningPublicKey),
            signature: toBase64Url(next.statement.signature),
            recoverySignature: toBase64Url(next.statement.recoverySignature ?? new Uint8Array()),
            kdf: toWireKdf(next.kdf),
            privateKeyBundle: toBase64Url(next.privateKeyBundle),
            recoveryKeyBundle: toBase64Url(next.recoveryKeyBundle),
          },
        }),
      );
      await storage.delete(secretKeyRecord(current.userId));
      await remember(current.userId, next.secretKey, rememberSecretKey);
      const session = sessionFor(next.keys, next.secrets, hostUserId);
      const failedVaults: string[] = [];
      const unrecognizedEntries: Record<string, readonly number[]> = {};
      for (const vaultId of await allVaultIds()) {
        try {
          const recorded = await session.recordKeyReplacement(vaultId);
          if (recorded.unrecognizedEntries.length > 0) {
            unrecognizedEntries[vaultId] = recorded.unrecognizedEntries;
          }
        } catch {
          failedVaults.push(vaultId);
        }
      }
      return {
        session,
        secretKeyCode: toSecretKeyCode(next.secretKey),
        recoveryKeyCode: toRecoveryKeyCode(next.recoveryKey),
        failedVaults,
        unrecognizedEntries,
      };
    },

    async remembersSecretKey(hostUserId) {
      return (await storage.get(secretKeyRecord(cloakUserId(hostUserId)))) !== undefined;
    },

    forgetSecretKey(hostUserId) {
      return storage.delete(secretKeyRecord(cloakUserId(hostUserId)));
    },

    forgetUser(hostUserId) {
      return storage.deletePrefix(userRecords(cloakUserId(hostUserId)));
    },
  };
}

/**
 * Opens a bundle, turning the failed tag of wrong secrets into a {@link CloakUnlockError}; any
 * other failure, such as a malformed bundle, stays as it is.
 */
function opening(reason: CloakUnlockErrorReason, open: () => IdentitySecrets): IdentitySecrets {
  try {
    return open();
  } catch (error: unknown) {
    if (isCloakCryptoError(error) && error.code === 'decryption_failed')
      throw new CloakUnlockError(reason, { cause: error });
    throw error;
  }
}

/** Whether a host user id derives a Cloak id (`PROTOCOL.md` §5.0). */
function derives(hostUserId: string, userId: string): boolean {
  try {
    return cloakUserId(hostUserId) === userId;
  } catch {
    return false;
  }
}
