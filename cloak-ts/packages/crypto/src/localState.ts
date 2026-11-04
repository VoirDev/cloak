import { decryptBlob, encryptBlob } from './blobs.ts';
import { uuidBytes } from './bytes.ts';
import { Canonical } from './canonical.ts';
import { hkdf } from './kdf.ts';
import { LABELS } from './labels.ts';

/**
 * Derives the key that encrypts a user's local client state: pins, vault snapshots, section marks
 * and own writes (`PROTOCOL.md` §15).
 *
 * @param localStateKey The 32-byte `localStateKey` from the private key bundle.
 * @param userId Owner of the state.
 * @returns `HKDF(localStateKey, salt = userId, "cloak/v1/local-state")`.
 */
export function deriveLocalRecordKey(localStateKey: Uint8Array, userId: string): Uint8Array {
  return hkdf(localStateKey, uuidBytes(userId), LABELS.localState);
}

/**
 * Builds the associated data of a local record: the label and the record's name.
 *
 * @param name Name the record is stored under.
 * @returns Canonical associated data.
 */
export function localRecordAd(name: string): Uint8Array {
  return Canonical.of(LABELS.localState).str(name).build();
}

/**
 * Encrypts one local state record bound to its name, so local storage can neither read, change
 * nor move it.
 *
 * @param key Key from {@link deriveLocalRecordKey}.
 * @param name Name the record is stored under.
 * @param plaintext Record content.
 * @param nonce Fixed nonce for tests; random by default.
 * @returns The encrypted blob.
 */
export function sealLocalRecord(
  key: Uint8Array,
  name: string,
  plaintext: Uint8Array,
  nonce?: Uint8Array,
): Uint8Array {
  return encryptBlob(key, localRecordAd(name), plaintext, nonce);
}

/**
 * Opens a record sealed by {@link sealLocalRecord}.
 *
 * @param key Key from {@link deriveLocalRecordKey}.
 * @param name Name the record was read from.
 * @param blob Stored blob.
 * @returns The record content.
 * @throws {CloakCryptoError} `decryption_failed` when the record was changed, moved or sealed
 *   with another key; `invalid_format` for a malformed blob.
 */
export function openLocalRecord(key: Uint8Array, name: string, blob: Uint8Array): Uint8Array {
  return decryptBlob(key, localRecordAd(name), blob);
}
