import { sha1 } from '@noble/hashes/legacy.js';

import { CloakCryptoError } from './CloakCryptoError.ts';
import { concatBytes, utf8, uuidBytes, uuidFromBytes } from './bytes.ts';

/**
 * The namespace of Cloak user ids (`PROTOCOL.md` §5.0): UUIDv5 of the URL namespace and
 * `urn:cloak:v1:user`.
 */
export const USER_NAMESPACE = '715ec4b7-23ef-5724-a2a7-6bd5871ab13d';

/** Longest host user id, in UTF-8 bytes. */
export const MAX_HOST_USER_ID_BYTES = 255;

/**
 * Derives a user's Cloak id from the host application's id of them (`PROTOCOL.md` §5.0):
 * `UUIDv5(USER_NAMESPACE, hostUserId)`, lowercase. Signed messages, the log and the API name users
 * by it; the host only ever sees its own ids.
 *
 * @param hostUserId The host's id of the user, exactly as its authentication gives it.
 * @returns The user's Cloak id.
 * @throws {CloakCryptoError} `invalid_format` when the id is empty or longer than 255 bytes.
 */
export function cloakUserId(hostUserId: string): string {
  const name = utf8(hostUserId);
  if (name.length === 0 || name.length > MAX_HOST_USER_ID_BYTES) {
    throw new CloakCryptoError('invalid_format', 'A host user id has 1 to 255 bytes');
  }
  return uuidV5(USER_NAMESPACE, name);
}

/**
 * RFC 9562 §5.5: the UUIDv5 of a name under a namespace, lowercase.
 *
 * @param namespace Namespace UUID.
 * @param name Name bytes.
 * @returns The UUID.
 */
export function uuidV5(namespace: string, name: Uint8Array): string {
  const bytes = sha1(concatBytes(uuidBytes(namespace), name)).slice(0, 16);
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x50;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  return uuidFromBytes(bytes);
}
