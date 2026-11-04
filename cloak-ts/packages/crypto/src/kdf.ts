import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { utf8 } from './bytes.ts';
import type { Label } from './labels.ts';

/**
 * HKDF-SHA256 with a protocol label as info (`PROTOCOL.md` §2).
 *
 * @param ikm Input keying material.
 * @param salt Salt; empty means none.
 * @param label Purpose of the derived key.
 * @param length Output size in bytes.
 * @returns Derived bytes.
 */
export function hkdf(ikm: Uint8Array, salt: Uint8Array, label: Label, length = 32): Uint8Array {
  return nobleHkdf(sha256, ikm, salt, utf8(label), length);
}
