import { CloakCryptoError } from './CloakCryptoError.ts';

/** Padding block of section content (`PROTOCOL.md` §8.1). */
export const PADDING_BLOCK = 256;

/**
 * Pads content with ISO/IEC 7816-4 to a multiple of {@link PADDING_BLOCK}: `0x80`, then zeros.
 * Hides the exact size of the content from the server.
 *
 * @param content Content to pad.
 * @returns Padded bytes, at least one block long.
 */
export function pad(content: Uint8Array): Uint8Array {
  const padded = new Uint8Array((Math.floor(content.length / PADDING_BLOCK) + 1) * PADDING_BLOCK);
  padded.set(content);
  padded[content.length] = 0x80;
  return padded;
}

/**
 * Removes {@link pad} padding.
 *
 * @param padded Padded bytes.
 * @returns The original content.
 * @throws {CloakCryptoError} `bad_padding` when the bytes are not padded that way.
 */
export function unpad(padded: Uint8Array): Uint8Array {
  if (padded.length === 0 || padded.length % PADDING_BLOCK !== 0) {
    throw new CloakCryptoError('bad_padding', 'Content is not a whole number of blocks');
  }
  let end = padded.length - 1;
  while (end > 0 && padded[end] === 0) end -= 1;
  if (padded[end] !== 0x80 || padded.length - end > PADDING_BLOCK) {
    throw new CloakCryptoError('bad_padding', 'Content is not padded');
  }
  return padded.slice(0, end);
}
