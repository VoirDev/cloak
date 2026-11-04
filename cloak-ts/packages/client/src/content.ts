/** Encoder of section content. */
const ENCODER = new TextEncoder();

/** Strict UTF-8 decoder of section content. */
const DECODER = new TextDecoder('utf-8', { fatal: true });

/**
 * Serializes section content as UTF-8 JSON, the client's default content format.
 *
 * @param content JSON-serializable value.
 * @returns Bytes to encrypt.
 */
export function encodeContent(content: unknown): Uint8Array {
  return ENCODER.encode(JSON.stringify(content));
}

/**
 * Parses decrypted section content. The result is `unknown`: whoever wrote the section decided
 * its shape, so callers validate it, for example with a schema.
 *
 * @param bytes Decrypted bytes.
 * @returns The JSON value.
 */
export function decodeContent(bytes: Uint8Array): unknown {
  return JSON.parse(DECODER.decode(bytes)) as unknown;
}
