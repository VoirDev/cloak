import { concatBytes, isUuid, isWellFormed, utf8, uuidBytes } from './bytes.ts';
import type { Label } from './labels.ts';

/** 16 zero bytes: the nil UUID, an absent id (`PROTOCOL.md` §3). */
const NIL_UUID = new Uint8Array(16);

/** 32 zero bytes: an absent key or digest (`PROTOCOL.md` §3). */
const ZERO32 = new Uint8Array(32);

/** Most UTF-8 bytes of a `str` field: its length is a u16. */
const MAX_STR_BYTES = 0xffff;

/**
 * Tells whether a value fits a `u8` field (`PROTOCOL.md` §3).
 *
 * @param value Value to test.
 * @returns Whether it is an integer in `0..255`.
 */
export function isU8(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 0xff;
}

/**
 * Tells whether a value fits a `flag` field (`PROTOCOL.md` §3).
 *
 * @param value Value to test.
 * @returns Whether it is a boolean.
 */
export function isFlag(value: unknown): value is boolean {
  return typeof value === 'boolean';
}

/**
 * Tells whether a value fits a `u32` field (`PROTOCOL.md` §3).
 *
 * @param value Value to test.
 * @returns Whether it is an integer in `0..2^32-1`.
 */
export function isU32(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

/**
 * Tells whether a number fits a `u64` field (`PROTOCOL.md` §3), as the protocol's numeric fields
 * hold one: `seq`, `dataVersion` and `logSeq` are JavaScript numbers, so a safe integer.
 *
 * @param value Value to test.
 * @returns Whether it is a safe integer of at least 0.
 */
export function isU64(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/**
 * Tells whether a value fits a `str` field (`PROTOCOL.md` §3): well-formed Unicode of at most
 * 65 535 UTF-8 bytes. A lone surrogate has no UTF-8 encoding; `TextEncoder` would write U+FFFD
 * for it and so give two strings the same bytes.
 *
 * @param value Value to test.
 * @returns Whether it is such a string.
 */
export function isStr(value: unknown): value is string {
  return typeof value === 'string' && isWellFormed(value) && utf8(value).length <= MAX_STR_BYTES;
}

/**
 * Tells whether a value fits a `uuid` field that may be absent (`PROTOCOL.md` §3).
 *
 * @param value Value to test.
 * @returns Whether it is `undefined` or a lowercase UUID.
 */
export function isOptionalUuid(value: unknown): value is string | undefined {
  return value === undefined || isUuid(value);
}

/**
 * Tells whether a value fits a `key32` or `digest32` field (`PROTOCOL.md` §3).
 *
 * @param value Value to test.
 * @returns Whether it is exactly 32 bytes.
 */
export function isBytes32(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array && value.length === 32;
}

/**
 * Tells whether a value fits a `key32` or `digest32` field that may be absent (`PROTOCOL.md` §3).
 *
 * @param value Value to test.
 * @returns Whether it is `undefined` or exactly 32 bytes.
 */
export function isOptionalBytes32(value: unknown): value is Uint8Array | undefined {
  return value === undefined || isBytes32(value);
}

/**
 * Builder of canonical messages (`PROTOCOL.md` §3): typed fields concatenated without separators.
 * Associated data, signed messages, hashes and fingerprints are built with it, so every client and
 * the server produce the same bytes. JSON is never signed.
 */
export class Canonical {
  /** Encoded fields so far. */
  readonly #parts: Uint8Array[] = [];

  /**
   * Starts a message with its domain label.
   *
   * @param value The message's label.
   * @returns A builder holding the label.
   */
  static of(value: Label): Canonical {
    return new Canonical().str(value);
  }

  /**
   * Appends a string as a 2-byte big-endian length and its UTF-8 bytes, without normalizing it.
   *
   * @param value Well-formed string of at most 65 535 UTF-8 bytes.
   * @returns This builder.
   * @throws {RangeError} when the string has a lone surrogate or is too long.
   */
  str(value: string): this {
    if (!isWellFormed(value)) throw new RangeError('Canonical strings are well-formed Unicode');
    const bytes = utf8(value);
    if (bytes.length > MAX_STR_BYTES)
      throw new RangeError('Canonical strings hold at most 65535 bytes');
    return this.#push(Uint8Array.of(bytes.length >> 8, bytes.length & 0xff), bytes);
  }

  /**
   * Appends one unsigned byte.
   *
   * @param value Integer in `0..255`.
   * @returns This builder.
   */
  u8(value: number): this {
    if (!isU8(value)) throw new RangeError('u8 out of range');
    return this.#push(Uint8Array.of(value));
  }

  /**
   * Appends a flag: one byte, 0 or 1.
   *
   * @param value The flag.
   * @returns This builder.
   */
  flag(value: boolean): this {
    if (!isFlag(value)) throw new RangeError('A flag needs a boolean');
    return this.#push(Uint8Array.of(value ? 1 : 0));
  }

  /**
   * Appends an unsigned 32-bit big-endian integer.
   *
   * @param value Integer in `0..2^32-1`.
   * @returns This builder.
   */
  u32(value: number): this {
    if (!isU32(value)) throw new RangeError('u32 out of range');
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value);
    return this.#push(bytes);
  }

  /**
   * Appends an unsigned 64-bit big-endian integer.
   *
   * @param value Integer in `0..2^64-1`; a `bigint` covers the whole range.
   * @returns This builder.
   */
  u64(value: number | bigint): this {
    const fits =
      typeof value === 'bigint' ? value >= 0n && value <= 0xffffffffffffffffn : isU64(value);
    if (!fits) throw new RangeError('u64 out of range');
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value));
    return this.#push(bytes);
  }

  /**
   * Appends a UUID as its 16 bytes, or the nil UUID when absent.
   *
   * @param value Hyphenated UUID, or `undefined`.
   * @returns This builder.
   */
  uuid(value: string | undefined): this {
    return this.#push(value === undefined ? NIL_UUID : uuidBytes(value));
  }

  /**
   * Appends exactly 32 raw bytes, such as a public key, or 32 zero bytes when absent.
   *
   * @param value 32 bytes, or `undefined`.
   * @returns This builder.
   */
  key32(value: Uint8Array | undefined): this {
    return this.#push32(value);
  }

  /**
   * Appends a 32-byte digest computed elsewhere, such as a previous entry's hash, or 32 zero bytes
   * when absent.
   *
   * @param value 32 bytes, or `undefined`.
   * @returns This builder.
   */
  digest32(value: Uint8Array | undefined): this {
    return this.#push32(value);
  }

  /**
   * Returns the message.
   *
   * @returns The canonical bytes.
   */
  build(): Uint8Array {
    return concatBytes(...this.#parts);
  }

  /** Appends a 32-byte value or its absence. */
  #push32(value: Uint8Array | undefined): this {
    if (value === undefined) return this.#push(ZERO32);
    if (!isBytes32(value)) throw new RangeError('A 32-byte field needs 32 bytes');
    return this.#push(value);
  }

  /** Appends encoded parts. */
  #push(...parts: readonly Uint8Array[]): this {
    this.#parts.push(...parts);
    return this;
  }
}
