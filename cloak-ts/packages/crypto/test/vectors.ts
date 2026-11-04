import { readFileSync } from 'node:fs';

/** A JSON object read from a vector file. */
export type Json = Readonly<Record<string, unknown>>;

/** Directory of the shared protocol vectors, relative to this file. */
const VECTORS = new URL('../../../../cloak-protocol/test-vectors/v1/', import.meta.url);

/**
 * Reads one vector file.
 *
 * @param file File name, such as `aead.json`.
 * @returns The parsed object.
 */
export function vectors(file: string): Json {
  return object(JSON.parse(readFileSync(new URL(file, VECTORS), 'utf8')));
}

/** Narrows a value to a JSON object. */
export function object(value: unknown): Json {
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    throw new TypeError('Expected an object');
  return value as Json;
}

/** Reads an array of objects. */
export function objects(json: Json, key: string): readonly Json[] {
  const value = json[key];
  if (!Array.isArray(value)) throw new TypeError(`Expected an array at ${key}`);
  return value.map(object);
}

/** Reads a string. */
export function text(json: Json, key: string): string {
  const value = json[key];
  if (typeof value !== 'string') throw new TypeError(`Expected a string at ${key}`);
  return value;
}

/** Reads a number. */
export function num(json: Json, key: string): number {
  const value = json[key];
  if (typeof value !== 'number') throw new TypeError(`Expected a number at ${key}`);
  return value;
}

/** Reads a hex string as bytes. */
export function hex(json: Json, key: string): Uint8Array {
  return fromHex(text(json, key));
}

/** Decodes hex. */
export function fromHex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g) ?? [], (pair) => parseInt(pair, 16));
}

/** Encodes hex. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** Reads an optional hex string as bytes. */
export function optionalHex(json: Json, key: string): Uint8Array | undefined {
  return json[key] === undefined ? undefined : hex(json, key);
}

/** Reads an optional string. */
export function optionalText(json: Json, key: string): string | undefined {
  return json[key] === undefined ? undefined : text(json, key);
}

/** Reads an optional number. */
export function optionalNum(json: Json, key: string): number | undefined {
  return json[key] === undefined ? undefined : num(json, key);
}

/** Reads a nested object. */
export function child(json: Json, key: string): Json {
  return object(json[key]);
}

/** Encodes text as UTF-8. */
export function utf8Of(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}
