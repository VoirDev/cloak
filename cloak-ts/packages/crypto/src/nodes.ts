import { CloakCryptoError } from './CloakCryptoError.ts';
import { utf8 } from './bytes.ts';
import { Canonical } from './canonical.ts';
import { LABELS } from './labels.ts';
import { uuidV5 } from './userIds.ts';

/** Longest node key, in UTF-8 bytes. */
export const MAX_NODE_KEY_BYTES = 255;

/** A section name (`PROTOCOL.md` §8.1). */
const SECTION_NAME = /^[a-z][a-z0-9_]{0,63}$/;

/** Who created a node, where it lives and the application's key for it (`PROTOCOL.md` §8.1). */
export interface NodeOrigin {
  /** The node's owner, who created it. */
  readonly ownerUserId: string;
  /** The node's home vault. */
  readonly homeVaultId: string;
  /** The application's key for the node, such as the id of the record it holds secrets for. */
  readonly nodeKey: string;
}

/**
 * Derives a node's id (`PROTOCOL.md` §8.1):
 * `UUIDv5(ownerUserId, label "cloak/v1/node" ‖ uuid homeVaultId ‖ str nodeKey)`. Every write carries
 * the three, so every reader knows a node's owner and home from its id alone.
 *
 * @param origin Owner, home vault and key.
 * @returns The node id.
 * @throws {CloakCryptoError} `invalid_format` for a key that is empty or longer than 255 bytes.
 */
export function nodeIdOf(origin: NodeOrigin): string {
  if (!isValidNodeKey(origin.nodeKey))
    throw new CloakCryptoError(
      'invalid_format',
      'A node key is well-formed UTF-8 of 1 to 255 bytes',
    );
  return uuidV5(
    origin.ownerUserId,
    Canonical.of(LABELS.node).uuid(origin.homeVaultId).str(origin.nodeKey).build(),
  );
}

/**
 * Whether a node key is 1 to 255 bytes of well-formed UTF-8 (`PROTOCOL.md` §7.7): a string with a
 * lone surrogate has no UTF-8 form, and encoding would silently replace it.
 *
 * @param nodeKey The key.
 * @returns Whether it is valid.
 */
export function isValidNodeKey(nodeKey: string): boolean {
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(nodeKey))
    return false;
  const length = utf8(nodeKey).length;
  return length >= 1 && length <= MAX_NODE_KEY_BYTES;
}

/**
 * Whether a node id derives from an origin; any malformed origin derives nothing.
 *
 * @param nodeId Node id as claimed.
 * @param origin Owner, home vault and key as claimed.
 * @returns Whether they agree.
 */
export function derivesNode(nodeId: string, origin: NodeOrigin): boolean {
  try {
    return nodeIdOf(origin) === nodeId;
  } catch {
    return false;
  }
}

/** The names a node entry covers (`PROTOCOL.md` §7.1): every one, or a list. */
export type SectionScope = '*' | readonly string[];

/**
 * Reads a node entry's `sections`: `*`, or names in ascending byte order, comma-joined, without
 * repeats.
 *
 * @param sections The field.
 * @returns The scope, or `undefined` when the field is malformed.
 */
export function parseSectionScope(sections: string | undefined): SectionScope | undefined {
  if (sections === '*') return '*';
  if (sections === undefined || sections === '') return undefined;
  const names = sections.split(',');
  // Names are ASCII, so comparing strings compares their UTF-8 bytes.
  const ordered = names.every(
    (name, index) => SECTION_NAME.test(name) && (index === 0 || (names[index - 1] ?? '') < name),
  );
  return ordered ? names : undefined;
}

/**
 * Writes a scope as a node entry's `sections`.
 *
 * @param scope Every name, or a list in any order.
 * @returns `*`, or the names sorted, without repeats, comma-joined.
 */
export function formatSectionScope(scope: SectionScope): string {
  return scope === '*' ? '*' : [...new Set(scope)].sort().join(',');
}
