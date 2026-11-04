import {
  equalBytes,
  fromBase64Url,
  sectionCiphertextHash,
  toBase64Url,
  type CheckpointLeaf,
  type KdfParams,
  type LeafProof,
  type KeyStatement,
  type LogEntry,
  type LogEntryFields,
  type PublicKeys,
  type SectionHeader,
  type SectionWrite,
  type SectionWriteFields,
} from '@voirdev/cloak-crypto';

import * as z from 'zod';

import { CloakApiError } from './CloakApiError.ts';
import type { Schemas } from './api.ts';

/** A lowercase canonical UUID: the only spelling ids are compared and stored in. */
const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

/** Base64url without padding. */
const base64 = z.string().regex(/^[A-Za-z0-9_-]*$/);

/** A positive integer the API counts with. */
const positive = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);

/** A role. */
const role = z.enum(['viewer', 'editor', 'admin', 'owner']);

/** Runtime shape of a stored log entry. */
const logEntrySchema = z.object({
  seq: positive,
  kind: z.enum([
    'vault_created',
    'member_added',
    'member_role_set',
    'member_removed',
    'member_keys_replaced',
    'key_rotated',
    'node_created',
    'node_shared',
    'node_unshared',
    'vault_deleted',
  ]),
  subjectUserId: uuid.optional(),
  role: role.optional(),
  keyVersion: positive,
  subjectKeys: base64.optional(),
  subjectKeyVersion: positive.optional(),
  keyCommitment: base64.optional(),
  checkpoint: base64.optional(),
  requestEnd: z.boolean(),
  authorKeyVersion: positive,
  nodeId: uuid.optional(),
  homeVaultId: uuid.optional(),
  nodeKey: z.string().min(1).max(255).optional(),
  sections: z.string().min(1).max(6500).optional(),
  signature: base64,
  authorUserId: uuid,
  entryHash: base64,
  createdAt: z.string(),
});

/** A section name. */
const sectionName = z.string().regex(/^[a-z][a-z0-9_]{0,63}$/);

/** Runtime shape of a stored write's header. */
const sectionHeaderSchema = z.object({
  vaultId: uuid,
  nodeId: uuid,
  sectionName,
  nodeType: z.string().regex(/^[a-z][a-z0-9_.-]{0,63}$/),
  homeVaultId: uuid,
  ownerUserId: uuid,
  nodeKey: z.string().min(1).max(255),
  vaultKeyVersion: positive,
  dataVersion: positive,
  deleted: z.boolean(),
  logSeq: positive,
  logHeadHash: base64,
  previousWriteHash: base64.optional(),
  writerUserId: uuid,
  writerKeyVersion: positive,
  ciphertextHash: base64.optional(),
  signature: base64,
  writeHash: base64,
  changeSeq: positive,
  writtenAt: z.string(),
});

/** Runtime shape of a stored section write. */
const sectionWriteSchema = sectionHeaderSchema.extend({ ciphertext: base64.optional() });

/** Runtime shape of a section the host removed. */
const sectionRemovalSchema = z.object({ nodeId: uuid, sectionName, changeSeq: positive });

/** The change range every feed page states. */
const feedRange = {
  removed: z.array(sectionRemovalSchema),
  throughChangeSeq: z.number().int().nonnegative(),
  lastChangeSeq: z.number().int().nonnegative(),
};

/** Runtime shape of a page of section headers. */
const sectionHeaderPageSchema = z.object({ items: z.array(sectionHeaderSchema), ...feedRange });

/** Runtime shape of a page of section writes. */
const sectionPageSchema = z.object({ items: z.array(sectionWriteSchema), ...feedRange });

/** Runtime shape of a checkpoint leaf. */
const leafSchema = z.object({
  nodeId: uuid,
  sectionName,
  dataVersion: positive,
  writeHash: base64,
});

/** Runtime shape of a page of a checkpoint's leaves. */
const leafPageSchema = z.object({
  checkpointSeq: positive,
  size: z.number().int().nonnegative(),
  leaves: z.array(leafSchema),
  nextCursor: z.string().max(512).optional(),
});

/** Runtime shape of a vault as the server describes it. */
const vaultSchema = z.object({
  id: uuid,
  role,
  keyVersion: positive,
  keyEnvelope: base64.optional(),
  envelopeUserKeyVersion: positive.optional(),
  logSeq: positive,
  logHeadHash: base64,
  createdByUserId: uuid,
  createdAt: z.string(),
  accepted: z.boolean(),
  addedByUserId: uuid.optional(),
  deleted: z.boolean(),
});

/** Runtime shape of one key version. */
const publicKeysSchema = z.object({
  userId: uuid,
  keyVersion: positive,
  cryptoSuite: z.literal(1),
  encryptionPublicKey: base64,
  signingPublicKey: base64,
  recoverySigningPublicKey: base64,
});

/** Runtime shape of a key statement. */
const keyStatementSchema = z.object({
  keys: publicKeysSchema,
  previousKeysDigest: base64.optional(),
  signature: base64,
  recoverySignature: base64.optional(),
  createdAt: z.string().optional(),
});

/** Runtime shape of a leaf with its path. */
const leafProofSchema = z.object({
  index: z.number().int().nonnegative(),
  leaf: leafSchema,
  path: z.array(base64),
});

/** Runtime shape of a checkpoint proof. */
const checkpointProofSchema = z.object({
  checkpointSeq: positive,
  size: z.number().int().nonnegative(),
  inclusion: leafProofSchema.optional(),
  before: leafProofSchema.optional(),
  after: leafProofSchema.optional(),
});

/** Runtime shape of a batch of checkpoint proofs. */
const checkpointProofsSchema = z.object({ items: z.array(checkpointProofSchema) });

/**
 * Checks a value the server sent against its runtime shape. Generated types describe what the
 * contract promises, not what a hostile server sends: a string where a number belongs, or an id in
 * another spelling, would otherwise slip past comparisons the signature check does not cover.
 *
 * @param schema Runtime shape.
 * @param value Value from the server.
 * @returns The value, typed.
 * @throws {CloakApiError} `unexpected_response` when it does not fit.
 */
// eslint-disable-next-line @typescript-eslint/no-unnecessary-type-parameters -- T names the generated type each caller returns; the schema's own output type differs only in optional keys.
function validated<T>(schema: z.ZodType, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw new CloakApiError(0, undefined);
  // The schema matches the generated type field for field; Zod leaves absent optional keys
  // absent, which is what `exactOptionalPropertyTypes` asks of them.
  return result.data as T;
}

/**
 * Validates a stored log entry.
 *
 * @param value Value from the server.
 * @returns The entry.
 */
export function validEntry(value: unknown): Schemas['LogEntry'] {
  return validated(logEntrySchema, value);
}

/**
 * Validates a stored section write.
 *
 * @param value Value from the server.
 * @returns The write.
 */
export function validWrite(value: unknown): Schemas['SectionWrite'] {
  return validated(sectionWriteSchema, value);
}

/**
 * Validates a stored write's header.
 *
 * @param value Value from the server.
 * @returns The header.
 */
export function validHeader(value: unknown): Schemas['SectionHeader'] {
  return validated(sectionHeaderSchema, value);
}

/**
 * Validates a page of section headers.
 *
 * @param value Value from the server.
 * @returns The page.
 */
export function validHeaderPage(value: unknown): Schemas['SectionHeaderPage'] {
  return validated(sectionHeaderPageSchema, value);
}

/**
 * Validates a page of section writes.
 *
 * @param value Value from the server.
 * @returns The page.
 */
export function validSectionPage(value: unknown): Schemas['SectionPage'] {
  return validated(sectionPageSchema, value);
}

/**
 * Whether a feed page covers what it says: every write and removal in it falls after `afterChange`
 * and up to `throughChangeSeq`, which moves on unless the feed is done. A page that breaks this
 * could keep a reader looping, or skip changes it claims to cover.
 *
 * @param page The page.
 * @param afterChange What the page was asked to follow.
 * @returns Whether the range holds.
 */
export function isFeedRangeSound(
  page: Schemas['SectionHeaderPage'] | Schemas['SectionPage'],
  afterChange: number,
): boolean {
  const { throughChangeSeq: through, lastChangeSeq: last } = page;
  const inRange = (change: number): boolean => change > afterChange && change <= through;
  return (
    through <= last &&
    (through > afterChange || through === last) &&
    page.items.every((item) => inRange(item.changeSeq)) &&
    page.removed.every((removal) => inRange(removal.changeSeq))
  );
}

/**
 * Validates a page of a checkpoint's leaves.
 *
 * @param value Value from the server.
 * @returns The page.
 */
export function validLeafPage(value: unknown): Schemas['CheckpointLeafPage'] {
  return validated(leafPageSchema, value);
}

/**
 * Validates a batch of checkpoint proofs.
 *
 * @param value Value from the server.
 * @returns The proofs.
 */
export function validProofs(value: unknown): Schemas['BatchGetCheckpointProofsResponse'] {
  return validated(checkpointProofsSchema, value);
}

/**
 * Validates a vault view.
 *
 * @param value Value from the server.
 * @returns The view.
 */
export function validVault(value: unknown): Schemas['Vault'] {
  return validated(vaultSchema, value);
}

/**
 * Validates a checkpoint proof.
 *
 * @param value Value from the server.
 * @returns The proof.
 */
export function validProof(value: unknown): Schemas['CheckpointProof'] {
  return validated(checkpointProofSchema, value);
}

/**
 * Conversions between the API's JSON and the crypto package's types. Everything the server sends
 * is converted here and then verified; nothing is trusted because of its shape.
 */

/**
 * Converts KDF parameters to the wire.
 *
 * @param kdf Parameters.
 * @returns Wire form.
 */
export function toWireKdf(kdf: KdfParams): Schemas['KdfParams'] {
  return {
    algorithm: 'argon2id',
    salt: toBase64Url(kdf.salt),
    memoryKib: kdf.memoryKib,
    iterations: kdf.iterations,
    parallelism: 1,
  };
}

/**
 * Converts KDF parameters from the wire; the caller checks their bounds before deriving.
 *
 * @param kdf Wire form.
 * @returns Parameters.
 */
export function fromWireKdf(kdf: Schemas['KdfParams']): KdfParams {
  return {
    salt: fromBase64Url(kdf.salt),
    memoryKib: kdf.memoryKib,
    iterations: kdf.iterations,
    parallelism: kdf.parallelism,
  };
}

/**
 * Converts a key version from the wire.
 *
 * @param keys Wire form.
 * @returns The key version.
 */
export function fromWireKeys(keys: Schemas['PublicKeys']): PublicKeys {
  return {
    userId: keys.userId,
    keyVersion: keys.keyVersion,
    cryptoSuite: keys.cryptoSuite,
    encryptionPublicKey: fromBase64Url(keys.encryptionPublicKey),
    signingPublicKey: fromBase64Url(keys.signingPublicKey),
    recoverySigningPublicKey: fromBase64Url(keys.recoverySigningPublicKey),
  };
}

/**
 * Converts a key statement from the wire.
 *
 * @param served Wire form, validated here.
 * @returns The statement.
 */
export function fromWireStatement(served: Schemas['KeyStatement']): KeyStatement {
  const statement = validated<Schemas['KeyStatement']>(keyStatementSchema, served);
  return {
    keys: fromWireKeys(statement.keys),
    signature: fromBase64Url(statement.signature),
    recoverySignature:
      statement.recoverySignature === undefined
        ? undefined
        : fromBase64Url(statement.recoverySignature),
  };
}

/**
 * Converts a stored log entry from the wire, with the vault and previous hash the reader expects.
 *
 * @param vaultId The vault the reader asked for.
 * @param served Wire form, validated here.
 * @param previousHash `entryHash` of the entry before, as the reader verified it.
 * @returns The entry to verify.
 */
export function fromWireEntry(
  vaultId: string,
  served: Schemas['LogEntry'],
  previousHash: Uint8Array | undefined,
): LogEntry {
  const entry = validEntry(served);
  return {
    vaultId,
    seq: entry.seq,
    previousHash,
    kind: entry.kind,
    subjectUserId: entry.subjectUserId,
    role: entry.role,
    keyVersion: entry.keyVersion,
    subjectKeys: optional(entry.subjectKeys),
    subjectKeyVersion: entry.subjectKeyVersion,
    keyCommitment: optional(entry.keyCommitment),
    checkpoint: optional(entry.checkpoint),
    requestEnd: entry.requestEnd,
    authorUserId: entry.authorUserId,
    authorKeyVersion: entry.authorKeyVersion,
    nodeId: entry.nodeId,
    homeVaultId: entry.homeVaultId,
    nodeKey: entry.nodeKey,
    sections: entry.sections,
    signature: fromBase64Url(entry.signature),
    entryHash: fromBase64Url(entry.entryHash),
  };
}

/**
 * Converts signed entry fields to a request entry.
 *
 * @param fields The signed fields.
 * @param signature The author's signature.
 * @returns Wire form.
 */
export function toWireEntry(
  fields: LogEntryFields,
  signature: Uint8Array,
): Schemas['LogEntryInput'] {
  return {
    seq: fields.seq,
    kind: fields.kind,
    ...(fields.subjectUserId === undefined ? {} : { subjectUserId: fields.subjectUserId }),
    ...(fields.role === undefined ? {} : { role: fields.role }),
    keyVersion: fields.keyVersion,
    ...(fields.subjectKeys === undefined ? {} : { subjectKeys: toBase64Url(fields.subjectKeys) }),
    ...(fields.subjectKeyVersion === undefined
      ? {}
      : { subjectKeyVersion: fields.subjectKeyVersion }),
    ...(fields.keyCommitment === undefined
      ? {}
      : { keyCommitment: toBase64Url(fields.keyCommitment) }),
    ...(fields.checkpoint === undefined ? {} : { checkpoint: toBase64Url(fields.checkpoint) }),
    requestEnd: fields.requestEnd,
    authorKeyVersion: fields.authorKeyVersion,
    ...(fields.nodeId === undefined ? {} : { nodeId: fields.nodeId }),
    ...(fields.homeVaultId === undefined ? {} : { homeVaultId: fields.homeVaultId }),
    ...(fields.nodeKey === undefined ? {} : { nodeKey: fields.nodeKey }),
    ...(fields.sections === undefined ? {} : { sections: fields.sections }),
    signature: toBase64Url(signature),
  };
}

/**
 * Converts a stored write's header from the wire.
 *
 * @param served Wire form, validated here.
 * @returns The header to judge.
 */
export function fromWireHeader(served: Schemas['SectionHeader']): SectionHeader {
  const header = validHeader(served);
  return {
    vaultId: header.vaultId,
    nodeId: header.nodeId,
    nodeType: header.nodeType,
    homeVaultId: header.homeVaultId,
    ownerUserId: header.ownerUserId,
    nodeKey: header.nodeKey,
    sectionName: header.sectionName,
    vaultKeyVersion: header.vaultKeyVersion,
    dataVersion: header.dataVersion,
    deleted: header.deleted,
    logSeq: header.logSeq,
    logHeadHash: fromBase64Url(header.logHeadHash),
    previousWriteHash: optional(header.previousWriteHash),
    writerUserId: header.writerUserId,
    writerKeyVersion: header.writerKeyVersion,
    ciphertextHash: optional(header.ciphertextHash),
    signature: fromBase64Url(header.signature),
  };
}

/**
 * Converts a stored section write from the wire, with its header. The header's digest is the
 * ciphertext's own: a served `ciphertextHash` that disagrees with the ciphertext is refused.
 *
 * @param served Wire form, validated here.
 * @returns The write and its header, or `undefined` when the served digest is not the
 *   ciphertext's.
 */
export function fromWireWrite(
  served: Schemas['SectionWrite'],
): { readonly write: SectionWrite; readonly header: SectionHeader } | undefined {
  const wire = validWrite(served);
  const header = fromWireHeader(wire);
  const ciphertext = optional(wire.ciphertext);
  const digest = ciphertext === undefined ? undefined : sectionCiphertextHash(ciphertext);
  if (
    (digest === undefined) !== (header.ciphertextHash === undefined) ||
    (digest !== undefined &&
      header.ciphertextHash !== undefined &&
      !equalBytes(digest, header.ciphertextHash))
  )
    return undefined;
  const write: SectionWrite = {
    vaultId: header.vaultId,
    nodeId: header.nodeId,
    nodeType: header.nodeType,
    homeVaultId: header.homeVaultId,
    ownerUserId: header.ownerUserId,
    nodeKey: header.nodeKey,
    sectionName: header.sectionName,
    vaultKeyVersion: header.vaultKeyVersion,
    dataVersion: header.dataVersion,
    deleted: header.deleted,
    logSeq: header.logSeq,
    logHeadHash: header.logHeadHash,
    previousWriteHash: header.previousWriteHash,
    writerUserId: header.writerUserId,
    writerKeyVersion: header.writerKeyVersion,
    ciphertext,
    signature: header.signature,
  };
  return { write, header };
}

/**
 * Converts a checkpoint leaf from the wire.
 *
 * @param leaf Wire form, already validated.
 * @returns The leaf.
 */
export function fromWireLeaf(leaf: Schemas['CheckpointLeaf']): CheckpointLeaf {
  return {
    nodeId: leaf.nodeId,
    sectionName: leaf.sectionName,
    dataVersion: leaf.dataVersion,
    writeHash: fromBase64Url(leaf.writeHash),
  };
}

/**
 * Converts a leaf with its path from the wire.
 *
 * @param proof Wire form, already validated.
 * @param size Number of leaves in the checkpoint.
 * @returns The leaf proof.
 */
export function fromWireLeafProof(proof: Schemas['LeafProof'], size: number): LeafProof {
  return {
    index: proof.index,
    size,
    leaf: fromWireLeaf(proof.leaf),
    path: proof.path.map(fromBase64Url),
  };
}

/**
 * Converts signed write fields to a request write.
 *
 * @param fields The signed fields.
 * @param signature The writer's signature.
 * @returns Wire form.
 */
export function toWireWrite(
  fields: SectionWriteFields,
  signature: Uint8Array,
): Schemas['SectionWriteInput'] {
  return {
    nodeType: fields.nodeType,
    homeVaultId: fields.homeVaultId,
    ownerUserId: fields.ownerUserId,
    nodeKey: fields.nodeKey,
    vaultKeyVersion: fields.vaultKeyVersion,
    dataVersion: fields.dataVersion,
    deleted: fields.deleted,
    logSeq: fields.logSeq,
    logHeadHash: toBase64Url(fields.logHeadHash),
    ...(fields.previousWriteHash === undefined
      ? {}
      : { previousWriteHash: toBase64Url(fields.previousWriteHash) }),
    writerKeyVersion: fields.writerKeyVersion,
    ...(fields.ciphertext === undefined ? {} : { ciphertext: toBase64Url(fields.ciphertext) }),
    signature: toBase64Url(signature),
  };
}

/** Decodes an optional base64url value. */
function optional(value: string | undefined): Uint8Array | undefined {
  return value === undefined ? undefined : fromBase64Url(value);
}
