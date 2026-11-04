import {
  fromBase64Url,
  toBase64Url,
  type Membership,
  type MembershipChange,
  type VaultLogState,
} from '@voirdev/cloak-crypto';
import * as z from 'zod';

/** A role as stored. */
const role = z.enum(['viewer', 'editor', 'admin', 'owner']);

/** A positive integer as stored. */
const positive = z.number().int().positive();

/**
 * Stored form of a vault snapshot (`PROTOCOL.md` §15), compact because it grows with the log:
 * one tuple per entry and per membership change, bytes in base64url.
 */
export const snapshotRecord = z.object({
  /** Vault. */
  vaultId: z.string(),
  /** Per entry, in `seq` order: `entryHash`, head flag, key version, author, author key version. */
  points: z.array(z.tuple([z.string(), z.boolean(), positive, z.string(), positive])),
  /** Per user: `[seq, role, keyVersion, keysDigest]` per change, `[seq]` for a removal. */
  history: z.array(
    z.tuple([
      z.string(),
      z.array(z.union([z.tuple([positive]), z.tuple([positive, role, positive, z.string()])])),
    ]),
  ),
  /** Entries carrying a checkpoint: `[seq, root]`. */
  checkpoints: z.array(z.tuple([positive, z.string()])),
  /** Key commitments: `[version, commitment]`. */
  commitments: z.array(z.tuple([positive, z.string()])),
  /** Newest recorded key version per user: `[userId, version]`. */
  recorded: z.array(z.tuple([z.string(), positive])),
  /** Members who left since the last rotation. */
  departed: z.array(z.string()),
  /** Members who recorded a key replacement since the last rotation. */
  replacedKeys: z.array(z.string()),
  /** Nodes created in the vault: id, owner, key and the `seq` of `node_created`. */
  nodes: z.array(z.tuple([z.string(), z.string(), z.string(), positive])),
  /** Nodes shared into the vault: id, owner, home, key, `seq` of `*` or 0, and names with theirs. */
  shares: z.array(
    z.tuple([
      z.string(),
      z.string(),
      z.string(),
      z.string(),
      z.number().int().nonnegative(),
      z.array(z.tuple([z.string(), positive])),
    ]),
  ),
  /** Whether the vault was deleted. */
  deleted: z.boolean(),
  /** The last `seq` at which where nodes live changed. */
  placesChangedAt: z.number().int().nonnegative(),
});

/** The stored form of a snapshot. */
export type SnapshotRecord = z.infer<typeof snapshotRecord>;

/**
 * Encodes a verified log state for storage.
 *
 * @param state The verified state.
 * @returns Its stored form.
 */
export function encodeSnapshot(state: VaultLogState): SnapshotRecord {
  return {
    vaultId: state.vaultId,
    points: state.points.map((point) => [
      toBase64Url(point.hash),
      point.head,
      point.keyVersion,
      point.authorUserId,
      point.authorKeyVersion,
    ]),
    history: [...state.history].map(([userId, changes]) => [
      userId,
      changes.map((change) =>
        change.membership === undefined
          ? ([change.seq] as [number])
          : ([
              change.seq,
              change.membership.role,
              change.membership.keyVersion,
              toBase64Url(change.membership.keysDigest),
            ] as [number, Membership['role'], number, string]),
      ),
    ]),
    checkpoints: state.checkpoints.map((checkpoint) => [
      checkpoint.seq,
      toBase64Url(checkpoint.root),
    ]),
    commitments: [...state.commitments].map(([version, commitment]) => [
      version,
      toBase64Url(commitment),
    ]),
    recorded: [...state.recordedKeyVersions],
    departed: [...state.sinceRotation.departed],
    replacedKeys: [...state.sinceRotation.replacedKeys],
    nodes: [...state.nodes].map(([nodeId, node]) => [
      nodeId,
      node.ownerUserId,
      node.nodeKey,
      node.seq,
    ]),
    shares: [...state.shares].map(([nodeId, share]) => [
      nodeId,
      share.ownerUserId,
      share.homeVaultId,
      share.nodeKey,
      share.all ?? 0,
      [...share.names],
    ]),
    deleted: state.deleted,
    placesChangedAt: state.placesChangedAt,
  };
}

/**
 * Decodes a stored snapshot. The record is authenticated by the local state key, so it holds what
 * this device verified; the checks here only refuse a record that is not a whole log.
 *
 * @param record The stored form.
 * @returns The state, or `undefined` when the record does not describe a whole log.
 */
export function decodeSnapshot(record: SnapshotRecord): VaultLogState | undefined {
  const points = record.points.map(
    ([hash, head, keyVersion, authorUserId, authorKeyVersion], index) => ({
      seq: index + 1,
      hash: fromBase64Url(hash),
      head,
      keyVersion,
      authorUserId,
      authorKeyVersion,
    }),
  );
  const last = points.at(-1);
  if (last?.head !== true) return undefined;
  const history = new Map<string, readonly MembershipChange[]>();
  const members = new Map<string, Membership>();
  for (const [userId, stored] of record.history) {
    const changes: MembershipChange[] = stored.map((change) =>
      change.length === 1
        ? { seq: change[0], membership: undefined }
        : {
            seq: change[0],
            membership: {
              role: change[1],
              keyVersion: change[2],
              keysDigest: fromBase64Url(change[3]),
            },
          },
    );
    const latest = changes.at(-1);
    if (latest === undefined || latest.seq > points.length) return undefined;
    history.set(userId, changes);
    if (latest.membership !== undefined) members.set(userId, latest.membership);
  }
  return {
    vaultId: record.vaultId,
    points,
    members,
    history,
    checkpoints: record.checkpoints.map(([seq, root]) => ({ seq, root: fromBase64Url(root) })),
    commitments: new Map(
      record.commitments.map(([version, commitment]) => [version, fromBase64Url(commitment)]),
    ),
    recordedKeyVersions: new Map(record.recorded),
    sinceRotation: { departed: record.departed, replacedKeys: record.replacedKeys },
    nodes: new Map(
      record.nodes.map(([nodeId, ownerUserId, nodeKey, seq]) => [
        nodeId,
        { ownerUserId, nodeKey, seq },
      ]),
    ),
    shares: new Map(
      record.shares.map(([nodeId, ownerUserId, homeVaultId, nodeKey, all, names]) => [
        nodeId,
        {
          ownerUserId,
          homeVaultId,
          nodeKey,
          all: all === 0 ? undefined : all,
          names: new Map(names),
        },
      ]),
    ),
    deleted: record.deleted,
    placesChangedAt: record.placesChangedAt,
  };
}
