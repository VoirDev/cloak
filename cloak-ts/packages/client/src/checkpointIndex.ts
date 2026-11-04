import {
  checkpointRoot,
  compareSections,
  equalBytes,
  resolveCheckpointProof,
  type CheckpointLeaf,
  type CheckpointRecord,
} from '@voirdev/cloak-crypto';

import { CloakVaultLogError } from './CloakVaultLogError.ts';
import { body, type CloakApi } from './api.ts';
import { fromWireLeaf, fromWireLeafProof, validLeafPage, validProofs } from './wire.ts';

/** One question to a checkpoint: what it holds for a section. */
export interface CheckpointQuery {
  /** The checkpoint, from the verified log. */
  readonly checkpoint: CheckpointRecord;
  /** Node of the section. */
  readonly nodeId: string;
  /** Section name. */
  readonly sectionName: string;
}

/** Answers to checkpoint queries, by {@link queryKey}: the leaf, or `undefined` when absent. */
export type CheckpointAnswers = ReadonlyMap<string, CheckpointLeaf | undefined>;

/** Most proofs one request asks for: the API's batch size. */
const PROOF_BATCH = 100;

/** Leaves per page of a checkpoint's leaf list: the API's index page size. */
const LEAF_PAGE = 1000;

/**
 * From this many questions to one checkpoint on, reading its whole leaf list costs the server
 * less than proofs: each proof request reads every leaf of the checkpoint once anyway.
 */
const WHOLE_LIST_FROM = PROOF_BATCH;

/** Most leaves of whole lists kept in memory; older lists are dropped first. */
const MAX_KEPT_LEAVES = 500_000;

/** Most single answers kept in memory; the oldest are dropped first. */
const MAX_KEPT_ANSWERS = 100_000;

/**
 * The key of a query's answer.
 *
 * @param seq Checkpoint's entry.
 * @param nodeId Node of the section.
 * @param sectionName Section name.
 * @returns A key unique per checkpoint and section.
 */
export function queryKey(seq: number, nodeId: string, sectionName: string): string {
  return `${String(seq)}/${nodeId}/${sectionName}`;
}

/**
 * What the checkpoints of the vaults a session reads hold (`PROTOCOL.md` §7.5). Every answer is
 * verified against the signed root before use: a proof's path, or a whole leaf list whose root is
 * recomputed. A checkpoint never changes, so verified answers are kept for the session. A server
 * whose answer does not verify is lying about a signed checkpoint, which fails the read rather
 * than refusing the write it concerns.
 */
export class CheckpointIndex {
  /** HTTP client. */
  readonly #api: CloakApi;
  /** Verified whole leaf lists, by vault and checkpoint, then section. */
  readonly #lists = new Map<string, ReadonlyMap<string, CheckpointLeaf>>();
  /** Leaves held by {@link #lists}. */
  #keptLeaves = 0;
  /** Verified single answers, by vault and {@link queryKey}. */
  readonly #answers = new Map<string, CheckpointLeaf | undefined>();

  /**
   * @param api HTTP client.
   */
  constructor(api: CloakApi) {
    this.#api = api;
  }

  /**
   * Answers what checkpoints of one vault hold for some sections, with as few requests as it
   * can: a whole leaf list for a checkpoint asked about often, batched proofs for the rest.
   *
   * @param vaultId The vault.
   * @param queries Questions, each about a checkpoint of the vault's verified log.
   * @returns The answers, by {@link queryKey}.
   * @throws {CloakVaultLogError} `state_mismatch` when the server's answer does not verify.
   */
  async lookup(vaultId: string, queries: readonly CheckpointQuery[]): Promise<CheckpointAnswers> {
    const answers = new Map<string, CheckpointLeaf | undefined>();
    const open = new Map<number, { checkpoint: CheckpointRecord; queries: CheckpointQuery[] }>();
    for (const query of queries) {
      const key = queryKey(query.checkpoint.seq, query.nodeId, query.sectionName);
      if (answers.has(key)) continue;
      const known = this.#known(vaultId, query);
      if (known.found) {
        answers.set(key, known.leaf);
        continue;
      }
      const group = open.get(query.checkpoint.seq) ?? { checkpoint: query.checkpoint, queries: [] };
      group.queries.push(query);
      open.set(query.checkpoint.seq, group);
    }

    const proofQueries: CheckpointQuery[] = [];
    for (const group of open.values()) {
      if (group.queries.length < WHOLE_LIST_FROM) {
        proofQueries.push(...group.queries);
        continue;
      }
      const list = await this.#loadList(vaultId, group.checkpoint);
      for (const query of group.queries) {
        answers.set(
          queryKey(query.checkpoint.seq, query.nodeId, query.sectionName),
          list.get(sectionKey(query.nodeId, query.sectionName)),
        );
      }
    }
    for (let start = 0; start < proofQueries.length; start += PROOF_BATCH) {
      const batch = proofQueries.slice(start, start + PROOF_BATCH);
      for (const [key, leaf] of await this.#prove(vaultId, batch)) answers.set(key, leaf);
    }
    return answers;
  }

  /** What is already known about a query. */
  #known(
    vaultId: string,
    query: CheckpointQuery,
  ): { readonly found: boolean; readonly leaf?: CheckpointLeaf | undefined } {
    const list = this.#lists.get(listKey(vaultId, query.checkpoint.seq));
    if (list !== undefined)
      return { found: true, leaf: list.get(sectionKey(query.nodeId, query.sectionName)) };
    const key = `${vaultId}/${queryKey(query.checkpoint.seq, query.nodeId, query.sectionName)}`;
    return this.#answers.has(key)
      ? { found: true, leaf: this.#answers.get(key) }
      : { found: false };
  }

  /** Reads, checks and keeps a checkpoint's whole leaf list. */
  async #loadList(
    vaultId: string,
    checkpoint: CheckpointRecord,
  ): Promise<ReadonlyMap<string, CheckpointLeaf>> {
    const kept = this.#lists.get(listKey(vaultId, checkpoint.seq));
    if (kept !== undefined) return kept;
    const mismatch = (): CloakVaultLogError => new CloakVaultLogError(vaultId, 'state_mismatch');
    const leaves: CheckpointLeaf[] = [];
    let size: number | undefined;
    let cursor: string | undefined;
    do {
      const page = validLeafPage(
        await body(
          this.#api.GET('/vaults/{vaultId}/checkpoints/{seq}/leaves', {
            params: {
              path: { vaultId, seq: checkpoint.seq },
              query: { limit: LEAF_PAGE, ...(cursor === undefined ? {} : { cursor }) },
            },
          }),
        ),
      );
      // A page that brings nothing but promises more would never end; one that brings more
      // leaves than the checkpoint has is lying. Order and the root are checked below.
      if (
        page.checkpointSeq !== checkpoint.seq ||
        (size !== undefined && page.size !== size) ||
        leaves.length + page.leaves.length > page.size ||
        (page.nextCursor !== undefined && page.leaves.length === 0)
      )
        throw mismatch();
      size = page.size;
      leaves.push(...page.leaves.map(fromWireLeaf));
      cursor = page.nextCursor;
    } while (cursor !== undefined);
    if (leaves.length !== size) throw mismatch();
    // Strictly sorted leaves hold each section at most once (§7.5), and their root must be the
    // signed one: then the list is exactly what the checkpoint holds.
    for (let index = 1; index < leaves.length; index += 1) {
      const previous = leaves[index - 1];
      const current = leaves[index];
      if (previous === undefined || current === undefined) throw mismatch();
      if (compareSections(previous, current) >= 0) throw mismatch();
    }
    if (!equalBytes(checkpointRoot(leaves), checkpoint.root)) throw mismatch();

    const list = new Map(leaves.map((leaf) => [sectionKey(leaf.nodeId, leaf.sectionName), leaf]));
    this.#lists.set(listKey(vaultId, checkpoint.seq), list);
    this.#keptLeaves += list.size;
    while (this.#keptLeaves > MAX_KEPT_LEAVES && this.#lists.size > 1) {
      const [oldest] = this.#lists;
      if (oldest === undefined) break;
      this.#lists.delete(oldest[0]);
      this.#keptLeaves -= oldest[1].size;
    }
    return list;
  }

  /** Asks for proofs of one batch and checks each against its checkpoint. */
  async #prove(
    vaultId: string,
    batch: readonly CheckpointQuery[],
  ): Promise<Map<string, CheckpointLeaf | undefined>> {
    const response = validProofs(
      await body(
        this.#api.POST('/vaults/{vaultId}/checkpoint-proofs/batch-get', {
          params: { path: { vaultId } },
          body: {
            items: batch.map((query) => ({
              checkpointSeq: query.checkpoint.seq,
              nodeId: query.nodeId,
              sectionName: query.sectionName,
            })),
          },
        }),
      ),
    );
    if (response.items.length !== batch.length)
      throw new CloakVaultLogError(vaultId, 'state_mismatch');
    const answers = new Map<string, CheckpointLeaf | undefined>();
    batch.forEach((query, index) => {
      const proof = response.items[index];
      if (proof?.checkpointSeq !== query.checkpoint.seq)
        throw new CloakVaultLogError(vaultId, 'state_mismatch');
      const leafProof = (wire: typeof proof.inclusion) =>
        wire === undefined ? undefined : fromWireLeafProof(wire, proof.size);
      const lookup = resolveCheckpointProof(
        {
          size: proof.size,
          inclusion: leafProof(proof.inclusion),
          before: leafProof(proof.before),
          after: leafProof(proof.after),
        },
        query,
        query.checkpoint.root,
      );
      if (!lookup.verified) throw new CloakVaultLogError(vaultId, 'state_mismatch');
      const key = queryKey(query.checkpoint.seq, query.nodeId, query.sectionName);
      answers.set(key, lookup.leaf);
      this.#answers.set(`${vaultId}/${key}`, lookup.leaf);
    });
    while (this.#answers.size > MAX_KEPT_ANSWERS) {
      const [oldest] = this.#answers.keys();
      if (oldest === undefined) break;
      this.#answers.delete(oldest);
    }
    return answers;
  }
}

/** Key of a vault's checkpoint. */
function listKey(vaultId: string, seq: number): string {
  return `${vaultId}/${String(seq)}`;
}

/** Key of a section within one vault's checkpoint. */
function sectionKey(nodeId: string, sectionName: string): string {
  return `${nodeId}/${sectionName}`;
}
