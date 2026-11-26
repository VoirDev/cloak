import { checkpointRoot, toBase64Url, type CheckpointLeaf } from '@voirdev/cloak-crypto';
import { describe, expect, it } from 'vitest';

import { createApi } from '../src/api.ts';
import { CheckpointIndex, queryKey } from '../src/checkpointIndex.ts';

const VAULT = '0192f5a3-0000-7aaa-8bbb-0123456789ab';
const NODE = '0192f5a5-1111-7aaa-8bbb-0123456789ab';
const SECTION = 'general';

/** The one leaf of a checkpoint over a single section at [dataVersion]. */
function leafAt(dataVersion: number): CheckpointLeaf {
  return {
    nodeId: NODE,
    sectionName: SECTION,
    dataVersion,
    writeHash: new Uint8Array(32).fill(dataVersion),
  };
}

/**
 * A checkpoint index whose server proves [served] as the one leaf of every checkpoint asked
 * about, counting the proof requests.
 */
function indexServing(served: { leaf: CheckpointLeaf }) {
  const asked = { proofs: 0 };
  const api = createApi({
    baseUrl: 'http://cloak.test/cloak/v1',
    fetch: (input, init) => {
      const request = new Request(input, init);
      if (!request.url.endsWith('/checkpoint-proofs/batch-get'))
        return Promise.reject(new Error(`Unexpected ${request.url}`));
      asked.proofs += 1;
      const { leaf } = served;
      return Promise.resolve(
        new Response(
          JSON.stringify({
            items: [
              {
                checkpointSeq: 3,
                size: 1,
                inclusion: {
                  index: 0,
                  leaf: { ...leaf, writeHash: toBase64Url(leaf.writeHash) },
                  path: [],
                },
              },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
      );
    },
  });
  const index = new CheckpointIndex(api, () =>
    Promise.resolve({ live: 100, stored: 1000, pageSize: 100, pageBytes: 8 * 1_048_576 }),
  );
  return { index, asked };
}

describe('the checkpoint index', () => {
  it('keeps answers by checkpoint root, and drops a vault’s answers when it is forgotten', async () => {
    const served = { leaf: leafAt(1) };
    const { index, asked } = indexServing(served);
    const first = { seq: 3, root: checkpointRoot([leafAt(1)]) };
    const query = { checkpoint: first, nodeId: NODE, sectionName: SECTION };

    expect((await index.lookup(VAULT, [query])).get(queryKey(3, NODE, SECTION))).toEqual(leafAt(1));
    await index.lookup(VAULT, [query]);
    expect(asked.proofs).toBe(1);

    // Another history of the vault signs another checkpoint at the same entry: asked anew.
    served.leaf = leafAt(2);
    const other = { seq: 3, root: checkpointRoot([leafAt(2)]) };
    const answers = await index.lookup(VAULT, [{ ...query, checkpoint: other }]);
    expect(answers.get(queryKey(3, NODE, SECTION))).toEqual(leafAt(2));
    expect(asked.proofs).toBe(2);

    served.leaf = leafAt(1);
    index.forget(VAULT);
    await index.lookup(VAULT, [query]);
    expect(asked.proofs).toBe(3);
  });

  it('keeps the checkpoints of one proof batch within a vault’s worth of leaves', async () => {
    // Four checkpoints of one leaf each, against a server that, like the real one, refuses a
    // batch whose checkpoints hold more than `live` leaves together.
    const live = 2;
    const leaf = leafAt(1);
    const wireLeaf = { ...leaf, writeHash: toBase64Url(leaf.writeHash) };
    const batches: number[][] = [];
    const api = createApi({
      baseUrl: 'http://cloak.test/cloak/v1',
      fetch: async (input, init) => {
        const request = new Request(input, init);
        const asked = (await request.json()) as {
          items: { checkpointSeq: number; sectionName: string }[];
        };
        const seqs = [...new Set(asked.items.map((item) => item.checkpointSeq))];
        batches.push(seqs);
        if (seqs.length > live) return new Response('{}', { status: 400 });
        const items = asked.items.map((item) => ({
          checkpointSeq: item.checkpointSeq,
          size: 1,
          ...(item.sectionName === SECTION
            ? { inclusion: { index: 0, leaf: wireLeaf, path: [] } }
            : { before: { index: 0, leaf: wireLeaf, path: [] } }),
        }));
        return new Response(JSON.stringify({ items }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      },
    });
    const index = new CheckpointIndex(api, () =>
      Promise.resolve({ live, stored: 1000, pageSize: 100, pageBytes: 8 * 1_048_576 }),
    );
    const checkpoints = [3, 4, 5, 6].map((seq) => ({ seq, root: checkpointRoot([leaf]) }));
    const ask = (sectionName: string) =>
      checkpoints.map((checkpoint) => ({ checkpoint, nodeId: NODE, sectionName }));

    // Sizes not known yet count as a whole vault: each checkpoint goes alone.
    const first = await index.lookup(VAULT, ask(SECTION));
    expect(batches).toEqual([[3], [4], [5], [6]]);
    expect([...first.values()]).toEqual([leaf, leaf, leaf, leaf]);

    // Their answers taught their sizes: two fit together now.
    batches.length = 0;
    const second = await index.lookup(VAULT, ask('zzz'));
    expect(batches).toEqual([
      [3, 4],
      [5, 6],
    ]);
    expect([...second.values()]).toEqual([undefined, undefined, undefined, undefined]);
  });
});
