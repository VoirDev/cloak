import { describe, expect, it } from 'vitest';

import { body, createApi, noBody, type Sleep } from '../src/api.ts';

/** What a fake server saw and how long the client waited. */
interface Recorded {
  readonly bodies: string[];
  readonly waits: number[];
}

/** An API whose fetch answers with [responses] in turn, recording each request's body. */
function apiAnswering(responses: readonly (() => Response | Promise<Response>)[]) {
  const recorded: Recorded = { bodies: [], waits: [] };
  let next = 0;
  const sleep: Sleep = (milliseconds) => {
    recorded.waits.push(milliseconds);
    return Promise.resolve();
  };
  const api = createApi(
    {
      baseUrl: 'http://cloak.test/cloak/v1',
      fetch: async (input, init) => {
        recorded.bodies.push(await new Request(input, init).text());
        const answer = responses[next];
        next += 1;
        if (answer === undefined) throw new Error('No more answers');
        return answer();
      },
    },
    sleep,
  );
  return { api, recorded };
}

/** A problem response. */
function problem(status: number, code: string, retryAfter?: string): Response {
  return new Response(
    JSON.stringify({ type: `urn:cloak:problem:${code}`, title: code, status, code }),
    {
      status,
      headers: {
        'content-type': 'application/problem+json',
        ...(retryAfter === undefined ? {} : { 'Retry-After': retryAfter }),
      },
    },
  );
}

/** An empty successful batch of user keys. */
function noKeys(): Response {
  return new Response(JSON.stringify({ items: [], missingUserIds: [] }), {
    headers: { 'content-type': 'application/json' },
  });
}

/** Asks for some users' keys, a request with a body. */
function askKeys(api: ReturnType<typeof createApi>) {
  return body(
    api.POST('/users/keys/batch-get', {
      body: { userIds: ['0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d0e'] },
    }),
  );
}

describe('the API transport', () => {
  it('sends the very same bytes again after a busy server says when to retry', async () => {
    const { api, recorded } = apiAnswering([
      () => problem(503, 'busy', '2'),
      () => problem(429, 'rate_limited', '1'),
      noKeys,
    ]);

    await askKeys(api);

    expect(recorded.waits).toEqual([2000, 1000]);
    expect(recorded.bodies).toHaveLength(3);
    expect(new Set(recorded.bodies).size).toBe(1);
  });

  it('passes the answer on without a Retry-After, after the last try, or for a long wait', async () => {
    const without = apiAnswering([() => problem(503, 'busy')]);
    await expect(askKeys(without.api)).rejects.toMatchObject({ status: 503, code: 'busy' });
    expect(without.recorded.waits).toEqual([]);

    const persistent = apiAnswering(
      Array.from({ length: 30 }, () => () => problem(503, 'busy', '1')),
    );
    await expect(askKeys(persistent.api)).rejects.toMatchObject({ code: 'busy' });
    expect(persistent.recorded.bodies).toHaveLength(30);

    const slow = apiAnswering(Array.from({ length: 30 }, () => () => problem(503, 'busy', '25')));
    await expect(askKeys(slow.api)).rejects.toMatchObject({ code: 'busy' });
    // 25 s twice is the most a minute allows; the third answer is passed on.
    expect(slow.recorded.waits).toEqual([25_000, 25_000]);

    const long = apiAnswering([() => problem(429, 'rate_limited', '120')]);
    await expect(askKeys(long.api)).rejects.toMatchObject({ code: 'rate_limited' });
    expect(long.recorded.waits).toEqual([]);
  });

  it('never retries other failures, such as a conflict', async () => {
    const { api, recorded } = apiAnswering([() => problem(409, 'log_conflict', '1')]);
    await expect(askKeys(api)).rejects.toMatchObject({ code: 'log_conflict' });
    expect(recorded.bodies).toHaveLength(1);
  });

  it('turns a request that got no response into network_error, once, keeping the cause', async () => {
    const cause = new TypeError('Failed to fetch');
    const { api, recorded } = apiAnswering([() => Promise.reject(cause)]);

    const error: unknown = await askKeys(api).catch((failure: unknown) => failure);

    expect(error).toMatchObject({ name: 'CloakApiError', status: 0, code: 'network_error', cause });
    expect(recorded.bodies).toHaveLength(1);
  });

  it('lets an aborted request fail as the abort it is', async () => {
    const controller = new AbortController();
    const api = createApi({
      baseUrl: 'http://cloak.test/cloak/v1',
      fetch: (input, init) => {
        controller.abort();
        return Promise.reject(new Request(input, init).signal.reason as Error);
      },
    });

    await expect(
      noBody(
        api.PUT('/vaults/{vaultId}/acceptance', {
          params: { path: { vaultId: '0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d0e' } },
          signal: controller.signal,
        }),
      ),
    ).rejects.toMatchObject({ name: 'AbortError' });
  });
});
