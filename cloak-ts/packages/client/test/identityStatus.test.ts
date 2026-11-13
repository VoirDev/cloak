import { describe, expect, it } from 'vitest';

import { createCloakClient, isCloakApiError, type CloakClient } from '../src/index.ts';

/** A client whose server answers every request with [answer], counting requests. */
function clientAnswering(answer: (request: Request) => Response | Promise<Response>): {
  readonly client: CloakClient;
  readonly requests: () => number;
} {
  let count = 0;
  const client = createCloakClient({
    baseUrl: 'http://cloak.test/cloak/v1',
    fetch: (input, init) => {
      count += 1;
      return Promise.resolve(answer(new Request(input, init)));
    },
  });
  return { client, requests: () => count };
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

describe('identityStatus', () => {
  it('reads a missing identity as none and a tombstone as deleted', async () => {
    expect(
      await clientAnswering(() => problem(404, 'identity_required')).client.identityStatus(),
    ).toBe('none');
    expect(
      await clientAnswering(() => problem(410, 'identity_deleted')).client.identityStatus(),
    ).toBe('deleted');
  });

  it('asks GET /identity and nothing else', async () => {
    const seen: string[] = [];
    const { client } = clientAnswering((request) => {
      seen.push(`${request.method} ${new URL(request.url).pathname}`);
      return problem(404, 'identity_required');
    });

    await client.identityStatus();

    expect(seen).toEqual(['GET /cloak/v1/identity']);
  });

  it('throws for a 404 that is not a Cloak problem instead of reading it as none', async () => {
    const { client } = clientAnswering(
      () =>
        new Response('<html>Not Found</html>', {
          status: 404,
          headers: { 'content-type': 'text/html' },
        }),
    );

    await expect(client.identityStatus()).rejects.toSatisfy(
      (error: unknown) => isCloakApiError(error, 'unexpected_response') && error.status === 404,
    );
  });

  it('throws what every request throws for other answers', async () => {
    await expect(
      clientAnswering(() => problem(401, 'unauthenticated')).client.identityStatus(),
    ).rejects.toSatisfy((error: unknown) => isCloakApiError(error, 'unauthenticated'));
    await expect(
      clientAnswering(() => problem(404, 'not_found')).client.identityStatus(),
    ).rejects.toSatisfy((error: unknown) => isCloakApiError(error, 'not_found'));

    const offline = createCloakClient({
      baseUrl: 'http://cloak.test/cloak/v1',
      fetch: () => Promise.reject(new TypeError('Network error')),
    });
    await expect(offline.identityStatus()).rejects.toSatisfy(
      (error: unknown) => isCloakApiError(error, 'network_error') && error.status === 0,
    );
  });

  it('stays an AbortError when aborted before the answer', async () => {
    const controller = new AbortController();
    const client = createCloakClient({
      baseUrl: 'http://cloak.test/cloak/v1',
      fetch: (input, init) => {
        const { signal } = new Request(input, init);
        return new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => {
            reject(signal.reason as Error);
          });
        });
      },
    });

    const status = client.identityStatus({ signal: controller.signal });
    controller.abort();

    await expect(status).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('stays an AbortError when aborted while waiting to retry a rate limit', async () => {
    const controller = new AbortController();
    const { client, requests } = clientAnswering(() => {
      controller.abort();
      return problem(429, 'rate_limited', '30');
    });

    await expect(client.identityStatus({ signal: controller.signal })).rejects.toMatchObject({
      name: 'AbortError',
    });
    expect(requests()).toBe(1);
  });
});
