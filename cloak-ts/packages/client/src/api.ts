import createClient, { type Client } from 'openapi-fetch';

import { CloakApiError } from './CloakApiError.ts';
import type { components, paths } from './generated/cloakApi.ts';

/** Wire schemas of the Cloak API, generated from the OpenAPI spec. */
export type Schemas = components['schemas'];

/** Typed HTTP client of the Cloak API. */
export type CloakApi = Client<paths>;

/** How to reach the host's Cloak endpoints. */
export interface CloakHttpOptions {
  /** Base URL of the API, ending in `/cloak/v1`. */
  readonly baseUrl: string;
  /** Fetch implementation; the global `fetch` by default. */
  readonly fetch?: typeof fetch | undefined;
  /**
   * Headers the host's authentication needs, such as a bearer token, read before every request.
   * Cookie sessions need nothing here.
   */
  readonly headers?: (() => HeadersInit) | undefined;
}

/** Waits, or rejects with the signal's reason when it aborts first. */
export type Sleep = (milliseconds: number, signal: AbortSignal) => Promise<void>;

/**
 * How long the client waits for a server that is busy (`503 busy`) or that the host's guard
 * rate-limits (`429 rate_limited`). The server answers both before applying anything.
 */
const RETRY = {
  /**
   * Most tries of one request, the first included. A write pause for a checkpoint asks writers to
   * come back within a second or two until it ends, which takes several tries.
   */
  attempts: 30,
  /** Longest single wait; a server asking for more gets its answer passed on instead. */
  maxWaitMs: 30_000,
  /** Longest wait over all tries of one request. */
  totalWaitMs: 60_000,
} as const;

/** Waits on a timer. */
const sleepOnTimer: Sleep = (milliseconds, signal) =>
  new Promise<void>((resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason as Error);
      return;
    }
    const abort = (): void => {
      clearTimeout(timer);
      reject(signal.reason as Error);
    };
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', abort);
      resolve();
    }, milliseconds);
    signal.addEventListener('abort', abort, { once: true });
  });

/**
 * The `Retry-After` of a response in milliseconds: delay seconds or an HTTP date.
 *
 * @returns The wait, or `undefined` when the header is absent or unreadable.
 */
function retryAfter(response: Response, now: number): number | undefined {
  const value = response.headers.get('Retry-After')?.trim();
  if (value === undefined || value === '') return undefined;
  if (/^\d+$/.test(value)) return Number(value) * 1000;
  const date = Date.parse(value);
  return Number.isNaN(date) ? undefined : Math.max(0, date - now);
}

/**
 * Wraps fetch so that what reaches the client is either a response or a `CloakApiError`:
 *
 * - a request that never got a response fails with `network_error`, its cause kept. Whether a
 *   write was applied is then unknown, so it is never retried here. An aborted request stays the
 *   `AbortError` the caller expects;
 * - a `429` or `503` with a `Retry-After` is sent again after that wait, as the very same bytes:
 *   the server applied nothing, and nothing is signed again, so a server that answers "busy"
 *   cannot collect several signed versions of one change. Past {@link RETRY}'s bounds the answer
 *   is passed on.
 */
function resilient(base: typeof fetch, sleep: Sleep): typeof fetch {
  return async (input, init) => {
    const original = new Request(input, init);
    let waited = 0;
    for (let attempt = 1; ; attempt += 1) {
      let response: Response;
      try {
        response = await base(original.clone());
      } catch (error: unknown) {
        if (original.signal.aborted) throw error;
        throw new CloakApiError(
          0,
          { code: 'network_error', detail: 'The Cloak API could not be reached' },
          { cause: error },
        );
      }
      if (response.status !== 429 && response.status !== 503) return response;
      const wait = retryAfter(response, Date.now());
      if (
        attempt >= RETRY.attempts ||
        wait === undefined ||
        wait > RETRY.maxWaitMs ||
        waited + wait > RETRY.totalWaitMs
      )
        return response;
      await response.body?.cancel();
      await sleep(wait, original.signal);
      waited += wait;
    }
  };
}

/**
 * Creates the typed HTTP client.
 *
 * @param options Base URL, fetch and host headers.
 * @param sleep How retries wait; a timer by default, replaced only in tests.
 * @returns The client.
 */
export function createApi(options: CloakHttpOptions, sleep: Sleep = sleepOnTimer): CloakApi {
  const api = createClient<paths>({
    baseUrl: options.baseUrl,
    fetch: resilient(options.fetch ?? ((request) => globalThis.fetch(request)), sleep),
  });
  const headers = options.headers;
  if (headers !== undefined) {
    api.use({
      onRequest({ request }) {
        new Headers(headers()).forEach((value, name) => {
          request.headers.set(name, value);
        });
        return request;
      },
    });
  }
  return api;
}

/** Result shape of an openapi-fetch call. */
interface CallResult<T> {
  /** Body of a successful response. */
  readonly data?: T;
  /** Body of a failed response. */
  readonly error?: unknown;
  /** The response. */
  readonly response: Response;
}

/**
 * Awaits a call and returns its body, or throws the server's problem.
 *
 * @param call Pending openapi-fetch call.
 * @returns The response body.
 * @throws {CloakApiError} for any non-2xx response.
 */
export async function body<T>(call: Promise<CallResult<T>>): Promise<T> {
  const { data, error, response } = await call;
  if (!response.ok || data === undefined) throw new CloakApiError(response.status, error);
  return data;
}

/**
 * Awaits a call whose success has no body.
 *
 * @param call Pending openapi-fetch call.
 * @throws {CloakApiError} for any non-2xx response.
 */
export async function noBody(call: Promise<CallResult<unknown>>): Promise<void> {
  const { error, response } = await call;
  if (!response.ok) throw new CloakApiError(response.status, error);
}
