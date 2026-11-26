import { body, type CloakApi, type Schemas } from './api.ts';
import { ciphertextBytes, validMeta } from './wire.ts';

/**
 * The server's limits on one vault's sections and on one response (`GET /meta`, `PROTOCOL.md`
 * §13). They bound what one read may hold: no checkpoint has more leaves than a vault has live
 * sections, no feed lists more sections than a vault stores, and no response carries more
 * sections or ciphertext than one page.
 */
export interface SectionLimits {
  /** Most live sections of a vault, so most leaves of a checkpoint and of one proof batch. */
  readonly live: number;
  /** Most sections a vault stores, deleted ones included, and so most a feed lists. */
  readonly stored: number;
  /** Most sections one response with ciphertext holds. */
  readonly pageSize: number;
  /** Most bytes of section ciphertext one response carries. */
  readonly pageBytes: number;
}

/**
 * Creates a reader of the server's section limits that asks once and keeps the answer.
 *
 * @param api HTTP client.
 * @returns The reader; a failed request is asked again on the next call.
 */
export function sectionLimits(api: CloakApi): () => Promise<SectionLimits> {
  let limits: Promise<SectionLimits> | undefined;
  return () => {
    limits ??= body(api.GET('/meta'))
      .then((meta) => {
        const { maxSectionsPerVault, maxStoredSectionsPerVault, maxPageSize, maxPageBytes } =
          validMeta(meta).limits;
        return {
          live: maxSectionsPerVault,
          stored: maxStoredSectionsPerVault,
          pageSize: maxPageSize,
          pageBytes: maxPageBytes,
        };
      })
      .catch((error: unknown) => {
        limits = undefined;
        throw error;
      });
    return limits;
  };
}

/**
 * Whether one response's writes fit one page (`GET /meta`): at most `maxPageSize` sections and
 * `maxPageBytes` bytes of ciphertext. A server that sends more ignores the budget every honest
 * one keeps, so a reader refuses the response rather than hold it.
 *
 * @param writes The writes one response carries.
 * @param limits The server's limits.
 * @returns Whether they fit.
 */
export function fitsOnePage(
  writes: readonly Schemas['SectionWrite'][],
  limits: SectionLimits,
): boolean {
  return writes.length <= limits.pageSize && ciphertextBytes(writes) <= limits.pageBytes;
}
