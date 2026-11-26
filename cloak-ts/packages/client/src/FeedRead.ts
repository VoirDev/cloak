import { CloakVaultLogError } from './CloakVaultLogError.ts';
import type { Schemas } from './api.ts';
import type { SectionLimits } from './limits.ts';
import { ciphertextBytes, isFeedRangeSound } from './wire.ts';

/**
 * One read of a vault's change feed, sections or headers, across its pages (`PROTOCOL.md` §12.5).
 * The server picks every page, so it could keep a reader paging forever or make it hold without
 * bound; this holds each page to what an honest feed does:
 *
 * - it covers the changes right after the previous page (see {@link isFeedRangeSound});
 * - the read ends at the latest change number the first page names, which later pages may not
 *   lower; writes made meanwhile get higher numbers and only the last page may bring them;
 * - up to that number, each section's latest write, and each removal, comes once, so no read lists
 *   more of either than a vault stores sections;
 * - a page carries at most one page's budget of ciphertext (`maxPageBytes`);
 * - a page that does not end the read brings a write or a removal.
 */
export class FeedRead {
  /** The vault. */
  readonly #vaultId: string;
  /** The server's limits: sections a vault stores, and one page's budget. */
  readonly #limits: SectionLimits;
  /** The change number the next page follows. */
  #after: number;
  /** The change number the read ends at, as the first page named it. */
  #target: number | undefined;
  /** Sections whose latest write came, up to {@link #target}. */
  readonly #writes = new Set<string>();
  /** Sections whose removal came, up to {@link #target}. */
  readonly #removals = new Set<string>();

  /**
   * @param vaultId The vault.
   * @param afterChange The change number the read follows.
   * @param limits The server's limits (`GET /meta`).
   */
  constructor(vaultId: string, afterChange: number, limits: SectionLimits) {
    this.#vaultId = vaultId;
    this.#after = afterChange;
    this.#limits = limits;
  }

  /** The change number the next page must follow. */
  get after(): number {
    return this.#after;
  }

  /**
   * Takes in the page read after {@link after}.
   *
   * @param page The page.
   * @returns Whether the read is complete.
   * @throws {CloakVaultLogError} `state_mismatch` when the page is not one an honest feed serves.
   */
  take(page: Schemas['SectionHeaderPage'] | Schemas['SectionPage']): boolean {
    const target = this.#target ?? page.lastChangeSeq;
    if (!isFeedRangeSound(page, this.#after) || page.lastChangeSeq < target) throw this.#mismatch();
    this.#target = target;
    const fresh = (seen: Set<string>, entries: readonly Schemas['SectionRemoval'][]): boolean =>
      entries.every((entry) => {
        if (entry.changeSeq > target) return true;
        const key = `${entry.nodeId}/${entry.sectionName}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    const { stored } = this.#limits;
    if (
      ciphertextBytes(page.items) > this.#limits.pageBytes ||
      !fresh(this.#writes, page.items) ||
      !fresh(this.#removals, page.removed) ||
      this.#writes.size > stored ||
      this.#removals.size > stored
    )
      throw this.#mismatch();
    const done = page.throughChangeSeq >= target;
    if (!done && page.items.length === 0 && page.removed.length === 0) throw this.#mismatch();
    this.#after = page.throughChangeSeq;
    return done;
  }

  /** The error for a page an honest feed does not serve. */
  #mismatch(): CloakVaultLogError {
    return new CloakVaultLogError(this.#vaultId, 'state_mismatch');
  }
}
