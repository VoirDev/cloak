/** The outcome of {@link requestPersistentStorage}. */
export type PersistentStorageResult =
  /** The browser will not evict this origin's storage on its own. */
  | 'persisted'
  /** The browser may evict it under storage pressure. */
  | 'denied'
  /** This runtime has no Storage API, such as Node.js or an old browser. */
  | 'unsupported';

/** The parts of the browser's `StorageManager` this uses. */
export interface PersistableStorage {
  /** Whether the origin's storage is already persistent. */
  persisted(): Promise<boolean>;
  /** Asks the browser to make it persistent. */
  persist(): Promise<boolean>;
}

/**
 * Asks the browser not to evict this origin's storage, where `createIndexedDbStorage` keeps pins,
 * verified heads and marks (`PROTOCOL.md` §15). If the browser evicts them, the device trusts the
 * server as a new device would and no longer notices rollbacks or key swaps it would have caught;
 * a remembered secret key is lost too. Call it after the user signs in, and tell the user when it
 * is `denied`: browsers grant it more readily to installed or bookmarked apps.
 *
 * @param storage The browser's storage manager; `navigator.storage` by default.
 * @returns Whether the storage is persistent now.
 */
export async function requestPersistentStorage(
  storage: PersistableStorage | undefined = (
    globalThis as { readonly navigator?: { readonly storage?: PersistableStorage } }
  ).navigator?.storage,
): Promise<PersistentStorageResult> {
  if (storage === undefined) return 'unsupported';
  if (await storage.persisted()) return 'persisted';
  return (await storage.persist()) ? 'persisted' : 'denied';
}
