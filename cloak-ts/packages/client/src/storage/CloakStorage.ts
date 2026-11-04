/**
 * Where a client keeps what it must remember between sessions: the fingerprints it pinned, the
 * highest section versions it has seen and, when the app opts in, the device's secret key.
 *
 * It is a plain store of bytes by key; the client owns every key and value format. Records other
 * than the secret key are encrypted and bound to their key, so the store needs no trust beyond
 * keeping what it was given. Keys start with `cloak/`; one store may hold several users.
 *
 * Use {@link createIndexedDbStorage} in browsers, or implement this over the platform's own
 * storage, such as a file or the keychain.
 */
export interface CloakStorage {
  /**
   * Reads a value.
   *
   * @param key Record key.
   * @returns The value, or `undefined` when there is none.
   */
  get(key: string): Promise<Uint8Array | undefined>;

  /**
   * Writes a value, replacing any earlier one.
   *
   * @param key Record key.
   * @param value Value to keep.
   */
  set(key: string, value: Uint8Array): Promise<void>;

  /**
   * Deletes a value; deleting a missing key does nothing.
   *
   * @param key Record key.
   */
  delete(key: string): Promise<void>;

  /**
   * Deletes every value whose key starts with a prefix. The client always passes a prefix ending
   * in `/`, so a key that merely shares its first characters with another is never touched.
   *
   * @param prefix Key prefix, ending in `/`.
   */
  deletePrefix(prefix: string): Promise<void>;

  /**
   * Replaces a value with one computed from it, atomically: no other write to the key lands in
   * between, even from another tab or process sharing the store. Optional; without it the
   * client reads and writes separately, and two writers at once may keep the older of two
   * versions, which weakens rollback checks but never fails a valid read.
   *
   * @param key Record key.
   * @param change Synchronous function of the current value, or `undefined` when there is none;
   *   returns the new value, or `undefined` to leave the record as it is. An exception aborts
   *   the update and rejects the returned promise.
   */
  update?(
    key: string,
    change: (current: Uint8Array | undefined) => Uint8Array | undefined,
  ): Promise<void>;
}

/**
 * Creates a store that forgets everything when the page or process ends. Pins and versions then
 * protect only within one run, so use it for tests and short-lived scripts only.
 *
 * @returns An in-memory store.
 */
export function createMemoryStorage(): CloakStorage {
  const records = new Map<string, Uint8Array>();
  return {
    get: (key) => Promise.resolve(records.get(key)?.slice()),
    set: (key, value) => {
      records.set(key, value.slice());
      return Promise.resolve();
    },
    delete: (key) => {
      records.delete(key);
      return Promise.resolve();
    },
    deletePrefix: (prefix) => {
      for (const key of [...records.keys()]) if (key.startsWith(prefix)) records.delete(key);
      return Promise.resolve();
    },
    update: (key, change) => {
      try {
        const next = change(records.get(key)?.slice());
        if (next !== undefined) records.set(key, next.slice());
        return Promise.resolve();
      } catch (error: unknown) {
        return Promise.reject(error instanceof Error ? error : new Error(String(error)));
      }
    },
  };
}
