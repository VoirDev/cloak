import type { CloakStorage } from './CloakStorage.ts';

/** Options of {@link createIndexedDbStorage}. */
export interface IndexedDbStorageOptions {
  /** Database name; `cloak` by default. Use another name to keep apps on one origin apart. */
  readonly databaseName?: string | undefined;
  /** IndexedDB factory; the global `indexedDB` by default. */
  readonly indexedDB?: IDBFactory | undefined;
}

/** The only object store; keys are the record keys, values the raw bytes. */
const STORE = 'records';

/**
 * Creates a store in the browser's IndexedDB. It persists across reloads and is shared by every
 * tab of the origin; {@link CloakStorage.update} runs in one transaction, so tabs raising the
 * same version record at once cannot lower it.
 *
 * @param options Database name and factory.
 * @returns The store; the database opens on first use.
 */
export function createIndexedDbStorage(options: IndexedDbStorageOptions = {}): CloakStorage {
  const name = options.databaseName ?? 'cloak';
  let database: Promise<IDBDatabase> | undefined;

  /** Opens the database once, creating its store on first use. */
  function open(): Promise<IDBDatabase> {
    database ??= new Promise<IDBDatabase>((resolve, reject) => {
      const factory = options.indexedDB ?? globalThis.indexedDB;
      const request = factory.open(name, 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore(STORE);
      };
      request.onsuccess = () => {
        resolve(request.result);
      };
      request.onerror = () => {
        reject(request.error ?? new Error(`Cannot open IndexedDB database ${name}`));
      };
    }).catch((error: unknown) => {
      // Let a later call retry instead of failing forever.
      database = undefined;
      throw error;
    });
    return database;
  }

  /** Runs one request in its own transaction and resolves when the transaction commits. */
  async function run<T>(
    mode: IDBTransactionMode,
    action: (store: IDBObjectStore) => IDBRequest<T>,
  ): Promise<T> {
    const db = await open();
    return new Promise<T>((resolve, reject) => {
      const transaction = db.transaction(STORE, mode);
      const request = action(transaction.objectStore(STORE));
      transaction.oncomplete = () => {
        resolve(request.result);
      };
      transaction.onerror = () => {
        reject(transaction.error ?? new Error('IndexedDB transaction failed'));
      };
      transaction.onabort = () => {
        reject(transaction.error ?? new Error('IndexedDB transaction aborted'));
      };
    });
  }

  return {
    async get(key) {
      const value: unknown = await run('readonly', (store) => store.get(key));
      return value instanceof Uint8Array ? value : undefined;
    },
    async set(key, value) {
      await run('readwrite', (store) => store.put(value.slice(), key));
    },
    async delete(key) {
      await run('readwrite', (store) => store.delete(key));
    },
    async deletePrefix(prefix) {
      // Every key with the prefix sorts between the prefix and the prefix followed by the
      // highest code unit, so one key range covers exactly them.
      await run('readwrite', (store) =>
        store.delete(IDBKeyRange.bound(prefix, `${prefix}\uffff`, false, true)),
      );
    },
    async update(key, change) {
      const db = await open();
      await new Promise<void>((resolve, reject) => {
        const transaction = db.transaction(STORE, 'readwrite');
        const store = transaction.objectStore(STORE);
        let failure: unknown;
        const read = store.get(key);
        // The put must be issued from this callback, before the transaction auto-commits, so
        // `change` is synchronous.
        read.onsuccess = () => {
          try {
            const current: unknown = read.result;
            const next = change(current instanceof Uint8Array ? current : undefined);
            if (next !== undefined) store.put(next.slice(), key);
          } catch (error: unknown) {
            failure = error;
            transaction.abort();
          }
        };
        transaction.oncomplete = () => {
          resolve();
        };
        transaction.onerror = () => {
          reject(transaction.error ?? new Error('IndexedDB transaction failed'));
        };
        transaction.onabort = () => {
          reject(
            failure instanceof Error
              ? failure
              : (transaction.error ?? new Error('IndexedDB transaction aborted')),
          );
        };
      });
    },
  };
}
