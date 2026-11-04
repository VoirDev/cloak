import type { KdfParams, PasswordHasher } from '@voirdev/cloak-crypto';

import { CloakPasswordWorkerError } from './CloakPasswordWorkerError.ts';
import { readKdfResponse, type KdfRequest } from './kdfMessages.ts';

/** The parts of a `Worker` the hasher uses, so tests and other runtimes can supply their own. */
export interface PasswordWorker {
  /** Sends the worker a request. */
  postMessage(message: unknown): void;
  /** Subscribes to the worker's answers and failures. */
  addEventListener(type: 'message', listener: (event: MessageEvent<unknown>) => void): void;
  /** Subscribes to the worker's failures. */
  addEventListener(type: 'error' | 'messageerror', listener: (event: Event) => void): void;
  /** Stops the worker at once, freeing its memory. */
  terminate(): void;
}

/**
 * Runs Argon2id in a Web Worker, so setting or checking a password does not freeze the page. Each
 * call starts a fresh worker and terminates it when the key arrives, so neither the password nor
 * Argon2id's memory outlives the call.
 *
 * Start the worker from this package's own `kdf-worker` entry, served from the app's origin: it
 * receives the password, so never load it from a URL that configuration or another origin chooses.
 *
 * ```ts
 * // Vite
 * import KdfWorker from '@voirdev/cloak-client/kdf-worker?worker';
 * const passwordHasher = createWorkerPasswordHasher(() => new KdfWorker());
 * // webpack 5
 * const passwordHasher = createWorkerPasswordHasher(
 *   () => new Worker(new URL('@voirdev/cloak-client/kdf-worker', import.meta.url), { type: 'module' }),
 * );
 * ```
 *
 * @param spawn Starts one worker running the `kdf-worker` entry.
 * @returns A hasher for `createCloakClient({ passwordHasher })`.
 */
export function createWorkerPasswordHasher(spawn: () => PasswordWorker): PasswordHasher {
  return (password: string, kdf: KdfParams) =>
    new Promise<Uint8Array>((resolve, reject) => {
      let worker: PasswordWorker;
      try {
        worker = spawn();
      } catch (error: unknown) {
        reject(new CloakPasswordWorkerError('The password worker did not start', { cause: error }));
        return;
      }
      const fail = (message: string, cause?: unknown): void => {
        worker.terminate();
        reject(new CloakPasswordWorkerError(message, cause === undefined ? {} : { cause }));
      };
      worker.addEventListener('message', (event) => {
        const response = readKdfResponse(event.data);
        if (response === undefined) {
          fail('The password worker answered something else');
          return;
        }
        if (!response.ok) {
          fail(`The password worker failed: ${response.message}`);
          return;
        }
        worker.terminate();
        resolve(response.key);
      });
      worker.addEventListener('error', (event) => {
        fail('The password worker crashed', event);
      });
      worker.addEventListener('messageerror', (event) => {
        fail('The password worker answered something unreadable', event);
      });
      const request: KdfRequest = {
        password,
        salt: kdf.salt,
        memoryKib: kdf.memoryKib,
        iterations: kdf.iterations,
        parallelism: kdf.parallelism,
      };
      worker.postMessage(request);
    });
}
