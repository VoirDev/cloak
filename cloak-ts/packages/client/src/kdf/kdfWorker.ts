/**
 * Entry point of the password worker, published as `@voirdev/cloak-client/kdf-worker`. Load it
 * with {@link createWorkerPasswordHasher}; it answers each message with one `passwordKey`.
 *
 * @module
 */
import { answerKdfRequest } from './kdfMessages.ts';

/**
 * The parts of a dedicated worker's global scope this entry uses. The package compiles against the
 * DOM library, not the worker one, so the scope is described here rather than typed by `lib`.
 */
interface WorkerScope {
  /** Subscribes to messages from the page. */
  addEventListener(type: 'message', listener: (event: MessageEvent<unknown>) => void): void;
  /** Answers the page, transferring the key's buffer instead of copying it. */
  postMessage(message: unknown, transfer: Transferable[]): void;
}

/** This worker's global scope; the entry only ever runs as a dedicated worker. */
const scope = globalThis as unknown as WorkerScope;

scope.addEventListener('message', (event) => {
  void answerKdfRequest(event.data).then((response) => {
    scope.postMessage(response, response.ok ? [response.key.buffer] : []);
  });
});
