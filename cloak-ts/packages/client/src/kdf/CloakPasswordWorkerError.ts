/**
 * The password worker could not compute the password key: it failed to start, which a Content
 * Security Policy without `worker-src` for it causes, crashed, ran out of memory, or answered
 * something else. Nothing was unlocked or changed. The client never falls back to the page's own
 * thread on its own; an app that wants that catches this error and uses a client without
 * `passwordHasher`.
 */
export class CloakPasswordWorkerError extends Error {
  /**
   * @param message What went wrong, for developers.
   * @param options Standard error options, keeping the worker's error as `cause`.
   */
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'CloakPasswordWorkerError';
  }
}
