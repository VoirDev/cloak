import { CloakSessionClosedError } from './CloakSessionClosedError.ts';

/**
 * Lets a session's operations in until it closes, and tells it when the last one ended, so keys
 * are wiped only once nothing uses them: a write sealed under a wiped key would be readable by
 * anyone.
 */
export interface SessionGate {
  /** Whether closing has begun. */
  readonly closed: boolean;

  /**
   * Runs one operation, unless closing has begun.
   *
   * @param operation The operation.
   * @returns Its result.
   * @throws {CloakSessionClosedError} once closing has begun, without running it.
   */
  run<T>(operation: () => Promise<T>): Promise<T>;

  /**
   * Turns away new operations and resolves once every running one has ended. Calling it again
   * returns the same promise.
   */
  shut(): Promise<void>;
}

/**
 * Creates a gate.
 *
 * @returns An open gate.
 */
export function createSessionGate(): SessionGate {
  let running = 0;
  let shutting: Promise<void> | undefined;
  let idle: (() => void) | undefined;

  return {
    get closed() {
      return shutting !== undefined;
    },
    async run(operation) {
      if (shutting !== undefined) throw new CloakSessionClosedError();
      running += 1;
      try {
        return await operation();
      } finally {
        running -= 1;
        if (running === 0) idle?.();
      }
    },
    shut() {
      shutting ??=
        running === 0
          ? Promise.resolve()
          : new Promise<void>((resolve) => {
              idle = resolve;
            });
      return shutting;
    },
  };
}
