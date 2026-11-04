import { derivePasswordKey } from '@voirdev/cloak-crypto';
import * as z from 'zod';

/** What the page asks the password worker: one `passwordKey` (`PROTOCOL.md` §5.3). */
export interface KdfRequest {
  /** Master password, as typed; the worker normalizes it. */
  readonly password: string;
  /** 16-byte salt. */
  readonly salt: Uint8Array;
  /** Memory cost in KiB. */
  readonly memoryKib: number;
  /** Iterations. */
  readonly iterations: number;
  /** Lanes; suite 1 accepts only 1. */
  readonly parallelism: number;
}

/** What the worker answers: the key, or why it failed. */
export type KdfResponse =
  | {
      /** Discriminator. */ readonly ok: true;
      /** The 32-byte `passwordKey`. */ readonly key: Uint8Array;
    }
  | {
      /** Discriminator. */ readonly ok: false;
      /** Why it failed, for developers; never contains the password. */ readonly message: string;
    };

/** Runtime shape of a request; the worker trusts nothing it is sent. */
const requestSchema = z.object({
  password: z.string(),
  salt: z.instanceof(Uint8Array),
  memoryKib: z.number(),
  iterations: z.number(),
  parallelism: z.number(),
});

/** Runtime shape of a response; the page trusts nothing the worker sends either. */
const responseSchema = z.union([
  z.object({ ok: z.literal(true), key: z.instanceof(Uint8Array) }),
  z.object({ ok: z.literal(false), message: z.string() }),
]);

/**
 * Answers one request inside the worker. `derivePasswordKey` checks the parameters against the
 * protocol's bounds before deriving anything.
 *
 * @param data The message the worker received.
 * @returns The answer to post back.
 */
export async function answerKdfRequest(data: unknown): Promise<KdfResponse> {
  const request = requestSchema.safeParse(data);
  if (!request.success) return { ok: false, message: 'Malformed password key request' };
  const { password, ...kdf } = request.data;
  try {
    return { ok: true, key: await derivePasswordKey(password, kdf) };
  } catch (error: unknown) {
    return { ok: false, message: error instanceof Error ? error.message : 'Argon2id failed' };
  }
}

/**
 * Reads the worker's answer on the page.
 *
 * @param data The message the page received.
 * @returns The answer, or `undefined` when it has an unknown shape.
 */
export function readKdfResponse(data: unknown): KdfResponse | undefined {
  const response = responseSchema.safeParse(data);
  return response.success ? response.data : undefined;
}
