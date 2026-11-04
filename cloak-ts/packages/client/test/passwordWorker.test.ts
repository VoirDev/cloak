import { derivePasswordKey, type KdfParams } from '@voirdev/cloak-crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  createWorkerPasswordHasher,
  type PasswordWorker,
} from '../src/kdf/createWorkerPasswordHasher.ts';
import { answerKdfRequest } from '../src/kdf/kdfMessages.ts';

/** The cheapest parameters the protocol accepts. */
const KDF: KdfParams = {
  salt: new Uint8Array(16).fill(7),
  memoryKib: 65_536,
  iterations: 2,
  parallelism: 1,
};

/** A worker in this thread that answers with [answer], recording whether it was terminated. */
function fakeWorker(answer: (data: unknown) => Promise<unknown>) {
  const listeners = new Map<string, ((event: never) => void)[]>();
  const state = { terminated: false, sent: [] as unknown[] };
  const worker: PasswordWorker = {
    postMessage(message) {
      state.sent.push(message);
      void answer(message).then((data) => {
        for (const listener of listeners.get('message') ?? [])
          listener(new MessageEvent('message', { data }) as never);
      });
    },
    addEventListener(type: string, listener: (event: never) => void) {
      listeners.set(type, [...(listeners.get(type) ?? []), listener]);
    },
    terminate() {
      state.terminated = true;
    },
  };
  const fail = (): void => {
    for (const listener of listeners.get('error') ?? []) listener(new Event('error') as never);
  };
  return { worker, state, fail };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the password worker', () => {
  it('computes exactly the password key of the calling thread, then stops', async () => {
    const { worker, state } = fakeWorker(answerKdfRequest);

    const key = await createWorkerPasswordHasher(() => worker)('pässword', KDF);

    expect(key).toEqual(await derivePasswordKey('pässword', KDF));
    expect(state.terminated).toBe(true);
  });

  it('refuses parameters out of bounds inside the worker', async () => {
    const { worker, state } = fakeWorker(answerKdfRequest);

    await expect(
      createWorkerPasswordHasher(() => worker)('pw', { ...KDF, memoryKib: 1024 }),
    ).rejects.toMatchObject({ name: 'CloakPasswordWorkerError' });
    expect(state.terminated).toBe(true);
  });

  it('fails clearly, and stops the worker, on an answer of another shape or a crash', async () => {
    const odd = fakeWorker(() => Promise.resolve({ ok: true, key: 'not bytes' }));
    await expect(createWorkerPasswordHasher(() => odd.worker)('pw', KDF)).rejects.toMatchObject({
      name: 'CloakPasswordWorkerError',
    });
    expect(odd.state.terminated).toBe(true);

    const crashing = fakeWorker(() => new Promise(() => undefined));
    const pending = createWorkerPasswordHasher(() => crashing.worker)('pw', KDF);
    crashing.fail();
    await expect(pending).rejects.toMatchObject({ name: 'CloakPasswordWorkerError' });
    expect(crashing.state.terminated).toBe(true);

    await expect(
      createWorkerPasswordHasher(() => {
        throw new Error('blocked by the Content Security Policy');
      })('pw', KDF),
    ).rejects.toMatchObject({ name: 'CloakPasswordWorkerError' });
  });

  it('answers messages from its entry point, transferring the key', async () => {
    let listener: ((event: MessageEvent<unknown>) => void) | undefined;
    const posted: { message: unknown; transfer: unknown[] }[] = [];
    vi.stubGlobal('addEventListener', (type: string, handle: typeof listener) => {
      if (type === 'message') listener = handle;
    });
    vi.stubGlobal('postMessage', (message: unknown, transfer: unknown[]) => {
      posted.push({ message, transfer });
    });
    await import('../src/kdf/kdfWorker.ts');

    listener?.(new MessageEvent('message', { data: { password: 'pw', ...KDF } }));
    await vi.waitFor(() => {
      expect(posted).toHaveLength(1);
    });

    const [answer] = posted;
    expect(answer?.message).toEqual({ ok: true, key: await derivePasswordKey('pw', KDF) });
    expect(answer?.transfer).toHaveLength(1);
  });
});
