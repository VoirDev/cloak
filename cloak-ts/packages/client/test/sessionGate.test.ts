import { describe, expect, it } from 'vitest';

import { createSessionGate } from '../src/sessionGate.ts';

describe('the session gate', () => {
  it('waits for running operations before it shuts, and turns new ones away at once', async () => {
    const gate = createSessionGate();
    let finish: () => void = () => undefined;
    const running = gate.run(
      () =>
        new Promise<string>((resolve) => {
          finish = () => {
            resolve('done');
          };
        }),
    );
    let shut = false;
    const shutting = gate.shut().then(() => {
      shut = true;
    });

    await expect(gate.run(() => Promise.resolve('late'))).rejects.toMatchObject({
      name: 'CloakSessionClosedError',
    });
    await Promise.resolve();
    expect(shut).toBe(false);
    expect(gate.closed).toBe(true);

    finish();
    await expect(running).resolves.toBe('done');
    await shutting;
    expect(shut).toBe(true);
  });

  it('shuts at once when idle, and after a failed operation', async () => {
    const gate = createSessionGate();
    await expect(gate.run(() => Promise.reject(new Error('boom')))).rejects.toThrow('boom');
    await gate.shut();
    await gate.shut();
    expect(gate.closed).toBe(true);
  });
});
