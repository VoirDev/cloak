import { describe, expect, it } from 'vitest';

import { requestPersistentStorage } from '../src/storage/persistentStorage.ts';

describe('persistent storage', () => {
  it('asks only when not yet persistent, and reports what the browser decided', async () => {
    let asked = 0;
    const browser = (already: boolean, grants: boolean) => ({
      persisted: () => Promise.resolve(already),
      persist: () => {
        asked += 1;
        return Promise.resolve(grants);
      },
    });

    expect(await requestPersistentStorage(browser(true, false))).toBe('persisted');
    expect(asked).toBe(0);
    expect(await requestPersistentStorage(browser(false, true))).toBe('persisted');
    expect(await requestPersistentStorage(browser(false, false))).toBe('denied');
    expect(asked).toBe(2);
  });

  it('says so where there is no Storage API', async () => {
    expect(await requestPersistentStorage(undefined)).toBe('unsupported');
  });
});
