import { defineConfig } from 'vitest/config';

/** Tests run in Node and read the shared vectors from `cloak-protocol/test-vectors`. */
export default defineConfig({
  resolve: { conditions: ['source'] },
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    testTimeout: 30_000,
  },
});
