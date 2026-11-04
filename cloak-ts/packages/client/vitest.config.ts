import { defineConfig } from 'vitest/config';

/** Unit tests; they need no server. */
export default defineConfig({
  // Workspace packages resolve to their TypeScript sources, so tests never run against a stale or
  // missing build. Vitest externalizes dependencies, which then resolve by these conditions.
  resolve: { conditions: ['source'] },
  ssr: { resolve: { externalConditions: ['source'] } },
  test: { environment: 'node', include: ['test/**/*.test.ts'] },
});
