import { defineConfig } from 'vitest/config';

/**
 * End-to-end tests against the real Kotlin server (`cloak-dev-server`), which a global setup
 * builds and starts. Needs Docker and a JAVA_HOME Gradle can run on.
 */
export default defineConfig({
  // Workspace packages resolve to their TypeScript sources, as in the unit tests.
  resolve: { conditions: ['source'] },
  ssr: { resolve: { externalConditions: ['source'] } },
  test: {
    environment: 'node',
    include: ['test/**/*.e2e.ts'],
    globalSetup: ['test/devServer.ts'],
    testTimeout: 60_000,
    hookTimeout: 180_000,
    fileParallelism: false,
  },
});
