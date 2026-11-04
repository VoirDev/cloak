import { spawn, execFileSync, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';

import type { TestProject } from 'vitest/node';

/** Repository root. */
const ROOT = fileURLToPath(new URL('../../../../', import.meta.url));

/** Start script of the installed development host. */
const SERVER = `${ROOT}cloak-dev-server/build/install/cloak-dev-server/bin/cloak-dev-server`;

declare module 'vitest' {
  export interface ProvidedContext {
    /** Base URL of the running development host's Cloak API. */
    cloakBaseUrl: string;
  }
}

/** Finds a free local port. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.listen(0, () => {
      const address = server.address();
      server.close(() => {
        if (typeof address === 'object' && address !== null) resolve(address.port);
        else reject(new Error('No port'));
      });
    });
  });
}

/**
 * Builds and starts `cloak-dev-server`, a real Spring Boot host with PostgreSQL in Docker, and
 * hands its base URL to the tests.
 */
export default async function setup(project: TestProject): Promise<() => void> {
  // Always build: Gradle skips it when nothing changed, and a stale server would test old code.
  execFileSync(`${ROOT}gradlew`, [':cloak-dev-server:installDist', '-q'], {
    cwd: ROOT,
    stdio: 'inherit',
  });
  const port = await freePort();
  const server: ChildProcess = spawn(SERVER, [`--server.port=${String(port)}`], {
    stdio: 'ignore',
  });
  const baseUrl = `http://localhost:${String(port)}/cloak/v1`;
  const deadline = Date.now() + 120_000;
  for (;;) {
    try {
      if ((await fetch(`${baseUrl}/meta`)).ok) break;
    } catch {
      // Not listening yet.
    }
    if (Date.now() > deadline || server.exitCode !== null) {
      server.kill();
      throw new Error('cloak-dev-server did not start');
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  project.provide('cloakBaseUrl', baseUrl);
  return () => {
    server.kill();
  };
}
