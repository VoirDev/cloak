// Fails when src/generated/cloakApi.ts no longer matches the OpenAPI spec, so the checked-in types
// cannot drift from the contract. Run `pnpm generate` to refresh them.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const directory = mkdtempSync(join(tmpdir(), 'cloak-api-'));
const fresh = join(directory, 'cloakApi.ts');
try {
  execFileSync(
    'pnpm',
    [
      'exec',
      'openapi-typescript',
      '../../../cloak-protocol/openapi/cloak-api.v1.yaml',
      '-o',
      fresh,
    ],
    {
      stdio: 'ignore',
    },
  );
  if (readFileSync(fresh, 'utf8') !== readFileSync('src/generated/cloakApi.ts', 'utf8')) {
    console.error(
      'src/generated/cloakApi.ts is out of date with the OpenAPI spec; run `pnpm generate`.',
    );
    process.exitCode = 1;
  }
} finally {
  rmSync(directory, { recursive: true, force: true });
}
