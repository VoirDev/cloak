import type { CloakClient, CloakSession, KeyReplacementResult } from '../src/index.ts';

/** A completed registration or key replacement, with the codes the user was shown. */
interface Codes {
  /** Secret key code. */
  readonly secretKeyCode: string;
  /** Recovery key code. */
  readonly recoveryKeyCode: string;
}

/**
 * Registers as an app does when nothing goes wrong: prepares, shows the codes, completes.
 *
 * @param client The user's client.
 * @param options As {@link CloakClient.prepareRegistration} takes them.
 * @returns The session with the codes.
 */
export async function register(
  client: CloakClient,
  options: Parameters<CloakClient['prepareRegistration']>[0],
): Promise<Codes & { readonly session: CloakSession }> {
  const prepared = await client.prepareRegistration(options);
  return {
    secretKeyCode: prepared.secretKeyCode,
    recoveryKeyCode: prepared.recoveryKeyCode,
    session: await prepared.complete(),
  };
}

/**
 * Replaces keys as an app does when nothing goes wrong: prepares, shows the codes, completes.
 *
 * @param client The user's client.
 * @param options As {@link CloakClient.prepareKeyReplacement} takes them.
 * @returns The result with the new codes.
 */
export async function replaceKeys(
  client: CloakClient,
  options: Parameters<CloakClient['prepareKeyReplacement']>[0],
): Promise<Codes & KeyReplacementResult> {
  const prepared = await client.prepareKeyReplacement(options);
  return {
    secretKeyCode: prepared.secretKeyCode,
    recoveryKeyCode: prepared.recoveryKeyCode,
    ...(await prepared.complete()),
  };
}
