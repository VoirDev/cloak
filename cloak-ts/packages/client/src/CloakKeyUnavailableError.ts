/**
 * The server holds no envelope of the vault's current key for this user's keys, for example after
 * a rotation that skipped keys they had replaced. An admin delivers one with `deliverEnvelopes`.
 */
export class CloakKeyUnavailableError extends Error {
  /** The vault. */
  readonly vaultId: string;
  /** The key version this user cannot open. */
  readonly keyVersion: number;

  /**
   * @param vaultId The vault.
   * @param keyVersion The key version this user cannot open.
   */
  constructor(vaultId: string, keyVersion: number) {
    super('This user has no envelope of the vault key yet; ask an admin to deliver one');
    this.name = 'CloakKeyUnavailableError';
    this.vaultId = vaultId;
    this.keyVersion = keyVersion;
  }
}
