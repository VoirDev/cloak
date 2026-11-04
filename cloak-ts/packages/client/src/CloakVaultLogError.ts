import type { LogRefusal } from '@voirdev/cloak-crypto';

/**
 * Why a vault log, or what the server says about it, was refused: one of the log rules of
 * `PROTOCOL.md` §7.6 as {@link LogRefusal} names them, or
 *
 * - `rollback`: the log is behind, or does not pass through, the head this device verified;
 * - `state_mismatch`: what the server says about the vault disagrees with its verified log;
 * - `key_mismatch`: a vault key does not match the commitment in the log.
 */
export type CloakVaultLogErrorReason = LogRefusal | 'rollback' | 'state_mismatch' | 'key_mismatch';

/**
 * A vault log failed verification, or the server's answer disagrees with it. The server is
 * faulty or lying; nothing it returned about the vault is used.
 */
export class CloakVaultLogError extends Error {
  /** Vault whose log was refused. */
  readonly vaultId: string;
  /** What was wrong. */
  readonly reason: CloakVaultLogErrorReason;
  /** The refused entry's `seq`, when the failure is about one entry. */
  readonly seq: number | undefined;

  /**
   * @param vaultId Vault whose log was refused.
   * @param reason What was wrong.
   * @param seq The refused entry's `seq`, if any.
   */
  constructor(vaultId: string, reason: CloakVaultLogErrorReason, seq?: number) {
    super(
      `The vault log was refused: ${reason}${seq === undefined ? '' : ` at entry ${String(seq)}`}`,
    );
    this.name = 'CloakVaultLogError';
    this.vaultId = vaultId;
    this.reason = reason;
    this.seq = seq;
  }
}
