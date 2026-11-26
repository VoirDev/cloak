import type { WriteRefusal } from '@voirdev/cloak-crypto';

/**
 * Why a section write was refused: a rule of `PROTOCOL.md` §8.4 as {@link WriteRefusal} names it;
 * from this device's section marks (§15), `rollback` for a write older than one seen and `fork`
 * for another write of a version seen or one that does not chain to it; or `bad_write_hash` when
 * the server sent a `writeHash` other than the one the write's header hashes to.
 */
export type CloakSectionErrorReason = WriteRefusal | 'rollback' | 'fork' | 'bad_write_hash';

/** A section's latest write was refused; its content is not shown. */
export class CloakSectionError extends Error {
  /** Vault of the section. */
  readonly vaultId: string;
  /** Node of the section. */
  readonly nodeId: string;
  /** Section name. */
  readonly sectionName: string;
  /** Why it was refused. */
  readonly reason: CloakSectionErrorReason;

  /**
   * @param vaultId Vault of the section.
   * @param nodeId Node of the section.
   * @param sectionName Section name.
   * @param reason Why it was refused.
   */
  constructor(
    vaultId: string,
    nodeId: string,
    sectionName: string,
    reason: CloakSectionErrorReason,
  ) {
    super(`The section's latest write was refused: ${reason}`);
    this.name = 'CloakSectionError';
    this.vaultId = vaultId;
    this.nodeId = nodeId;
    this.sectionName = sectionName;
    this.reason = reason;
  }
}
