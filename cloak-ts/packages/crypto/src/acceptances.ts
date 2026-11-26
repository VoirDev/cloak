import { Canonical } from './canonical.ts';
import { LABELS } from './labels.ts';

/**
 * Builds the statement a user signs to accept one vault (`PROTOCOL.md` §9), so that the vault
 * vouches for the keys its log commits.
 *
 * @param userId The accepting user.
 * @param keyVersion The user's current identity key version, whose signing key signs it.
 * @param vaultId The vault.
 * @returns Canonical message.
 */
export function vaultAcceptanceMessage(
  userId: string,
  keyVersion: number,
  vaultId: string,
): Uint8Array {
  return Canonical.of(LABELS.vaultAcceptance).uuid(userId).u32(keyVersion).uuid(vaultId).build();
}

/**
 * Builds the statement a user signs to accept every vault one person adds them to
 * (`PROTOCOL.md` §9).
 *
 * @param userId The accepting user.
 * @param keyVersion The user's current identity key version, whose signing key signs it.
 * @param inviterUserId The person whose vaults the user accepts.
 * @returns Canonical message.
 */
export function inviterAcceptanceMessage(
  userId: string,
  keyVersion: number,
  inviterUserId: string,
): Uint8Array {
  return Canonical.of(LABELS.inviterAcceptance)
    .uuid(userId)
    .u32(keyVersion)
    .uuid(inviterUserId)
    .build();
}
