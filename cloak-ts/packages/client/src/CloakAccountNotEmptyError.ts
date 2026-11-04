/**
 * Deleting the account would leave vaults without an owner who can act: the user is the only owner
 * of each listed vault, and it has other members who are not deleted. Nothing was changed; appoint
 * another owner in each, or delete them, and try again.
 */
export class CloakAccountNotEmptyError extends Error {
  /** The vaults where the user is the only owner. */
  readonly vaultIds: readonly string[];

  /** @param vaultIds The vaults where the user is the only owner. */
  constructor(vaultIds: readonly string[]) {
    super(
      `The user is the only owner of ${String(vaultIds.length)} vault(s) with other members; ` +
        'appoint another owner first',
    );
    this.name = 'CloakAccountNotEmptyError';
    this.vaultIds = vaultIds;
  }
}
