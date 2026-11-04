/** Which secret did not open the user's keys. */
export type CloakUnlockErrorReason =
  /** The password or the secret key is wrong; the client cannot tell which. */
  | 'wrong_credentials'
  /** The recovery key is not this user's current one. */
  | 'wrong_recovery_key';

/**
 * The secrets the user gave do not open their keys. Unlocking, changing the password, recovering
 * and replacing keys throw it; ask the user to type them again.
 *
 * A wrong password and a wrong secret key look the same: both fail one authentication tag, so the
 * client cannot say which was wrong. A bundle the server altered fails the same way, so when the
 * user is sure of both, the server may be at fault.
 */
export class CloakUnlockError extends Error {
  /** Which secret did not open the keys. */
  readonly reason: CloakUnlockErrorReason;

  /**
   * @param reason Which secret did not open the keys.
   * @param options Standard error options, keeping the underlying `CloakCryptoError` as `cause`.
   */
  constructor(reason: CloakUnlockErrorReason, options?: ErrorOptions) {
    super(
      reason === 'wrong_credentials'
        ? 'The password or the secret key is wrong'
        : 'The recovery key is wrong',
      options,
    );
    this.name = 'CloakUnlockError';
    this.reason = reason;
  }
}
