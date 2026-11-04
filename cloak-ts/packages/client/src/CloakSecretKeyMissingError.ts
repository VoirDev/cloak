/**
 * Unlocking needs the secret key code: none was given and this device has not remembered one.
 * Ask the user for the `CS1-…` code from their kit.
 */
export class CloakSecretKeyMissingError extends Error {
  /** Host user id of the user whose secret key is unknown on this device. */
  readonly userId: string;

  /** @param userId User whose secret key is unknown on this device. */
  constructor(userId: string) {
    super('This device does not know the secret key; ask the user for their secret key code');
    this.name = 'CloakSecretKeyMissingError';
    this.userId = userId;
  }
}
