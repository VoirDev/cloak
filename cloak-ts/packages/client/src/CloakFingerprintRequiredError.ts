/**
 * Adding a person needs their keys vouched for (`PROTOCOL.md` §9): a fingerprint the user confirmed
 * out of band, or a vault the user accepted that commits them. Otherwise the server could hand over
 * its own keys under their name. Compare
 * {@link CloakFingerprintRequiredError.fingerprint} with the person, then call
 * `confirmFingerprint` and add them again.
 */
export class CloakFingerprintRequiredError extends Error {
  /** Host user id of the person to add. */
  readonly userId: string;
  /** Fingerprint of the keys the server serves for them, to compare with the person. */
  readonly fingerprint: string;

  /**
   * @param userId Host user id of the person to add.
   * @param fingerprint Fingerprint of the keys the server serves for them.
   */
  constructor(userId: string, fingerprint: string) {
    super("Confirm this person's fingerprint with them before adding them");
    this.name = 'CloakFingerprintRequiredError';
    this.userId = userId;
    this.fingerprint = fingerprint;
  }
}
