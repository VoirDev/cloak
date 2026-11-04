/**
 * A user's keys disagree with what this device trusts (`PROTOCOL.md` §9): the server served other
 * keys for a version the device pinned, two different statements for one version, or a statement
 * that does not chain. The device keeps what it trusts; compare both fingerprints with the person
 * before trusting anything new.
 */
export class CloakKeyChangedError extends Error {
  /** Host user id of the person whose keys disagree, or their Cloak id before it is known. */
  readonly userId: string;
  /** Key version where they disagree. */
  readonly keyVersion: number;
  /** Fingerprint this device trusts for that version, when it has one. */
  readonly trustedFingerprint: string | undefined;
  /** Fingerprint the server served, when it served keys at all. */
  readonly servedFingerprint: string | undefined;

  /**
   * @param userId Host user id of the person whose keys disagree.
   * @param keyVersion Key version where they disagree.
   * @param trustedFingerprint Fingerprint this device trusts.
   * @param servedFingerprint Fingerprint the server served.
   */
  constructor(
    userId: string,
    keyVersion: number,
    trustedFingerprint: string | undefined,
    servedFingerprint: string | undefined,
  ) {
    super("The server's keys for this user disagree with the ones this device trusts");
    this.name = 'CloakKeyChangedError';
    this.userId = userId;
    this.keyVersion = keyVersion;
    this.trustedFingerprint = trustedFingerprint;
    this.servedFingerprint = servedFingerprint;
  }
}
