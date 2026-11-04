/**
 * Why a Cloak cryptographic operation failed.
 *
 * - `decryption_failed`: wrong key, wrong context or tampered data; never says which.
 * - `invalid_format`: a blob, key or bundle has the wrong size or format version.
 * - `bad_padding`: decrypted content is not padded as the protocol requires.
 * - `bad_code`: a human-readable code has a typo, a wrong prefix, padding bits or a bad checksum.
 * - `bad_signature`: a signature does not verify against the signer's key.
 * - `key_mismatch`: an opened vault key does not match the commitment in the vault log.
 * - `invalid_kdf`: stored Argon2id parameters are outside the protocol's bounds.
 */
export type CloakCryptoErrorCode =
  | 'decryption_failed'
  | 'invalid_format'
  | 'bad_padding'
  | 'bad_code'
  | 'bad_signature'
  | 'key_mismatch'
  | 'invalid_kdf';

/** Failure of a Cloak cryptographic operation. Messages never contain key material. */
export class CloakCryptoError extends Error {
  /** Stable discriminant. */
  readonly code: CloakCryptoErrorCode;

  /**
   * @param code Stable discriminant.
   * @param message Explanation without secrets.
   * @param options Standard error options, to keep the underlying `cause`.
   */
  constructor(code: CloakCryptoErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'CloakCryptoError';
    this.code = code;
  }
}

/**
 * Tells whether a value is a {@link CloakCryptoError}.
 *
 * @param error Caught value.
 * @returns Whether it is a Cloak crypto error.
 */
export function isCloakCryptoError(error: unknown): error is CloakCryptoError {
  return error instanceof CloakCryptoError;
}
