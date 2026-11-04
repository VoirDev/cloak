/**
 * Domain labels of every canonical message, associated data and derived key (`PROTOCOL.md` §14).
 * Each purpose has its own label, so nothing made for one purpose verifies or decrypts in another.
 */
export const LABELS = {
  /** HKDF info of the secret key's contribution to the master key. */
  secretKey: 'cloak/v1/secret-key',
  /** Associated data of the private key bundle, and its HKDF info. */
  privateKeyBundle: 'cloak/v1/private-key-bundle',
  /** Associated data of the recovery key bundle, and its HKDF info. */
  recoveryKeyBundle: 'cloak/v1/recovery-key-bundle',
  /** HKDF info of the recovery signing seed. */
  recoverySign: 'cloak/v1/recovery-sign',
  /** Fingerprint message, whose digest is a key version's `keysDigest`. */
  fingerprint: 'cloak/v1/fingerprint',
  /** Signed key statement. */
  keyStatement: 'cloak/v1/key-statement',
  /** HKDF info of a vault key's content key. */
  vaultContent: 'cloak/v1/vault-content',
  /** HKDF info of a vault key's wrapping key. */
  vaultWrap: 'cloak/v1/vault-wrap',
  /** HKDF info of a vault key's commitment. */
  vaultKeyCommit: 'cloak/v1/vault-key-commit',
  /** Context label of an envelope, and its HPKE info. */
  vaultKey: 'cloak/v1/vault-key',
  /** Associated data of a vault key's previous version. */
  vaultPrevious: 'cloak/v1/vault-previous',
  /** Signed and hashed vault log entry. */
  vaultLog: 'cloak/v1/vault-log',
  /** Associated data of section content. */
  sectionContent: 'cloak/v1/section-content',
  /** Signed and hashed section write. */
  sectionWrite: 'cloak/v1/section-write',
  /** Name of a node's UUIDv5 id. */
  node: 'cloak/v1/node',
  /** Signed new private key bundle. */
  credentials: 'cloak/v1/credentials',
  /** Signed deletion of one's own identity. */
  identityDeletion: 'cloak/v1/identity-deletion',
  /** HKDF info and associated data of a client's local state; never sent to a server. */
  localState: 'cloak/v1/local-state',
} as const satisfies Readonly<Record<string, `cloak/v1/${string}`>>;

/** One of the protocol's labels. */
export type Label = (typeof LABELS)[keyof typeof LABELS];
