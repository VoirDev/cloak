export {
  CloakCryptoError,
  isCloakCryptoError,
  type CloakCryptoErrorCode,
  type PasswordHasher,
} from '@voirdev/cloak-crypto';
export {
  CloakApiError,
  isCloakApiError,
  type CloakApiErrorCode,
  type CloakFieldError,
} from './CloakApiError.ts';
export { CloakAccountNotEmptyError } from './CloakAccountNotEmptyError.ts';
export { CloakUnlockError, type CloakUnlockErrorReason } from './CloakUnlockError.ts';
export { CloakPasswordWorkerError } from './kdf/CloakPasswordWorkerError.ts';
export {
  createWorkerPasswordHasher,
  type PasswordWorker,
} from './kdf/createWorkerPasswordHasher.ts';
export { CloakFingerprintRequiredError } from './CloakFingerprintRequiredError.ts';
export { CloakKeyChangedError } from './CloakKeyChangedError.ts';
export { CloakKeyUnavailableError } from './CloakKeyUnavailableError.ts';
export { CloakSessionClosedError } from './CloakSessionClosedError.ts';
export { CloakSecretKeyMissingError } from './CloakSecretKeyMissingError.ts';
export { CloakSectionError, type CloakSectionErrorReason } from './CloakSectionError.ts';
export { CloakVaultLogError, type CloakVaultLogErrorReason } from './CloakVaultLogError.ts';
export { type CloakHttpOptions } from './api.ts';
export {
  createCloakClient,
  type CloakClient,
  type CloakClientOptions,
  type CredentialsResult,
  type KeyReplacementResult,
  type RememberSecretKeyOption,
} from './client.ts';
export type {
  DecryptedNode,
  DecryptedSection,
  KeyReplacementRecord,
  NodeRef,
  Page,
  SectionChange,
  SectionChanges,
  SectionInfo,
  SectionRemoval,
  VaultBatchResult,
  VaultContents,
  VaultFailure,
  VaultMember,
  VaultSummary,
  VerifiedVault,
} from './model.ts';
export { nodeIdFor } from './nodeRef.ts';
export type { CloakSession } from './session.ts';
export { createMemoryStorage, type CloakStorage } from './storage/CloakStorage.ts';
export {
  requestPersistentStorage,
  type PersistableStorage,
  type PersistentStorageResult,
} from './storage/persistentStorage.ts';
export {
  createIndexedDbStorage,
  type IndexedDbStorageOptions,
} from './storage/indexedDbStorage.ts';
