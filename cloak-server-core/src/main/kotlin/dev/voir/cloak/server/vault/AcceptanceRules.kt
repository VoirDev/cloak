package dev.voir.cloak.server.vault

import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.identity.IdentityOperations
import dev.voir.cloak.server.identity.domain.PublicKeys
import dev.voir.cloak.server.protocol.BlobRules
import dev.voir.cloak.server.vault.domain.Acceptance
import kotlinx.io.bytestring.ByteString

/**
 * Checks a signed acceptance (`PROTOCOL.md` §9): signed with the caller's current key version, over
 * the statement the server rebuilds. An acceptance at an older version vouches for nothing, so the
 * server keeps none.
 */
internal object AcceptanceRules {
    /**
     * Checks an acceptance's shape, before any transaction.
     *
     * @param acceptance The acceptance.
     * @param pointer JSON Pointer of the object holding `keyVersion` and `signature`; empty for the body.
     * @throws CloakException `validation_failed` for a malformed signature.
     */
    fun checkShape(acceptance: Acceptance, pointer: String) {
        BlobRules.signature(acceptance.signature, "$pointer/signature")
    }

    /**
     * Verifies an acceptance against the caller's current keys.
     *
     * @param current The caller's current key version.
     * @param acceptance The acceptance.
     * @param message Builds the statement signed at a key version.
     * @param pointer JSON Pointer of the object holding `keyVersion` and `signature`; empty for the body.
     * @throws CloakException `identity_version_conflict` with the current version when it is signed
     *   at another one, `bad_signature` when the signature does not verify.
     */
    fun verify(current: PublicKeys, acceptance: Acceptance, message: (keyVersion: Int) -> ByteString, pointer: String) {
        if (acceptance.keyVersion != current.keyVersion) {
            throw CloakException(
                CloakErrorCode.IDENTITY_VERSION_CONFLICT,
                "Sign the acceptance with your current keys, version ${current.keyVersion}.",
                currentVersion = current.keyVersion.toLong(),
            )
        }
        IdentityOperations.requireSignature(current.signingPublicKey, message(current.keyVersion), acceptance.signature, "$pointer/signature")
    }
}
