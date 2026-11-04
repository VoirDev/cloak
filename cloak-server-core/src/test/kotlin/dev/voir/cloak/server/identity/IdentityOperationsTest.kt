package dev.voir.cloak.server.identity

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.identity.domain.HostUserId
import dev.voir.cloak.server.identity.domain.KdfParams
import dev.voir.cloak.server.identity.domain.UpdateCredentialsCommand
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.protocol.Messages
import dev.voir.cloak.server.testing.TestBlobs
import dev.voir.cloak.server.testing.TestClient
import kotlinx.io.bytestring.ByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.uuid.Uuid

/** Registration, credentials, key replacement and key statements. */
class IdentityOperationsTest {
    private val cloak = CloakFixture()

    @Test
    fun `registers key version 1 with its statement`() {
        val alice = cloak.user()

        val identity = cloak.server.identity.get(alice.id)
        val keys = cloak.server.identity.userKeys(alice.id, alice.id)

        assertEquals(alice.keys, identity.keys)
        assertEquals(alice.hostUserId, identity.hostUserId)
        assertEquals(alice.hostUserId, keys.hostUserId)
        assertEquals(1, identity.credentialsVersion)
        assertEquals(listOf(1), keys.versions.map { it.keys.keyVersion })
        assertNull(keys.versions.single().recoverySignature)
    }

    @Test
    fun `refuses a second registration and a taken signing key`() {
        val alice = cloak.user()
        assertCloakError(CloakErrorCode.ALREADY_EXISTS) { cloak.server.identity.register(alice.hostUserId, alice.registration()) }

        val other = TestClient()
        val stolen = alice.registration().copy(signature = alice.sign(Messages.keyStatement(alice.keys.copy(userId = other.id), null)))
        assertCloakError(CloakErrorCode.ALREADY_EXISTS) { cloak.server.identity.register(other.hostUserId, stolen) }
    }

    @Test
    fun `refuses a statement the signing key did not sign, a small-order key and weak KDF parameters`() {
        val bob = TestClient()
        val registration = bob.registration()

        assertCloakError(CloakErrorCode.BAD_SIGNATURE) {
            cloak.server.identity.register(bob.hostUserId, registration.copy(signature = TestBlobs.blob(65)))
        }
        val identityPoint = ByteString(byteArrayOf(1) + ByteArray(31))
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) {
            cloak.server.identity.register(bob.hostUserId, registration.copy(recoverySigningPublicKey = identityPoint))
        }
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) {
            cloak.server.identity.register(bob.hostUserId, registration.copy(kdf = registration.kdf.copy(iterations = 11)))
        }
    }

    @Test
    fun `changes credentials once per version, signed by the current keys for the next version`() {
        val alice = cloak.user()
        val command = cloak.credentialsChange(alice, expected = 1)

        assertEquals(2, cloak.server.identity.updateCredentials(alice.id, command).credentialsVersion)
        val conflict = assertCloakError(CloakErrorCode.CREDENTIALS_VERSION_CONFLICT) {
            cloak.server.identity.updateCredentials(alice.id, command)
        }
        assertEquals(2, conflict.currentVersion)
    }

    @Test
    fun `refuses a credentials change whose statement does not match what it carries`() {
        val alice = cloak.user()
        val command = cloak.credentialsChange(alice, expected = 1)
        val forLater = cloak.credentialsChange(alice, expected = 2)

        assertCloakError(CloakErrorCode.BAD_SIGNATURE) {
            cloak.server.identity.updateCredentials(alice.id, command.copy(kdf = KdfParams(TestBlobs.random(16), 131_072, 4)))
        }
        assertCloakError(CloakErrorCode.BAD_SIGNATURE) {
            cloak.server.identity.updateCredentials(alice.id, command.copy(signature = forLater.signature))
        }
        assertCloakError(CloakErrorCode.BAD_SIGNATURE) {
            cloak.server.identity.updateCredentials(alice.id, command.copy(signature = TestClient().sign(ByteString(1, 2, 3))))
        }
        assertEquals(1, cloak.server.identity.get(alice.id).credentialsVersion)
    }

    @Test
    fun `a key replacement starts the credentials versions again at 1`() {
        val alice = cloak.user()
        cloak.server.identity.updateCredentials(alice.id, cloak.credentialsChange(alice, expected = 1))
        cloak.server.identity.updateCredentials(alice.id, cloak.credentialsChange(alice, expected = 2))
        val before = cloak.credentialsChange(alice, expected = 3)

        cloak.replaceKeys(alice)

        assertEquals(1, cloak.server.identity.get(alice.id).credentialsVersion)
        assertCloakError(CloakErrorCode.CREDENTIALS_VERSION_CONFLICT) { cloak.server.identity.updateCredentials(alice.id, before) }
        assertEquals(2, cloak.server.identity.updateCredentials(alice.id, cloak.credentialsChange(alice, expected = 1)).credentialsVersion)
    }

    @Test
    fun `replaces keys with a statement the old recovery key signed`() {
        val alice = cloak.user()

        cloak.replaceKeys(alice)

        val identity = cloak.server.identity.get(alice.id)
        val versions = cloak.server.identity.userKeys(alice.id, alice.id).versions
        assertEquals(2, identity.keys.keyVersion)
        assertEquals(alice.keys, identity.keys)
        assertEquals(listOf(1, 2), versions.map { it.keys.keyVersion })
        assertEquals(Messages.keysDigest(versions[0].keys), versions[1].previousKeysDigest)
    }

    @Test
    fun `refuses a replacement not signed by the current recovery key, or of a stale version`() {
        val alice = cloak.user()
        val replacement = alice.replacement()

        assertCloakError(CloakErrorCode.BAD_SIGNATURE) {
            cloak.server.identity.replaceKeys(alice.id, replacement.copy(recoverySignature = replacement.signature))
        }
        assertCloakError(CloakErrorCode.IDENTITY_VERSION_CONFLICT) {
            cloak.server.identity.replaceKeys(alice.id, replacement.copy(expectedKeyVersion = 2))
        }
        cloak.server.identity.replaceKeys(alice.id, replacement)
        assertCloakError(CloakErrorCode.IDENTITY_VERSION_CONFLICT) { cloak.server.identity.replaceKeys(alice.id, replacement) }
    }

    @Test
    fun `derives the user id from the host user id and keeps both`() {
        val host = HostUserId.of("auth0|64b7f1c2e4")
        val client = TestClient(host)
        val identity = cloak.server.identity.register(host, client.registration())

        assertEquals(UserId(Uuid.parse("cd85e682-c849-5f1b-812f-01bf96b0f91e")), identity.keys.userId)
        assertEquals(host, cloak.server.identity.get(client.id).hostUserId)
        // The same host id cannot register twice.
        assertCloakError(CloakErrorCode.ALREADY_EXISTS) { cloak.server.identity.register(host, TestClient(host).registration()) }
    }

    @Test
    fun `reads several users' keys and names the missing ones`() {
        val alice = cloak.user()
        val nobody = UserId(Uuid.random())

        val batch = cloak.server.identity.userKeys(alice.id, listOf(alice.id, nobody))

        assertEquals(listOf(alice.id), batch.items.map { it.userId })
        assertEquals(listOf(alice.hostUserId), batch.items.map { it.hostUserId })
        assertEquals(listOf(nobody), batch.missingUserIds)
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.server.identity.userKeys(alice.id, nobody) }
    }
}
