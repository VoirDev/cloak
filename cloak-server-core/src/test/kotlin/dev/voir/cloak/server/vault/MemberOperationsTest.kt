package dev.voir.cloak.server.vault

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.testing.TestBlobs
import dev.voir.cloak.server.vault.domain.AddMemberCommand
import dev.voir.cloak.server.vault.domain.DeliverEnvelopeCommand
import dev.voir.cloak.server.vault.domain.LeftOutWrite
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.SetMemberRoleCommand
import kotlinx.io.bytestring.ByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.uuid.Uuid

/** Adding members, roles, envelopes, leaving, rotation and key replacements. */
class MemberOperationsTest {
    private val cloak = CloakFixture()
    private val alice = cloak.user()
    private val bob = cloak.user()
    private val carol = cloak.user()
    private val vault = cloak.createVault(alice)

    @Test
    fun `an admin adds members, an editor cannot`() {
        cloak.addMember(alice, vault, bob, Role.EDITOR)

        assertEquals(Role.EDITOR, cloak.vault(bob, vault).role)
        assertNotNull(cloak.vault(bob, vault).keyEnvelope)
        assertCloakError(CloakErrorCode.ROLE_REQUIRED) { cloak.addMember(bob, vault, carol, Role.VIEWER) }
        assertCloakError(CloakErrorCode.ALREADY_EXISTS) { cloak.addMember(alice, vault, bob, Role.VIEWER) }
    }

    @Test
    fun `refuses an entry for a stale head, a stale key version or a mismatched request`() {
        val stale = cloak.entry(alice, vault, LogEntryKind.MEMBER_ADDED, subject = bob, role = Role.VIEWER)
        cloak.addMember(alice, vault, carol, Role.VIEWER)

        val conflict = assertCloakError(CloakErrorCode.LOG_CONFLICT) {
            cloak.server.members.add(alice.id, vault, AddMemberCommand(bob.id, Role.VIEWER, 1, 1, TestBlobs.envelope(), stale))
        }
        assertEquals(2, conflict.currentVersion)
        val fresh = cloak.entry(alice, vault, LogEntryKind.MEMBER_ADDED, subject = bob, role = Role.VIEWER)
        assertCloakError(CloakErrorCode.VAULT_KEY_VERSION_MISMATCH) {
            cloak.server.members.add(alice.id, vault, AddMemberCommand(bob.id, Role.VIEWER, 2, 1, TestBlobs.envelope(), fresh))
        }
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) {
            cloak.server.members.add(alice.id, vault, AddMemberCommand(bob.id, Role.EDITOR, 1, 1, TestBlobs.envelope(), fresh))
        }
    }

    @Test
    fun `refuses fields of zeros the encoding cannot tell from absent`() {
        val zeros = cloak.entry(alice, vault, LogEntryKind.MEMBER_ADDED, subject = bob, role = Role.VIEWER, keyCommitment = ByteString(ByteArray(32)))
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) {
            cloak.server.members.add(alice.id, vault, AddMemberCommand(bob.id, Role.VIEWER, 1, 1, TestBlobs.envelope(), zeros))
        }
    }

    @Test
    fun `taking away the right to write needs a checkpoint over the stored latest writes`() {
        cloak.addMember(alice, vault, bob, Role.EDITOR)
        cloak.write(bob, vault, cloak.node(alice, vault), "general")

        assertCloakError(CloakErrorCode.LOG_REJECTED) { cloak.setRole(alice, vault, bob, Role.VIEWER) }
        val wrong = cloak.entry(
            alice, vault, LogEntryKind.MEMBER_ROLE_SET, subject = bob, role = Role.VIEWER, checkpoint = TestBlobs.random(32),
        )
        assertCloakError(CloakErrorCode.CHECKPOINT_CONFLICT) {
            cloak.server.members.setRole(alice.id, vault, bob.id, SetMemberRoleCommand(Role.VIEWER, wrong))
        }

        cloak.setRole(alice, vault, bob, Role.VIEWER, withCheckpoint = true)
        assertEquals(Role.VIEWER, cloak.vault(bob, vault).role)
    }

    @Test
    fun `a checkpoint may leave out a latest write, but only while it is still the latest`() {
        cloak.addMember(alice, vault, bob, Role.EDITOR)
        val node = cloak.node(alice, vault)
        val write = cloak.write(bob, vault, node, "general")
        val leftOut = listOf(LeftOutWrite(node, SectionName("general"), write.writeHash))
        val log = cloak.entry(
            alice, vault, LogEntryKind.MEMBER_ROLE_SET, subject = bob, role = Role.VIEWER, checkpoint = cloak.checkpoint(alice, vault, leftOut),
        )
        cloak.write(bob, vault, node, "general")

        assertCloakError(CloakErrorCode.CHECKPOINT_CONFLICT) {
            cloak.server.members.setRole(alice.id, vault, bob.id, SetMemberRoleCommand(Role.VIEWER, log, leftOut))
        }
    }

    @Test
    fun `a member may lower their own role, and the vault always keeps an owner`() {
        cloak.addMember(alice, vault, bob, Role.ADMIN)

        cloak.setRole(bob, vault, bob, Role.VIEWER, withCheckpoint = true)
        assertCloakError(CloakErrorCode.LOG_REJECTED) { cloak.setRole(alice, vault, alice, Role.ADMIN) }
    }

    @Test
    fun `members leave on their own, an editor with a checkpoint`() {
        cloak.addMember(alice, vault, bob, Role.EDITOR)
        cloak.addMember(alice, vault, carol, Role.VIEWER)

        assertCloakError(CloakErrorCode.LOG_REJECTED) { cloak.leave(bob, vault, withCheckpoint = false) }
        cloak.leave(bob, vault, withCheckpoint = true)
        cloak.leave(carol, vault, withCheckpoint = false)

        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.vault(bob, vault) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.vault(carol, vault) }
    }

    @Test
    fun `a rotation removes members and reseals to exactly the rest`() {
        cloak.addMember(alice, vault, bob, Role.EDITOR)
        cloak.addMember(alice, vault, carol, Role.VIEWER)

        assertCloakError(CloakErrorCode.RECIPIENTS_MISMATCH) {
            cloak.rotate(alice, vault, removed = listOf(bob), recipients = listOf(alice to 1, bob to 1, carol to 1))
        }
        assertCloakError(CloakErrorCode.RECIPIENTS_MISMATCH) {
            cloak.rotate(alice, vault, removed = listOf(bob), recipients = listOf(alice to 1))
        }
        val rotated = cloak.rotate(alice, vault, removed = listOf(bob), recipients = listOf(alice to 1, carol to 1))

        assertEquals(2, rotated.keyVersion)
        assertNotNull(cloak.vault(carol, vault).keyEnvelope)
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.vault(bob, vault) }
        assertEquals(listOf(1, 2), cloak.server.vaults.keys(alice.id, vault).map { it.version })
        assertNotNull(cloak.server.vaults.keys(alice.id, vault).last().previousWrappedKey)
    }

    @Test
    fun `only an owner removes an owner, and nobody removes themselves in a rotation`() {
        cloak.addMember(alice, vault, bob, Role.ADMIN)
        cloak.addMember(alice, vault, carol, Role.OWNER)

        assertCloakError(CloakErrorCode.ROLE_REQUIRED) {
            cloak.rotate(bob, vault, removed = listOf(carol), recipients = listOf(alice to 1, bob to 1))
        }
        assertCloakError(CloakErrorCode.LOG_REJECTED) {
            cloak.rotate(bob, vault, removed = listOf(bob), recipients = listOf(alice to 1, carol to 1))
        }
    }

    @Test
    fun `replaced keys lose their rights until the replacement is recorded`() {
        cloak.addMember(alice, vault, bob, Role.EDITOR)
        cloak.replaceKeys(bob)

        // Bob's committed version 1 is superseded: his new keys cannot write here yet, and a
        // rotation seals nothing to the old ones.
        assertCloakError(CloakErrorCode.IDENTITY_VERSION_CONFLICT) { cloak.write(bob, vault, cloak.node(alice, vault), "general") }
        cloak.rotate(alice, vault, recipients = listOf(alice to 1))
        assertNull(cloak.vault(bob, vault).keyEnvelope)
        assertCloakError(CloakErrorCode.IDENTITY_VERSION_CONFLICT) {
            cloak.server.members.deliverEnvelope(alice.id, vault, bob.id, DeliverEnvelopeCommand(2, 1, TestBlobs.envelope()))
        }

        // Bob no longer holds the current key, so he records without an envelope and an admin
        // delivers one to his new keys.
        cloak.recordReplacement(bob, vault, withCheckpoint = true, withEnvelope = false)
        assertNull(cloak.vault(bob, vault).keyEnvelope)
        cloak.server.members.deliverEnvelope(alice.id, vault, bob.id, DeliverEnvelopeCommand(2, 2, TestBlobs.envelope()))
        assertEquals(2, cloak.vault(bob, vault).envelopeUserKeyVersion)
        cloak.write(bob, vault, cloak.node(alice, vault), "general")
    }

    @Test
    fun `a member delivers their own envelope, only an admin delivers another member's`() {
        cloak.addMember(alice, vault, bob, Role.EDITOR)
        cloak.addMember(alice, vault, carol, Role.VIEWER)
        val command = DeliverEnvelopeCommand(1, 1, TestBlobs.envelope())

        cloak.server.members.deliverEnvelope(bob.id, vault, bob.id, command)
        cloak.server.members.deliverEnvelope(alice.id, vault, carol.id, command)
        assertCloakError(CloakErrorCode.ROLE_REQUIRED) { cloak.server.members.deliverEnvelope(bob.id, vault, carol.id, command) }
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) {
            cloak.server.members.deliverEnvelope(bob.id, vault, bob.id, command.copy(userKeyVersion = 2))
        }
        assertCloakError(CloakErrorCode.VAULT_KEY_VERSION_MISMATCH) {
            cloak.server.members.deliverEnvelope(bob.id, vault, bob.id, command.copy(keyVersion = 2))
        }
    }
}
