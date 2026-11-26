package dev.voir.cloak.server.vault

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.CloakSettings
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.race
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.testing.TestBlobs
import dev.voir.cloak.server.vault.domain.Acceptance
import dev.voir.cloak.server.vault.domain.AddMemberCommand
import dev.voir.cloak.server.vault.domain.CreateVaultCommand
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultAcceptance
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.server.vault.domain.VaultLogQuery
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.uuid.Uuid
import kotlin.uuid.toJavaUuid

/**
 * Accepting vaults (`PROTOCOL.md` §9, §12.4): help against being added unasked. A person added is a
 * member by the log at once, but is listed, and counted by the host, only once they accept, with an
 * acceptance signed by their current keys that the vault's view then carries.
 */
class AcceptanceTest {
    private val cloak = CloakFixture(CloakSettings.builder().maxPendingInvitations(2).build())
    private val alice: TestClient = cloak.user()
    private val bob: TestClient = cloak.user()

    @Test
    fun `the creator has accepted, an added member is pending until they accept`() {
        val vault = cloak.createVault(alice)
        val created = cloak.vault(alice, vault)
        assertTrue(created.accepted)
        assertNull(created.addedByUserId)
        assertEquals(VaultAcceptance(null, 1, alice.vaultAcceptance(vault).signature), created.acceptance)

        cloak.addMember(alice, vault, bob, Role.VIEWER)
        val pending = cloak.vault(bob, vault)
        assertFalse(pending.accepted)
        assertNull(pending.acceptance)
        assertEquals(alice.id, pending.addedByUserId)
        assertEquals(emptyList(), cloak.server.vaults.list(bob.id).items)
        assertEquals(listOf(vault), cloak.server.vaults.list(bob.id, pending = true).items.map { it.id })
        assertNull(cloak.server.access.role(bob.hostUserId.value, vault.value.toJavaUuid()))

        cloak.accept(bob, vault)
        assertTrue(cloak.vault(bob, vault).accepted)
        assertEquals(VaultAcceptance(null, 1, bob.vaultAcceptance(vault).signature), cloak.vault(bob, vault).acceptance)
        assertEquals(listOf(vault), cloak.server.vaults.list(bob.id).items.map { it.id })
        assertEquals(emptyList(), cloak.server.vaults.list(bob.id, pending = true).items)
        assertEquals(Role.VIEWER, cloak.server.access.role(bob.hostUserId.value, vault.value.toJavaUuid()))
    }

    @Test
    fun `accepting an inviter accepts their vaults, now and later`() {
        val first = cloak.createVault(alice)
        cloak.addMember(alice, first, bob, Role.VIEWER)
        val carol = cloak.user()
        val carols = cloak.createVault(carol)
        cloak.addMember(carol, carols, bob, Role.VIEWER)

        cloak.acceptInviter(bob, alice)
        cloak.acceptInviter(bob, alice)
        val later = cloak.createVault(alice)
        cloak.addMember(alice, later, bob, Role.EDITOR)

        assertTrue(cloak.vault(bob, first).accepted)
        assertTrue(cloak.vault(bob, later).accepted)
        assertFalse(cloak.vault(bob, carols).accepted)
        val byAlice = VaultAcceptance(alice.id, 1, bob.inviterAcceptance(alice.id).signature)
        assertEquals(byAlice, cloak.vault(bob, first).acceptance)
        assertEquals(byAlice, cloak.vault(bob, later).acceptance)
        assertNull(cloak.vault(bob, carols).acceptance)
        assertEquals(listOf(byAlice, byAlice), cloak.server.vaults.list(bob.id).items.map { it.acceptance })
        val batch = cloak.server.vaults.getMany(bob.id, listOf(VaultLogQuery(first), VaultLogQuery(carols), VaultLogQuery(later)))
        assertEquals(listOf(byAlice, null, byAlice), batch.map { it.vault?.acceptance })
    }

    @Test
    fun `a vault's own acceptance comes before its inviter's`() {
        val vault = cloak.createVault(alice)
        cloak.addMember(alice, vault, bob, Role.VIEWER)
        cloak.accept(bob, vault)
        cloak.acceptInviter(bob, alice)

        assertEquals(VaultAcceptance(null, 1, bob.vaultAcceptance(vault).signature), cloak.vault(bob, vault).acceptance)
    }

    @Test
    fun `an acceptance with a bad signature is refused`() {
        val vault = cloak.createVault(alice)
        cloak.addMember(alice, vault, bob, Role.VIEWER)
        val forged = Acceptance(1, alice.vaultAcceptance(vault).signature)

        val refused = assertCloakError(CloakErrorCode.BAD_SIGNATURE) { cloak.server.members.accept(bob.id, vault, forged) }
        assertTrue("/signature" in refused.detail)
        assertCloakError(CloakErrorCode.BAD_SIGNATURE) {
            cloak.server.members.acceptInviter(bob.id, alice.id, Acceptance(1, alice.inviterAcceptance(alice.id).signature))
        }
        assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.server.members.accept(bob.id, vault, Acceptance(1, TestBlobs.blob(64))) }
        assertFalse(cloak.vault(bob, vault).accepted)
    }

    @Test
    fun `an acceptance signed with another key version than the current one is refused`() {
        val vault = cloak.createVault(alice)
        cloak.addMember(alice, vault, bob, Role.VIEWER)
        val beforeReplacement = bob.vaultAcceptance(vault)
        val inviterBefore = bob.inviterAcceptance(alice.id)

        val ahead = assertCloakError(CloakErrorCode.IDENTITY_VERSION_CONFLICT) {
            cloak.server.members.accept(bob.id, vault, Acceptance(2, beforeReplacement.signature))
        }
        assertEquals(1L, ahead.currentVersion)
        cloak.replaceKeys(bob)
        val behind = assertCloakError(CloakErrorCode.IDENTITY_VERSION_CONFLICT) { cloak.server.members.accept(bob.id, vault, beforeReplacement) }
        assertEquals(2L, behind.currentVersion)
        assertCloakError(CloakErrorCode.IDENTITY_VERSION_CONFLICT) { cloak.server.members.acceptInviter(bob.id, alice.id, inviterBefore) }
        assertFalse(cloak.vault(bob, vault).accepted)
    }

    @Test
    fun `an acceptance of another vault or inviter is refused`() {
        val vault = cloak.createVault(alice)
        val other = cloak.createVault(alice)
        cloak.addMember(alice, vault, bob, Role.VIEWER)
        val carol = cloak.user()

        assertCloakError(CloakErrorCode.BAD_SIGNATURE) { cloak.server.members.accept(bob.id, vault, bob.vaultAcceptance(other)) }
        assertCloakError(CloakErrorCode.BAD_SIGNATURE) { cloak.server.members.acceptInviter(bob.id, alice.id, bob.inviterAcceptance(carol.id)) }
        // The labels keep one statement from passing for the other.
        assertCloakError(CloakErrorCode.BAD_SIGNATURE) {
            cloak.server.members.acceptInviter(bob.id, alice.id, bob.vaultAcceptance(VaultId(alice.id.value)))
        }
        assertFalse(cloak.vault(bob, vault).accepted)
    }

    @Test
    fun `accepting again after a key replacement stores the new version`() {
        val vault = cloak.createVault(alice)
        val later = cloak.createVault(alice)
        cloak.addMember(alice, vault, bob, Role.VIEWER)
        cloak.accept(bob, vault)
        cloak.acceptInviter(bob, alice)
        cloak.addMember(alice, later, bob, Role.VIEWER)

        cloak.replaceKeys(bob)
        cloak.accept(bob, vault)
        cloak.acceptInviter(bob, alice)

        assertEquals(VaultAcceptance(null, 2, bob.vaultAcceptance(vault).signature), cloak.vault(bob, vault).acceptance)
        assertEquals(VaultAcceptance(alice.id, 2, bob.inviterAcceptance(alice.id).signature), cloak.vault(bob, later).acceptance)
    }

    @Test
    fun `a new vault carries its creator's acceptance, signed for it with their current keys`() {
        val id = VaultId(Uuid.random())
        val log = cloak.entry(alice, id, LogEntryKind.VAULT_CREATED, subject = alice, role = Role.OWNER, keyVersion = 1, keyCommitment = TestBlobs.random(32), seq = 1)
        val create = { acceptance: Acceptance -> cloak.server.vaults.create(alice.id, CreateVaultCommand(id, TestBlobs.envelope(), log, acceptance)) }

        val refused = assertCloakError(CloakErrorCode.BAD_SIGNATURE) { create(alice.vaultAcceptance(VaultId(Uuid.random()))) }
        assertTrue("/acceptance/signature" in refused.detail)
        val conflict = assertCloakError(CloakErrorCode.IDENTITY_VERSION_CONFLICT) { create(Acceptance(2, alice.vaultAcceptance(id).signature)) }
        assertEquals(1L, conflict.currentVersion)
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.vault(alice, id) }

        val created = create(alice.vaultAcceptance(id))
        assertTrue(created.accepted)
        assertEquals(VaultAcceptance(null, 1, alice.vaultAcceptance(id).signature), created.acceptance)
    }

    @Test
    fun `a user holds at most the configured pending invitations, except from inviters they accept`() {
        val vaults = List(3) { cloak.createVault(alice) }
        cloak.addMember(alice, vaults[0], bob, Role.VIEWER)
        cloak.addMember(alice, vaults[1], bob, Role.VIEWER)

        assertCloakError(CloakErrorCode.TOO_MANY_INVITATIONS) { cloak.addMember(alice, vaults[2], bob, Role.VIEWER) }
        assertEquals(2, cloak.server.meta().limits.maxPendingInvitations)

        cloak.accept(bob, vaults[0])
        cloak.addMember(alice, vaults[2], bob, Role.VIEWER)
        val carol = cloak.user()
        val carols = List(3) { cloak.createVault(carol) }
        assertCloakError(CloakErrorCode.TOO_MANY_INVITATIONS) { cloak.addMember(carol, carols[0], bob, Role.VIEWER) }
        cloak.acceptInviter(bob, carol)
        carols.forEach { cloak.addMember(carol, it, bob, Role.VIEWER) }
    }

    @Test
    fun `one inviter holds at most their share of a user's pending invitations`() {
        val limited = CloakFixture(CloakSettings.builder().maxPendingInvitations(3).maxPendingInvitationsPerInviter(1).build())
        val owner = limited.user()
        val other = limited.user()
        val invitee = limited.user()
        val first = limited.createVault(owner)
        val second = limited.createVault(owner)
        val others = limited.createVault(other)

        limited.addMember(owner, first, invitee, Role.VIEWER)
        assertCloakError(CloakErrorCode.TOO_MANY_INVITATIONS) { limited.addMember(owner, second, invitee, Role.VIEWER) }
        limited.addMember(other, others, invitee, Role.VIEWER)
        assertEquals(1, limited.server.meta().limits.maxPendingInvitationsPerInviter)

        limited.accept(invitee, first)
        limited.addMember(owner, second, invitee, Role.VIEWER)
    }

    @Test
    fun `parallel additions of one user from several people never pass the pending limit`() {
        val limited = CloakFixture(CloakSettings.builder().maxPendingInvitations(2).build())
        val invitee = limited.user()
        val additions = List(6) {
            val owner = limited.user()
            val vault = limited.createVault(owner)
            addition(limited, owner, vault, invitee)
        }

        val outcomes = race(additions)

        assertEquals(2, outcomes.count { it == null }, "$outcomes")
        assertTrue(outcomes.filterNotNull().all { it == CloakErrorCode.TOO_MANY_INVITATIONS }, "$outcomes")
        assertEquals(2L, limited.number("select count(*) from cloak.vault_members where user_id = '${invitee.id.value}'"))
    }

    @Test
    fun `parallel additions of one user from one person never pass that person's share`() {
        val limited = CloakFixture(CloakSettings.builder().maxPendingInvitationsPerInviter(1).build())
        val owner = limited.user()
        val invitee = limited.user()
        val additions = List(6) { addition(limited, owner, limited.createVault(owner), invitee) }

        val outcomes = race(additions)

        assertEquals(1, outcomes.count { it == null }, "$outcomes")
        assertTrue(outcomes.filterNotNull().all { it == CloakErrorCode.TOO_MANY_INVITATIONS }, "$outcomes")
        assertEquals(1L, limited.number("select count(*) from cloak.vault_members where user_id = '${invitee.id.value}'"))
    }

    /** A signed addition of [user] to [vault] by [admin], made now and sent when called. */
    private fun addition(fixture: CloakFixture, admin: TestClient, vault: VaultId, user: TestClient): () -> Any {
        val log = fixture.entry(admin, vault, LogEntryKind.MEMBER_ADDED, subject = user, role = Role.VIEWER)
        val command = AddMemberCommand(user.id, Role.VIEWER, fixture.vault(admin, vault).keyVersion, user.keys.keyVersion, TestBlobs.envelope(), log)
        return { fixture.server.members.add(admin.id, vault, command) }
    }

    @Test
    fun `a non-member accepts nothing`() {
        val vault = cloak.createVault(alice)
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.accept(bob, vault) }
    }

    @Test
    fun `only a registered person who is not deleted can be accepted`() {
        val stranger = TestClient()
        val carol = cloak.user()
        cloak.deleteIdentity(carol)

        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.acceptInviter(bob, stranger) }
        assertCloakError(CloakErrorCode.NOT_FOUND) { cloak.acceptInviter(bob, carol) }
        assertEquals(0L, cloak.number("select count(*) from cloak.accepted_inviters"))
    }
}
