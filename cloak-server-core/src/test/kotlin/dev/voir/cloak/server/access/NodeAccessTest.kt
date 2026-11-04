package dev.voir.cloak.server.access

import dev.voir.cloak.server.CloakFixture
import dev.voir.cloak.server.assertCloakError
import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.identity.domain.HostUserId
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.server.vault.domain.LogEntryKind
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.uuid.toJavaUuid

/**
 * The host's checks by node (`PROTOCOL.md` §8.4 rule 6): a user reads a node in its home and where
 * its owner shared it, and nowhere else, whatever anyone writes under its id.
 */
class NodeAccessTest {
    private val cloak = CloakFixture()
    private val alice: TestClient = cloak.user()
    private val bob: TestClient = cloak.user()
    private val home: VaultId = cloak.createVault(alice)
    private val access get() = cloak.server.access

    /** Adds [user] to [vaultId] and accepts, so the host counts them. */
    private fun join(vaultId: VaultId, user: TestClient, role: Role = Role.VIEWER) {
        cloak.addMember(alice, vaultId, user, role)
        cloak.server.members.accept(user.id, vaultId)
    }

    @Test
    fun `lists the nodes a user can read, by node id, from their homes and shares`() {
        join(home, bob)
        val nodes = cloak.writeMany(alice, home, 5)
        val other = cloak.createVault(alice)
        val shared = cloak.node(alice, cloak.createVault(alice))
        cloak.share(alice, other, shared, "general")
        join(other, bob)
        cloak.node(alice, cloak.createVault(alice))

        val first = access.readableNodes(bob.hostUserId.value, null, 3)
        val rest = access.readableNodes(bob.hostUserId.value, first.last(), 3)

        // PostgreSQL orders uuids by their bytes, which their lowercase text orders the same way.
        assertEquals((nodes + shared).map { it.value.toJavaUuid() }.sortedBy { it.toString() }, first + rest)
        assertEquals(3, first.size)
    }

    @Test
    fun `tells how a user reads a node, in its home and by the names shared elsewhere`() {
        val node = cloak.node(alice, home, "server-1")
        cloak.write(alice, home, node, "general")
        cloak.write(alice, home, node, "login_deploy")
        val team = cloak.createVault(alice)
        join(team, bob)
        cloak.write(alice, home, node, "billing")
        cloak.share(alice, team, node, "login_deploy")

        val reads = assertNotNull(access.canRead(bob.hostUserId.value, node.value.toJavaUuid()))
        assertFalse(reads.readsHome)
        assertFalse(reads.readsAllSections)
        assertEquals(listOf(NodeVaultAccess(team.value.toJavaUuid(), Role.VIEWER, home = false, allSections = false, sectionNames = listOf("login_deploy"))), reads.vaults)
        assertEquals(emptyList(), access.readableSections(bob.hostUserId.value, node.value.toJavaUuid()))

        // A write in the shared vault since the share is what Bob reads.
        cloak.write(alice, team, node, "login_deploy")
        assertEquals(
            listOf(ReadableSection(team.value.toJavaUuid(), "login_deploy", Role.VIEWER)),
            access.readableSections(bob.hostUserId.value, node.value.toJavaUuid()),
        )

        val owner = assertNotNull(access.canRead(alice.hostUserId.value, node.value.toJavaUuid()))
        assertTrue(owner.readsHome)
        assertTrue(owner.readsAllSections)
    }

    @Test
    fun `writing another user's node id into one's own vault opens nothing`() {
        join(home, bob, Role.EDITOR)
        val node = cloak.node(alice, home, "server-1")
        cloak.write(alice, home, node, "general")
        val bobs = cloak.createVault(bob)
        val carol = cloak.user()
        cloak.addMember(bob, bobs, carol, Role.VIEWER)
        cloak.server.members.accept(carol.id, bobs)

        // Alice never shared her node into Bob's vault, so a write of it there does not stand.
        val planted = assertCloakError(CloakErrorCode.VALIDATION_FAILED) { cloak.write(bob, bobs, node, "general") }
        assertEquals("not_shared", planted.fieldErrors.single().code)
        // A node Bob creates under the same key is his own, with another id.
        assertNotEquals(node, cloak.node(bob, bobs, "server-1"))

        assertNull(access.canRead(carol.hostUserId.value, node.value.toJavaUuid()))
        assertEquals(emptyList(), access.readableSections(carol.hostUserId.value, node.value.toJavaUuid()))
    }

    @Test
    fun `a pending member and a member of a deleted vault read nothing`() {
        val node = cloak.node(alice, home)
        cloak.write(alice, home, node, "general")
        cloak.addMember(alice, home, bob, Role.VIEWER)

        assertNull(access.canRead(bob.hostUserId.value, node.value.toJavaUuid()))
        assertEquals(emptyList(), access.readableNodes(bob.hostUserId.value))
        assertNull(access.role(bob.hostUserId.value, home.value.toJavaUuid()))

        cloak.server.members.accept(bob.id, home)
        assertNotNull(access.canRead(bob.hostUserId.value, node.value.toJavaUuid()))

        cloak.server.vaults.delete(alice.id, home, cloak.entry(alice, home, LogEntryKind.VAULT_DELETED))
        assertNull(access.canRead(bob.hostUserId.value, node.value.toJavaUuid()))
        assertEquals(emptyList(), access.readableNodes(alice.hostUserId.value))
        assertNull(access.role(alice.hostUserId.value, home.value.toJavaUuid()))
    }

    @Test
    fun `a share ends when it is unshared or its owner leaves the vault`() {
        val node = cloak.node(alice, home)
        val team = cloak.createVault(bob)
        cloak.addMember(bob, team, alice, Role.ADMIN)
        cloak.server.members.accept(alice.id, team)
        val carol = cloak.user()
        cloak.addMember(bob, team, carol, Role.VIEWER)
        cloak.server.members.accept(carol.id, team)
        cloak.share(alice, team, node)
        assertNotNull(access.canRead(carol.hostUserId.value, node.value.toJavaUuid()))

        val unshare = cloak.entry(alice, team, LogEntryKind.NODE_UNSHARED, nodeId = node, sections = "*")
        cloak.server.vaults.appendNodeEntry(alice.id, team, unshare)
        assertNull(access.canRead(carol.hostUserId.value, node.value.toJavaUuid()))

        cloak.share(alice, team, node)
        assertNotNull(access.canRead(carol.hostUserId.value, node.value.toJavaUuid()))
        cloak.leave(alice, team, withCheckpoint = true)
        assertNull(access.canRead(carol.hostUserId.value, node.value.toJavaUuid()))
    }

    @Test
    fun `in the home, a section counts only if written since the node was created there`() {
        join(home, bob)
        val node = cloak.node(alice, home)
        cloak.write(alice, home, node, "general")
        cloak.write(alice, home, node, "billing")
        // A row citing a head before node_created, which the place rule never lets in.
        cloak.sql("update cloak.sections set log_seq = 1 where vault_id = '${home.value}' and section_name = 'billing'")

        assertEquals(
            listOf(ReadableSection(home.value.toJavaUuid(), "general", Role.VIEWER)),
            access.readableSections(bob.hostUserId.value, node.value.toJavaUuid()),
        )
    }

    @Test
    fun `a deleted user reads nothing`() {
        join(home, bob)
        val node = cloak.node(alice, home)
        cloak.write(alice, home, node, "general")
        cloak.server.identity.erase(HostUserId.of(bob.hostUserId.value))

        assertEquals(emptyList(), access.readableNodes(bob.hostUserId.value))
        assertEquals(emptyList(), access.readableSections(bob.hostUserId.value, node.value.toJavaUuid()))
        assertNull(access.canRead(bob.hostUserId.value, node.value.toJavaUuid()))
    }
}
