package dev.voir.cloak.server.section

import dev.voir.cloak.server.access.Validation
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.paging.NodeCursor
import dev.voir.cloak.server.paging.PageRequest
import dev.voir.cloak.server.persistence.CloakContext
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.NodeSections
import dev.voir.cloak.server.section.domain.NodeSectionsBatch
import dev.voir.cloak.server.section.persistence.NodeAccessRepository
import dev.voir.cloak.server.section.persistence.SectionRepository
import dev.voir.cloak.server.identity.domain.HostUserId
import dev.voir.cloak.server.identity.persistence.IdentityRepository
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.server.vault.persistence.MemberRepository
import dev.voir.cloak.server.vault.persistence.VaultRepository
import java.util.UUID
import kotlin.uuid.Uuid
import kotlin.uuid.toJavaUuid
import kotlin.uuid.toKotlinUuid

/**
 * Nodes: all sections of a node the caller can read, across vaults (`/nodes`).
 *
 * @property context Database and clock.
 */
public class NodeOperations internal constructor(
    private val context: CloakContext,
) {
    /**
     * Returns one page of the latest writes of a node's sections in vaults the caller belongs to,
     * by vault and then section name: whole sections, at least one, up to [PageRequest.MAX_LIMIT]
     * of them and [Limits.MAX_PAGE_BYTES] of ciphertext.
     *
     * @param caller Authenticated user.
     * @param nodeId The node.
     * @param cursor `nextCursor` of the node's previous page, or `null` for the first page.
     * @return One page of its readable sections, with the cursor of the next page while more follow.
     * @throws CloakException `not_found` when the caller can read none; `validation_failed` for a
     *   cursor of another node or listing.
     */
    @JvmOverloads
    public fun get(caller: UserId, nodeId: NodeId, cursor: String? = null): NodeSections = context.operation("getNode") {
        val after = NodeCursor.decode(cursor, nodeId)
        asCaller(caller) {
            val read = SectionRepository.readableByNode(nodeId, caller, after, PageRequest.MAX_LIMIT)
            if (read.writes.isEmpty() && after == null) throw CloakException.notFound("node")
            NodeSections(nodeId, read.writes, read.next?.let { NodeCursor.encode(read.writes.last().section) })
        }
    }

    /**
     * Returns the readable sections of several nodes in one query, sharing one page's budget:
     * whole sections, at least one, up to [PageRequest.MAX_LIMIT] of them and
     * [Limits.MAX_PAGE_BYTES] of ciphertext, filled node by node in node id order.
     *
     * A node whose sections did not all fit carries a cursor to read on with [get]; nodes the
     * budget did not reach are listed as unread, to ask for again.
     *
     * @param caller Authenticated user.
     * @param nodeIds 1 to 100 distinct nodes.
     * @return The nodes with a readable section on this page, those without one, and those not
     *   reached, each in request order.
     */
    public fun get(caller: UserId, nodeIds: List<NodeId>): NodeSectionsBatch = context.operation("batchGetNodes") {
        Validation.size(nodeIds, 1..Limits.MAX_BATCH_SIZE, "/nodeIds")
        Validation.unique(nodeIds, "/nodeIds") { it }
        asCaller(caller) {
            val read = SectionRepository.readableByNodes(nodeIds, caller, PageRequest.MAX_LIMIT)
            val found = read.writes.groupBy { it.section.nodeId }
            val cut = read.next
            // The page ends at [cut]: nodes from it on that brought nothing were not reached.
            val unread = nodeIds.filter { it !in found && cut != null && UUID_ORDER.compare(it.value, cut.nodeId.value) >= 0 }.toSet()
            NodeSectionsBatch(
                items = nodeIds.mapNotNull { id ->
                    found[id]?.let { sections ->
                        NodeSections(id, sections, cut?.takeIf { it.nodeId == id }?.let { NodeCursor.encode(sections.last().section) })
                    }
                },
                missingNodeIds = nodeIds.filter { it !in found && it !in unread },
                unreadNodeIds = nodeIds.filter { it in unread },
            )
        }
    }

    /**
     * Removes a node's sections for the host, such as when it deletes the resource the node names:
     * every stored section of the node, live and deleted, in the vaults the user accepted where they
     * are an admin or owner when the vault is locked. Each removal takes a new change number in its
     * vault, so members' change feeds drop it (`PROTOCOL.md` §15). Unsigned, like any loss of
     * availability (§16); sections in vaults the user does not administer stay, so one person never
     * removes another's data.
     *
     * Authorize it as the deletion of the resource, and never reuse the node id afterwards: a
     * device that saw a section of it would refuse a new first write with the same name. It does
     * not wait for a write pause.
     *
     * @param hostUserId The host's id of the user on whose behalf the node is removed.
     * @param nodeId The node.
     * @return The vaults the user accepted where sections of the node remain; none for a deleted user.
     * @throws IllegalArgumentException when [hostUserId] is not a valid host user id.
     */
    public fun purge(hostUserId: String, nodeId: UUID): Set<UUID> {
        val userId = HostUserId.of(hostUserId).userId
        val node = NodeId(nodeId.toKotlinUuid())
        return context.unrecorded {
            // The user's identity row first, then the vaults in id order, as every request locks them.
            if (IdentityRepository.isDeleted(userId, lock = true)) return@unrecorded emptySet()
            val stored = NodeAccessRepository.storedSections(node).map { it.vaultId }.toSet()
            // Read without locks first, so vaults the user cannot purge in are never locked.
            val vaults = VaultRepository.lock(administered(userId, stored))
            // Read again under the locks: a role may have changed while this waited for them.
            val purged = administered(userId, vaults.keys)
            vaults.values.filter { it.id in purged }.forEach { vault ->
                val sections = NodeAccessRepository.storedSections(node).filter { it.vaultId == vault.id }
                NodeAccessRepository.deleteNode(vault.id, node)
                var changeSeq = vault.changeSeq
                sections.forEach { section ->
                    changeSeq += 1
                    NodeAccessRepository.recordRemoval(vault.id, changeSeq, node, section.sectionName)
                }
                VaultRepository.updateSections(
                    vault.copy(
                        changeSeq = changeSeq,
                        liveSections = vault.liveSections - sections.count { !it.deleted },
                        storedSections = vault.storedSections - sections.size,
                    ),
                )
            }
            val remaining = NodeAccessRepository.storedSections(node).map { it.vaultId }.toSet()
            MemberRepository.memberships(userId, remaining).filterValues { it.accepted }.keys.map { it.value.toJavaUuid() }.toSet()
        }
    }

    /** Constants of node reads. */
    private companion object {
        /** PostgreSQL's order of `uuid` values: their 16 bytes, unsigned. */
        val UUID_ORDER: Comparator<Uuid> = Comparator { a, b ->
            a.toULongs { aHigh, aLow -> b.toULongs { bHigh, bLow -> compareValuesBy(aHigh to aLow, bHigh to bLow, { it.first }, { it.second }) } }
        }
    }

    /**
     * Picks the vaults a user accepted and is an admin or owner of, as the host APIs count them.
     *
     * @param userId User.
     * @param vaultIds Vaults to look at.
     * @return Those of them the user administers.
     */
    private fun administered(userId: UserId, vaultIds: Collection<VaultId>): Set<VaultId> =
        MemberRepository.memberships(userId, vaultIds)
            .filterValues { it.accepted && it.membership.role.includes(Role.ADMIN) }
            .keys
}
