package dev.voir.cloak.server.section

import dev.voir.cloak.server.access.Validation
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.persistence.CloakContext
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.NodeSections
import dev.voir.cloak.server.section.domain.NodeSectionsBatch
import dev.voir.cloak.server.section.persistence.NodeAccessRepository
import dev.voir.cloak.server.section.persistence.SectionRepository
import dev.voir.cloak.server.identity.domain.HostUserId
import dev.voir.cloak.server.identity.persistence.IdentityRepository
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.persistence.MemberRepository
import dev.voir.cloak.server.vault.persistence.VaultRepository
import java.util.UUID
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
     * Returns the latest write of each of a node's sections in vaults the caller belongs to.
     *
     * @param caller Authenticated user.
     * @param nodeId The node.
     * @return Its readable sections.
     * @throws CloakException `not_found` when the caller can read none.
     */
    public fun get(caller: UserId, nodeId: NodeId): NodeSections = context.operation("getNode") {
        asCaller(caller) {
            val sections = SectionRepository.readableByNode(listOf(nodeId), caller)[nodeId] ?: throw CloakException.notFound("node")
            NodeSections(nodeId, sections)
        }
    }

    /**
     * Returns the readable sections of several nodes in one query.
     *
     * @param caller Authenticated user.
     * @param nodeIds 1 to 100 distinct nodes.
     * @return Nodes with a readable section, and the ids of the others.
     */
    public fun get(caller: UserId, nodeIds: List<NodeId>): NodeSectionsBatch = context.operation("batchGetNodes") {
        Validation.size(nodeIds, 1..Limits.MAX_BATCH_SIZE, "/nodeIds")
        Validation.unique(nodeIds, "/nodeIds") { it }
        asCaller(caller) {
            val found = SectionRepository.readableByNode(nodeIds, caller)
            NodeSectionsBatch(
                items = nodeIds.mapNotNull { id -> found[id]?.let { NodeSections(id, it) } },
                missingNodeIds = nodeIds.filterNot(found::containsKey),
            )
        }
    }

    /**
     * Removes a node's sections for the host, such as when it deletes the resource the node names:
     * every stored section of the node, live and deleted, in the vaults where the user is an admin
     * or owner. Each removal takes a new change number in its vault, so members' change feeds drop
     * it (`PROTOCOL.md` §15). Unsigned, like any loss of availability (§16); sections in vaults the
     * user does not administer stay, so one person never removes another's data.
     *
     * Authorize it as the deletion of the resource, and never reuse the node id afterwards: a
     * device that saw a section of it would refuse a new first write with the same name. It does
     * not wait for a write pause.
     *
     * @param hostUserId The host's id of the user on whose behalf the node is removed.
     * @param nodeId The node.
     * @return The vaults where sections of the node remain.
     * @throws IllegalArgumentException when [hostUserId] is not a valid host user id.
     */
    public fun purge(hostUserId: String, nodeId: UUID): Set<UUID> {
        val userId = HostUserId.of(hostUserId).userId
        val node = NodeId(nodeId.toKotlinUuid())
        return context.unrecorded {
            val stored = NodeAccessRepository.storedSections(node).groupBy { it.vaultId }
            val roles = if (IdentityRepository.isDeleted(userId, lock = false)) emptyMap() else MemberRepository.roles(userId, stored.keys)
            val purged = stored.keys.filter { roles[it]?.includes(Role.ADMIN) == true }
            // Locked in id order, as every request locks vaults, then read again under the lock.
            VaultRepository.lock(purged).values.forEach { vault ->
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
            NodeAccessRepository.storedSections(node).map { it.vaultId.value.toJavaUuid() }.toSet()
        }
    }
}
