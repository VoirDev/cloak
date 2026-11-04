package dev.voir.cloak.server.access

import dev.voir.cloak.server.identity.domain.HostUserId
import dev.voir.cloak.server.identity.persistence.IdentityRepository
import dev.voir.cloak.server.paging.PageRequest
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.persistence.NodeAccessRepository
import dev.voir.cloak.server.persistence.CloakContext
import dev.voir.cloak.server.vault.domain.Role
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.server.vault.persistence.MemberRepository
import dev.voir.cloak.server.vault.persistence.VaultRepository
import java.util.UUID
import kotlin.uuid.Uuid
import kotlin.uuid.toJavaUuid
import kotlin.uuid.toKotlinUuid

/**
 * Access checks for the host's own endpoints, so a host can tie its plaintext data to Cloak and let
 * the same people reach it. They answer `null` or nothing instead of throwing, and never reveal
 * whether a vault exists. Callable from Java: users are host user ids, vaults and nodes plain UUIDs.
 * None of them is served over HTTP.
 *
 * **Access follows signed entries only.** A node's id derives from its owner, home vault and key,
 * and its sections are valid only where the owner's signed `node_created` and `node_shared` put it
 * (`PROTOCOL.md` §7.7). These checks read exactly that: a vault where someone wrote sections under
 * another user's node id, or added that user unasked, gives no access to it. Only memberships the
 * user accepted count (§12.4), and never in a vault an owner deleted.
 *
 * **The sharing graph is private.** Who can read what tells who shares with whom. A host must use
 * these answers for the user they are about and never show one user what another can read.
 *
 * @property context Database and clock.
 */
public class AccessOperations internal constructor(
    private val context: CloakContext,
) {
    /**
     * Returns a user's role in a vault they accepted and no owner deleted.
     *
     * @param hostUserId The host's id of the user, as its authentication gives it.
     * @param vaultId Vault.
     * @return The role, or `null` when the user is not an accepted member, is deleted, or the vault
     *   does not exist or was deleted.
     * @throws IllegalArgumentException when [hostUserId] is not a valid host user id.
     */
    public fun role(hostUserId: String, vaultId: UUID): Role? = role(hostUserId, vaultId.toKotlinUuid())

    /**
     * Returns a user's role in a vault they accepted and no owner deleted.
     *
     * @param hostUserId The host's id of the user, as its authentication gives it.
     * @param vaultId Vault.
     * @return The role, or `null` when the user is not an accepted member, is deleted, or the vault
     *   does not exist or was deleted.
     * @throws IllegalArgumentException when [hostUserId] is not a valid host user id.
     */
    @JvmName("roleOfKotlinUuid")
    public fun role(hostUserId: String, vaultId: Uuid): Role? {
        val userId = HostUserId.of(hostUserId).userId
        val vault = VaultId(vaultId)
        // A host erasure keeps the user's memberships in the logs; they give no access.
        return context.unrecorded {
            if (IdentityRepository.isDeleted(userId, lock = false)) return@unrecorded null
            val member = MemberRepository.find(vault, userId)?.takeIf { it.accepted } ?: return@unrecorded null
            member.membership.role.takeIf { VaultRepository.find(vault)?.isDeleted == false }
        }
    }

    /**
     * Lists, by node id, the nodes the user reads: created in or shared into a vault they accepted
     * and no owner deleted. Use it for a "shared with me" list; [canRead] tells how they read each.
     *
     * @param hostUserId The host's id of the user.
     * @param after Node id the previous page ended at, or `null` for the first page.
     * @param limit Page size, 1 to 1000.
     * @return One page of node ids; empty for a deleted user.
     * @throws IllegalArgumentException when [hostUserId] is not a valid host user id or [limit] is
     *   out of range.
     */
    @JvmOverloads
    public fun readableNodes(hostUserId: String, after: UUID? = null, limit: Int = PageRequest.MAX_INDEX_LIMIT): List<UUID> {
        require(limit in 1..PageRequest.MAX_INDEX_LIMIT) { "limit must be 1 to ${PageRequest.MAX_INDEX_LIMIT}" }
        val userId = HostUserId.of(hostUserId).userId
        return context.unrecorded {
            if (IdentityRepository.isDeleted(userId, lock = false)) {
                emptyList()
            } else {
                NodeAccessRepository.readableNodes(userId, after?.let { NodeId(it.toKotlinUuid()) }, limit).map { it.value.toJavaUuid() }
            }
        }
    }

    /**
     * Tells how a user reads a node: in its home, and in which vaults it is shared into, with all
     * its sections or by name. Partial access, such as one login of a server, is for the host to
     * interpret: it decides which of its own fields about the node such a user sees.
     *
     * @param hostUserId The host's id of the user.
     * @param nodeId The node.
     * @return How they read it, or `null` when they read it nowhere or are deleted.
     * @throws IllegalArgumentException when [hostUserId] is not a valid host user id.
     */
    public fun canRead(hostUserId: String, nodeId: UUID): NodeAccess? {
        val userId = HostUserId.of(hostUserId).userId
        return context.unrecorded {
            if (IdentityRepository.isDeleted(userId, lock = false)) return@unrecorded null
            val places = NodeAccessRepository.places(userId, NodeId(nodeId.toKotlinUuid()))
            if (places.isEmpty()) return@unrecorded null
            NodeAccess(
                nodeId,
                places.map { place ->
                    NodeVaultAccess(
                        vaultId = place.vaultId.value.toJavaUuid(),
                        role = place.role,
                        home = place.home,
                        allSections = place.home || place.allSince != null,
                        sectionNames = if (place.home) emptyList() else place.names.keys.map { it.value }.sorted(),
                    )
                },
            )
        }
    }

    /**
     * Lists the live sections of a node the user reads under the protocol's place rule
     * (`PROTOCOL.md` §8.4 rule 6): every section in its home, and the shared names elsewhere, each
     * written since it was shared.
     *
     * @param hostUserId The host's id of the user.
     * @param nodeId The node.
     * @return The sections, by vault and name; empty for a deleted user.
     * @throws IllegalArgumentException when [hostUserId] is not a valid host user id.
     */
    public fun readableSections(hostUserId: String, nodeId: UUID): List<ReadableSection> {
        val userId = HostUserId.of(hostUserId).userId
        val node = NodeId(nodeId.toKotlinUuid())
        return context.unrecorded {
            if (IdentityRepository.isDeleted(userId, lock = false)) return@unrecorded emptyList()
            NodeAccessRepository.places(userId, node).flatMap { place ->
                NodeAccessRepository.readableSections(node, place).map { name ->
                    ReadableSection(place.vaultId.value.toJavaUuid(), name.value, place.role)
                }
            }
        }
    }
}
