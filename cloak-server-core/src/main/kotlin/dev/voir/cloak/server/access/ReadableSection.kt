package dev.voir.cloak.server.access

import dev.voir.cloak.server.vault.domain.Role
import java.util.UUID

/**
 * A live section of a node a user reads (`PROTOCOL.md` §8.4 rule 6): in the node's home, or under a
 * name shared into the vault.
 *
 * @property vaultId Vault the section lives in.
 * @property sectionName Name of the section.
 * @property role The user's role in the vault.
 */
public data class ReadableSection(
    /** Vault the section lives in. */
    public val vaultId: UUID,
    /** Name of the section. */
    public val sectionName: String,
    /** The user's role in the vault. */
    public val role: Role,
)

/**
 * One vault where a user reads a node, as an accepted member of a vault no owner deleted.
 *
 * @property vaultId The vault.
 * @property role The user's role there.
 * @property home Whether it is the node's home, where its owner created it: every section there.
 * @property allSections Whether the node is shared into it with `*`; always `true` for the home.
 * @property sectionNames The names shared into it by name; empty for the home or a `*` share.
 */
public data class NodeVaultAccess(
    /** The vault. */
    public val vaultId: UUID,
    /** The user's role there. */
    public val role: Role,
    /** Whether it is the node's home. */
    public val home: Boolean,
    /** Whether every section may be read there. */
    public val allSections: Boolean,
    /** The names shared by name. */
    public val sectionNames: List<String>,
)

/**
 * How a user reads a node: every vault where its owner created or shared it and the user is an
 * accepted member (`PROTOCOL.md` §7.7, §12.4). A host decides from it which of its own fields about
 * the node to show: the whole record to someone in its home or with a `*` share, and only what
 * matches the shared names to someone with one login, say.
 *
 * @property nodeId The node.
 * @property vaults The vaults, by id.
 */
public data class NodeAccess(
    /** The node. */
    public val nodeId: UUID,
    /** The vaults. */
    public val vaults: List<NodeVaultAccess>,
) {
    /** Whether the user reads the node in its home. */
    public val readsHome: Boolean get() = vaults.any { it.home }

    /** Whether the user may read every section of the node somewhere. */
    public val readsAllSections: Boolean get() = vaults.any { it.allSections }
}
