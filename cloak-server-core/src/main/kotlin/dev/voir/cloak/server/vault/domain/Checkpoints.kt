package dev.voir.cloak.server.vault.domain

import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.SectionName
import kotlinx.io.bytestring.ByteString

/**
 * A section's latest write as a checkpoint holds it (`PROTOCOL.md` §7.5).
 *
 * @property nodeId Node of the section.
 * @property sectionName Section name.
 * @property dataVersion Data version of the write.
 * @property writeHash `writeHash` of the write.
 */
public data class CheckpointLeaf(
    /** Node of the section. */
    public val nodeId: NodeId,
    /** Section name. */
    public val sectionName: SectionName,
    /** Data version of the write. */
    public val dataVersion: Long,
    /** `writeHash` of the write. */
    public val writeHash: ByteString,
)

/**
 * A leaf with its RFC 6962 audit path.
 *
 * @property index Index of the leaf, from 0.
 * @property leaf The leaf.
 * @property path Sibling hashes from the leaf up to the root.
 */
public data class LeafProof(
    /** Index of the leaf. */
    public val index: Long,
    /** The leaf. */
    public val leaf: CheckpointLeaf,
    /** Sibling hashes, leaf to root. */
    public val path: List<ByteString>,
)

/**
 * What a checkpoint holds for one section: its leaf, or the neighbouring leaves that show it is
 * not in the checkpoint (either absent at an edge).
 *
 * @property checkpointSeq Log entry carrying the checkpoint.
 * @property size Number of leaves.
 * @property inclusion The section's leaf, when present.
 * @property before The leaf just before the section's place, when absent.
 * @property after The leaf just after the section's place, when absent.
 */
public data class CheckpointProof(
    /** Log entry carrying the checkpoint. */
    public val checkpointSeq: Long,
    /** Number of leaves. */
    public val size: Long,
    /** The section's leaf. */
    public val inclusion: LeafProof?,
    /** The leaf before the section's place. */
    public val before: LeafProof?,
    /** The leaf after the section's place. */
    public val after: LeafProof?,
)

/**
 * What to prove: a section in the checkpoint of one log entry.
 *
 * @property checkpointSeq Log entry carrying the checkpoint.
 * @property nodeId Node of the section.
 * @property sectionName Section name.
 */
public data class CheckpointProofQuery(
    /** Log entry carrying the checkpoint. */
    public val checkpointSeq: Long,
    /** Node of the section. */
    public val nodeId: NodeId,
    /** Section name. */
    public val sectionName: SectionName,
)

/**
 * One page of a checkpoint's leaves in checkpoint order.
 *
 * @property checkpointSeq Log entry carrying the checkpoint.
 * @property size Number of leaves of the whole checkpoint.
 * @property leaves Leaves of this page, continuing the previous page.
 * @property nextCursor Cursor of the next page, or `null` on the last page.
 */
public data class CheckpointLeafPage(
    /** Log entry carrying the checkpoint. */
    public val checkpointSeq: Long,
    /** Number of leaves of the checkpoint. */
    public val size: Int,
    /** Leaves of this page. */
    public val leaves: List<CheckpointLeaf>,
    /** Cursor of the next page, or `null`. */
    public val nextCursor: String?,
)

/**
 * A section's latest write that a checkpoint leaves out (`PROTOCOL.md` §7.5).
 *
 * @property nodeId Node of the section.
 * @property sectionName Section name.
 * @property writeHash `writeHash` of the write left out; it must still be the latest.
 */
public data class LeftOutWrite(
    /** Node of the section. */
    public val nodeId: NodeId,
    /** Section name. */
    public val sectionName: SectionName,
    /** `writeHash` of the write left out. */
    public val writeHash: ByteString,
)
