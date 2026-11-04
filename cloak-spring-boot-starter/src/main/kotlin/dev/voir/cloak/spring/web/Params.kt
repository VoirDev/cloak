package dev.voir.cloak.spring.web

import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.paging.PageRequest
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.SectionName
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.spring.web.mapping.Wire
import kotlin.uuid.Uuid

/** Parsing of path and query parameters. */
internal object Params {
    /** A vault id from the path; a malformed one cannot name anything, so it answers `not_found`. */
    fun vault(value: String): VaultId = VaultId(pathId(value, "vault"))

    /** A user id from the path. */
    fun user(value: String): UserId = UserId(pathId(value, "user"))

    /** A node id from the path. */
    fun node(value: String): NodeId = NodeId(pathId(value, "node"))

    /** A section name from the path; a malformed one answers `not_found`. */
    fun section(value: String): SectionName =
        runCatching { Wire.sectionName(value, "") }.getOrElse { throw notFound("section") }

    /**
     * Parses the page parameters.
     *
     * @param limit `limit` query value.
     * @param cursor `cursor` query value.
     * @return The page request.
     */
    fun page(limit: String?, cursor: String?): PageRequest = PageRequest(limit(limit), cursor)

    /**
     * Parses the page size.
     *
     * @param limit `limit` query value.
     * @return The size, or the default.
     */
    fun limit(limit: String?): Int =
        limit?.let { it.toIntOrNull() ?: throw Wire.invalid("#/query/limit", "type", "Must be an integer.") } ?: PageRequest.DEFAULT_LIMIT

    /**
     * Parses the page size of an index listing, whose default is its largest page.
     *
     * @param limit `limit` query value.
     * @return The size, or the default.
     */
    fun indexLimit(limit: String?): Int =
        limit?.let { it.toIntOrNull() ?: throw Wire.invalid("#/query/limit", "type", "Must be an integer.") } ?: PageRequest.MAX_INDEX_LIMIT

    /**
     * Parses a log `seq` from the path; a malformed one names no checkpoint.
     *
     * @param value Path value.
     * @return The `seq`.
     */
    fun checkpointSeq(value: String): Long = value.toLongOrNull()?.takeIf { it >= 1 } ?: throw notFound("checkpoint")

    /**
     * Parses an optional boolean from the query; absent is `false`.
     *
     * @param value Query value.
     * @param name Parameter name.
     * @return The value.
     */
    fun queryFlag(value: String?, name: String): Boolean =
        when (value) {
            null, "false" -> false
            "true" -> true
            else -> throw Wire.invalid("#/query/$name", "type", "Must be true or false.")
        }

    /**
     * Parses an optional positive number from the query.
     *
     * @param value Query value.
     * @param name Parameter name.
     * @return The value, or `null`.
     */
    fun queryLong(value: String?, name: String): Long? =
        value?.let { it.toLongOrNull()?.takeIf { n -> n >= 1 } ?: throw Wire.invalid("#/query/$name", "type", "Must be a positive integer.") }

    /**
     * Parses an optional positive 32-bit number from the query.
     *
     * @param value Query value.
     * @param name Parameter name.
     * @return The value, or `null`.
     */
    fun queryInt(value: String?, name: String): Int? =
        value?.let { it.toIntOrNull()?.takeIf { n -> n >= 1 } ?: throw Wire.invalid("#/query/$name", "type", "Must be a positive integer.") }

    /**
     * Parses a required id from the query.
     *
     * @param value Query value.
     * @param name Parameter name.
     * @return The id.
     */
    fun queryId(value: String?, name: String): Uuid =
        Wire.uuid(value ?: throw Wire.invalid("#/query/$name", "required", "Required."), "#/query/$name")

    /**
     * A `not_found` problem for a malformed path value, worded like the core's.
     *
     * @param what Kind of resource.
     * @return The exception to throw.
     */
    fun notFound(what: String): CloakException =
        CloakException(CloakErrorCode.NOT_FOUND, "The $what does not exist or is not visible to you.")

    /** Parses an id from the path. */
    private fun pathId(value: String, what: String): Uuid =
        runCatching { Wire.uuid(value, "") }.getOrElse { throw notFound(what) }
}
