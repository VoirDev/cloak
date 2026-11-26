package dev.voir.cloak.server.meta

import dev.voir.cloak.server.protocol.BlobRules

/**
 * Size limits of the API, published by `GET /meta` so clients can check them before writing.
 *
 * @property maxSectionBytes Largest section ciphertext.
 * @property maxRequestBytes Largest request body; never below [MIN_REQUEST_BYTES].
 * @property maxBatchSize Most items per batch call, such as sections per batch write or vaults per batch
 *   rotation. A rotation's envelopes are bounded by [maxMembersPerVault] instead.
 * @property maxPageSize Largest page.
 * @property maxIndexPageSize Largest page of an index listing (section headers, checkpoint leaves).
 * @property maxPageBytes Most bytes of section ciphertext one response carries; a response always
 *   holds whole sections, at least one.
 * @property maxMembersPerVault Most members of one vault, so a rotation fits in one request.
 * @property maxSectionsPerVault Most live sections of one vault, so a checkpoint stays bounded.
 * @property maxStoredSectionsPerVault Most stored sections of one vault, deletions included.
 * @property writePauseSeconds How long a write pause holds a vault.
 * @property writePauseIntervalSeconds Least time between two pauses of one vault by the same member
 *   who is not an admin, renewals included.
 * @property minKdfMemoryKib Smallest Argon2id memory cost.
 * @property maxKdfMemoryKib Largest Argon2id memory cost.
 * @property minKdfIterations Fewest Argon2id iterations.
 * @property maxKdfIterations Most Argon2id iterations.
 * @property maxPendingInvitations Most vaults a user may be added to without accepting them.
 * @property maxPendingInvitationsPerInviter Most of those one person may have added the user to.
 * @property maxKeyVersions Most key versions of one identity, so a chain of key statements stays bounded.
 */
public data class Limits(
    /** Largest section ciphertext. */
    public val maxSectionBytes: Int,
    /** Largest request body. */
    public val maxRequestBytes: Int,
    /** Most items per batch call. */
    public val maxBatchSize: Int,
    /** Largest page. */
    public val maxPageSize: Int,
    /** Largest page of an index listing. */
    public val maxIndexPageSize: Int,
    /** Most bytes of section ciphertext one response carries. */
    public val maxPageBytes: Int,
    /** Most members of one vault. */
    public val maxMembersPerVault: Int,
    /** Most live sections of one vault. */
    public val maxSectionsPerVault: Int,
    /** Most stored sections of one vault, deletions included. */
    public val maxStoredSectionsPerVault: Int,
    /** How long a write pause holds a vault, in seconds. */
    public val writePauseSeconds: Int,
    /** Least time between two pauses of one vault by the same member who is not an admin, in seconds. */
    public val writePauseIntervalSeconds: Int,
    /** Smallest Argon2id memory cost in KiB. */
    public val minKdfMemoryKib: Int,
    /** Largest Argon2id memory cost in KiB. */
    public val maxKdfMemoryKib: Int,
    /** Fewest Argon2id iterations. */
    public val minKdfIterations: Int,
    /** Most Argon2id iterations. */
    public val maxKdfIterations: Int,
    /** Most vaults a user may be added to without accepting them. */
    public val maxPendingInvitations: Int,
    /** Most vaults one person may have added a user to without the user accepting them. */
    public val maxPendingInvitationsPerInviter: Int,
    /** Most key versions of one identity. */
    public val maxKeyVersions: Int,
) {
    /** The limits this server enforces. */
    public companion object {
        /** Most items per batch call. */
        internal const val MAX_BATCH_SIZE: Int = 100

        /** Most members of one vault. */
        public const val MAX_MEMBERS_PER_VAULT: Int = 1_000

        /** Most live sections of one vault: a deletion does not count. */
        public const val MAX_SECTIONS_PER_VAULT: Int = 100_000

        /**
         * Most bytes of section ciphertext one response carries: a read that returns ciphertext
         * holds whole sections up to it, and always at least one, so the server never loads more
         * than this for one request.
         */
        public const val MAX_PAGE_BYTES: Int = 8 * 1_048_576

        /** Most nodes created in one vault, so its log and every member's view of it stay bounded. */
        public const val MAX_NODES_PER_VAULT: Int = 100_000

        /**
         * Most key versions of one identity (`PROTOCOL.md` §5.6), so the chain of key statements a
         * reader verifies, and a key replacement's check of it, stay bounded.
         */
        public const val MAX_KEY_VERSIONS: Int = 100

        /** Most entries of one rotation request: a removal per member, then `key_rotated`. */
        internal const val MAX_ROTATION_ENTRIES: Int = MAX_MEMBERS_PER_VAULT + 1

        /** Most writes one checkpoint may leave out. */
        public const val MAX_LEFT_OUT: Int = 10_000

        /** Upper bound of one log entry in compact JSON, every field at its longest. */
        internal const val MAX_LOG_ENTRY_JSON_BYTES: Int = 640

        /** Upper bound of one member envelope of a rotation in compact JSON. */
        internal const val MAX_ENVELOPE_JSON_BYTES: Int = 256

        /** Upper bound of one write a checkpoint leaves out, in compact JSON. */
        internal const val MAX_LEFT_OUT_JSON_BYTES: Int = 256

        /** Room for the other fields of a request and its JSON punctuation. */
        internal const val REQUEST_OVERHEAD_BYTES: Int = 4_096

        /** Upper bound of the largest rotation: every member removed, every envelope, the longest left-out list. */
        internal const val MAX_ROTATION_REQUEST_BYTES: Int =
            MAX_ROTATION_ENTRIES * MAX_LOG_ENTRY_JSON_BYTES + MAX_MEMBERS_PER_VAULT * MAX_ENVELOPE_JSON_BYTES +
                MAX_LEFT_OUT * MAX_LEFT_OUT_JSON_BYTES + REQUEST_OVERHEAD_BYTES

        /** Upper bound of the largest key replacement, departure or role change: one entry, an envelope, the longest left-out list. */
        internal const val MAX_CHECKPOINT_REQUEST_BYTES: Int =
            MAX_LOG_ENTRY_JSON_BYTES + MAX_ENVELOPE_JSON_BYTES + MAX_LEFT_OUT * MAX_LEFT_OUT_JSON_BYTES + REQUEST_OVERHEAD_BYTES

        /** Upper bound of one write of the largest section: its ciphertext in base64url and the header fields. */
        internal const val MAX_SECTION_REQUEST_BYTES: Int = (1_048_576 + 2) / 3 * 4 + REQUEST_OVERHEAD_BYTES

        /**
         * Smallest request size limit a server may have: what the largest rotation, the largest
         * request with a checkpoint and one write of the largest section need, so taking access
         * away always fits in one request (`PROTOCOL.md` §13).
         */
        public const val MIN_REQUEST_BYTES: Int = 4 * 1_048_576

        /** Request size limit when the host sets none: 16 MiB. */
        public const val DEFAULT_MAX_REQUEST_BYTES: Int = 16 * 1_048_576

        init {
            check(MAX_PAGE_BYTES >= BlobRules.MAX_CIPHERTEXT_BYTES) { "MAX_PAGE_BYTES must hold the largest section" }
            check(maxOf(MAX_ROTATION_REQUEST_BYTES, MAX_CHECKPOINT_REQUEST_BYTES, MAX_SECTION_REQUEST_BYTES) <= MIN_REQUEST_BYTES) {
                "MIN_REQUEST_BYTES is below what the largest request needs"
            }
        }

        /** Smallest Argon2id memory cost in KiB. */
        internal const val MIN_KDF_MEMORY_KIB: Int = 65_536

        /** Largest Argon2id memory cost in KiB. */
        internal const val MAX_KDF_MEMORY_KIB: Int = 1_048_576

        /** Fewest Argon2id iterations. */
        internal const val MIN_KDF_ITERATIONS: Int = 2

        /** Most Argon2id iterations. */
        internal const val MAX_KDF_ITERATIONS: Int = 10
    }
}
