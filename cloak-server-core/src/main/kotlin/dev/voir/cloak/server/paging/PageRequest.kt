package dev.voir.cloak.server.paging

/**
 * Which page of a listing to return.
 *
 * @property limit Page size, 1 to 100.
 * @property cursor `nextCursor` of the previous page, or `null` for the first page.
 */
public data class PageRequest(
    /** Page size. */
    public val limit: Int = DEFAULT_LIMIT,
    /** Cursor of the previous page, or `null`. */
    public val cursor: String? = null,
) {
    /** Page size bounds of the API. */
    public companion object {
        /** Default page size. */
        public const val DEFAULT_LIMIT: Int = 50

        /** Largest page size. */
        public const val MAX_LIMIT: Int = 100

        /** Default and largest page size of an index listing, whose items are small. */
        public const val MAX_INDEX_LIMIT: Int = 1_000
    }
}
