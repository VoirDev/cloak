package dev.voir.cloak.server.paging

/**
 * One page of a keyset-paginated listing.
 *
 * @property items Items of this page.
 * @property nextCursor Cursor of the next page, or `null` on the last page.
 */
public data class Page<out T>(
    /** Items of this page. */
    public val items: List<T>,
    /** Cursor of the next page, or `null`. */
    public val nextCursor: String?,
)
