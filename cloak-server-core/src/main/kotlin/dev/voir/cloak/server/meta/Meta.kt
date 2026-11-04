package dev.voir.cloak.server.meta

/**
 * Capabilities and limits of this server (`GET /meta`).
 *
 * @property apiVersion Version of the OpenAPI contract.
 * @property protocolVersion Version of the signing and encoding rules.
 * @property cryptoSuites Accepted crypto suites.
 * @property acceptedBlobFormats Blob format versions accepted on write.
 * @property deprecatedBlobFormats Blob format versions readable but refused on write.
 * @property limits Size limits.
 */
public data class Meta(
    /** Version of the OpenAPI contract. */
    public val apiVersion: String,
    /** Version of the signing and encoding rules. */
    public val protocolVersion: Int,
    /** Accepted crypto suites. */
    public val cryptoSuites: List<Int>,
    /** Blob formats accepted on write. */
    public val acceptedBlobFormats: List<Int>,
    /** Blob formats refused on write. */
    public val deprecatedBlobFormats: List<Int>,
    /** Size limits. */
    public val limits: Limits,
)
