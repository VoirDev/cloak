package dev.voir.cloak.server.error

/**
 * One violated rule of a `validation_failed` problem.
 *
 * @property pointer JSON Pointer into the request body, such as `/grants/0/wrappedKey`, or
 *   `#/query/<name>` for a query parameter.
 * @property code Violated rule, such as `size`, `pattern`, `format` or `duplicate`.
 * @property message Human-readable explanation; not for display logic.
 */
public data class FieldError(
    /** JSON Pointer to the invalid value. */
    public val pointer: String,
    /** Violated rule. */
    public val code: String,
    /** Explanation for developers. */
    public val message: String,
)
