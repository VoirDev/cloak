package dev.voir.cloak.server.access

import dev.voir.cloak.server.error.CloakException

/** Request-shape checks the API schema states and the core enforces again. */
internal object Validation {
    /**
     * Checks a list's size.
     *
     * @param items List to check.
     * @param range Allowed sizes.
     * @param pointer JSON Pointer of the list.
     */
    fun size(items: Collection<*>, range: IntRange, pointer: String) {
        if (items.size !in range) {
            throw CloakException.invalid(pointer, "size", "Must hold ${range.first} to ${range.last} items.")
        }
    }

    /**
     * Checks that no two items share a key.
     *
     * @param items Items in request order.
     * @param pointer JSON Pointer of the list; the error points at the first repeated item.
     * @param key Identity of an item.
     */
    fun <T> unique(items: List<T>, pointer: String, key: (T) -> Any) {
        val seen = HashSet<Any>()
        items.forEachIndexed { index, item ->
            if (!seen.add(key(item))) throw CloakException.invalid(
                "$pointer/$index",
                "duplicate",
                "Repeats an earlier item.",
            )
        }
    }

    /**
     * Checks a rule on one value.
     *
     * @param condition Whether the value is valid.
     * @param pointer JSON Pointer of the value.
     * @param rule Name of the rule.
     * @param message Explanation.
     */
    fun require(condition: Boolean, pointer: String, rule: String, message: String) {
        if (!condition) throw CloakException.invalid(pointer, rule, message)
    }
}
