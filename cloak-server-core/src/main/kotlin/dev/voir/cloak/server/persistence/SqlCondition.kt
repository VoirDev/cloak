package dev.voir.cloak.server.persistence

import org.jetbrains.exposed.v1.core.Op
import org.jetbrains.exposed.v1.core.QueryBuilder

/**
 * A boolean SQL condition written by hand, for check constraints the Exposed DSL cannot express,
 * such as `octet_length` or regular-expression matches.
 *
 * It declares a constraint the Flyway migration already creates, so the schema drift test sees
 * every named check in both places. [sql] must be the constant text of the migration's check and
 * must never contain input.
 *
 * @property sql Constant SQL condition, identical to the migration's.
 */
internal class SqlCondition(
    private val sql: String,
) : Op<Boolean>() {
    /** Appends [sql] unchanged. */
    override fun toQueryBuilder(queryBuilder: QueryBuilder) {
        queryBuilder.append(sql)
    }
}
