package dev.voir.cloak.server

import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Asserts that [block] fails with [code].
 *
 * @return The exception, for further checks.
 */
internal fun assertCloakError(code: CloakErrorCode, block: () -> Unit): CloakException {
    val error = assertFailsWith<CloakException> { block() }
    assertEquals(code, error.code, error.message)
    return error
}
