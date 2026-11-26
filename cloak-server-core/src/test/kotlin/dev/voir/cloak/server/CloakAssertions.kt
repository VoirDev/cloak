package dev.voir.cloak.server

import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
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

/**
 * Runs tasks at once, each on its own thread, released together.
 *
 * @return Each task's error code, or `null` when it succeeded, in task order.
 */
internal fun race(tasks: List<() -> Any>): List<CloakErrorCode?> {
    val pool = Executors.newFixedThreadPool(tasks.size)
    val start = CountDownLatch(1)
    val futures = tasks.map { task ->
        pool.submit<CloakErrorCode?> {
            start.await()
            try {
                task()
                null
            } catch (error: CloakException) {
                error.code
            }
        }
    }
    start.countDown()
    val outcomes = futures.map { it.get(60, TimeUnit.SECONDS) }
    pool.shutdown()
    return outcomes
}
