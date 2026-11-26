package dev.voir.cloak.spring.web

import dev.voir.cloak.server.error.CloakErrorCode
import dev.voir.cloak.server.error.CloakException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.uuid.Uuid

/** Query ids are taken only in their canonical form, refused otherwise as other malformed input. */
class ParamsTest {
    private val id = Uuid.parse("0192f5a4-7c3e-7b1a-9d2e-5f6a7b8c9d0e")

    @Test
    fun `a query id is taken only in its canonical lowercase hyphenated form`() {
        assertEquals(id, Params.queryId(id.toString(), "userId"))
        val spellings = listOf(
            id.toString().uppercase(),
            id.toString().replace("-", ""),
            java.util.Base64.getEncoder().encodeToString(id.toByteArray()),
            "{$id}",
        )
        for (spelling in spellings) {
            val refused = assertFailsWith<CloakException>(spelling) { Params.queryId(spelling, "userId") }
            assertEquals(CloakErrorCode.VALIDATION_FAILED, refused.code, spelling)
            assertEquals("#/query/userId", refused.fieldErrors.single().pointer, spelling)
        }
    }
}
