package dev.voir.cloak.spring

import kotlin.test.Test
import kotlin.test.assertFails

/** The contract check itself must reject what the spec does not allow. */
class OpenApiContractTest {
    @Test
    fun `a body missing a required field is rejected`() {
        assertFails {
            OpenApiContract.check("GET", "/identity", 200, "application/json", """{"keys":{"userId":"x"}}""")
        }
    }

    @Test
    fun `a status the operation does not list is rejected`() {
        assertFails {
            OpenApiContract.check("GET", "/meta", 418, "application/json", "{}")
        }
    }

    @Test
    fun `a problem with an unknown code is rejected`() {
        assertFails {
            OpenApiContract.check(
                "GET",
                "/identity",
                404,
                "application/problem+json",
                """{"type":"urn:cloak:problem:nope","title":"t","status":404,"code":"nope"}""",
            )
        }
    }
}
