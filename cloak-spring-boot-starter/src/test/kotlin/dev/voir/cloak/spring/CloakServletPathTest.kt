package dev.voir.cloak.spring

import dev.voir.cloak.server.meta.Limits
import dev.voir.cloak.server.testing.TestClient
import dev.voir.cloak.spring.testhost.CloakTestApplication
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.http.HttpMethod.GET
import org.springframework.http.HttpMethod.POST
import org.springframework.test.web.servlet.MockMvc
import tools.jackson.databind.json.JsonMapper
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

/** A host that maps its dispatcher servlet below `/api`: Cloak and its admission move with it. */
@SpringBootTest(
    classes = [CloakTestApplication::class],
    properties = ["spring.mvc.servlet.path=/api", "cloak.max-request-size=4MB"],
)
@AutoConfigureMockMvc
class CloakServletPathTest {
    @Autowired
    private lateinit var mvc: MockMvc

    @Autowired
    private lateinit var mapper: JsonMapper

    private lateinit var api: CloakApi

    @BeforeTest
    fun setUp() {
        api = CloakApi(mvc, mapper, servletPath = "/api")
    }

    @Test
    fun `a body over the limit is refused under the servlet path before it is read`() {
        val alice = TestClient().also { assertEquals(201, api.call(POST, "/identity", it, CloakApi.registration(it)).status) }
        assertEquals(200, api.call(GET, "/meta").status)

        val response = api.call(POST, "/vaults", alice, "x".repeat(Limits.MIN_REQUEST_BYTES + 1))

        assertEquals(413, response.status)
        assertEquals("payload_too_large", response.code)
    }
}
