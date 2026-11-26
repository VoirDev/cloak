package dev.voir.cloak.spring.web

import dev.voir.cloak.spring.web.mapping.Wire
import tools.jackson.core.JsonParser
import tools.jackson.core.JsonToken
import tools.jackson.databind.DeserializationContext
import tools.jackson.databind.deser.std.StdScalarDeserializer
import java.util.UUID
import kotlin.uuid.toJavaUuid

/**
 * Reads a UUID of a request body only as the contract writes it: a JSON string in canonical form,
 * lowercase and hyphenated. Jackson's own reader also takes uppercase, other groupings and the 16
 * bytes in base64; this one refuses them, and any other JSON type, as a body that does not match
 * the schema, which the starter answers with `validation_failed` naming the value's pointer.
 */
internal class StrictUuidDeserializer : StdScalarDeserializer<UUID>(UUID::class.java) {
    /**
     * Reads one UUID.
     *
     * @param p Parser at the value.
     * @param ctxt Context of the read.
     * @return The UUID.
     * @throws tools.jackson.databind.DatabindException for anything but a canonical UUID string.
     */
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): UUID {
        if (!p.hasToken(JsonToken.VALUE_STRING)) return ctxt.handleUnexpectedToken(UUID::class.java, p) as UUID
        val text = p.string
        return Wire.canonicalUuid(text)?.toJavaUuid()
            ?: ctxt.handleWeirdStringValue(UUID::class.java, text, "Not a lowercase hyphenated UUID") as UUID
    }
}
