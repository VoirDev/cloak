package dev.voir.cloak.spring.web

import com.fasterxml.jackson.annotation.JsonInclude
import org.springframework.core.ResolvableType
import org.springframework.http.MediaType
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter
import tools.jackson.core.StreamReadFeature
import tools.jackson.databind.DeserializationFeature
import tools.jackson.databind.MapperFeature
import tools.jackson.databind.cfg.CoercionAction
import tools.jackson.databind.cfg.CoercionInputShape
import tools.jackson.databind.type.LogicalType
import tools.jackson.databind.json.JsonMapper
import tools.jackson.databind.module.SimpleModule
import tools.jackson.module.kotlin.KotlinModule
import java.util.UUID

/**
 * Reads and writes the generated Cloak models with Cloak's own JSON settings, so the host's
 * Jackson configuration can never change the wire format. It handles only classes of
 * [MODELS_PACKAGE]; everything else falls through to the host's converters.
 *
 * Absent optional values are omitted, as the API contract requires. Reading is as strict as the
 * contract's JSON types: a string is never taken for a number or a boolean, a number never for a
 * string or a boolean, a fraction never for an integer, a UUID only in its canonical lowercase
 * hyphenated form, and an object that repeats a key is refused. Unknown properties are ignored, as
 * the generated models declare.
 */
internal class CloakJsonConverter : JacksonJsonHttpMessageConverter(MAPPER) {
    /** Reads only Cloak models. */
    override fun canRead(type: ResolvableType, mediaType: MediaType?): Boolean =
        isCloakModel(type) && super.canRead(type, mediaType)

    /** Writes only Cloak models. */
    override fun canWrite(type: ResolvableType, valueClass: Class<*>, mediaType: MediaType?): Boolean =
        isCloakModel(type) && super.canWrite(type, valueClass, mediaType)

    /** Whether [type] is a generated Cloak model. */
    private fun isCloakModel(type: ResolvableType): Boolean = type.toClass().packageName == MODELS_PACKAGE

    /** Cloak's JSON settings. */
    companion object {
        /** Package of the generated models. */
        private const val MODELS_PACKAGE = "dev.voir.cloak.api.models"

        /** Mapper with Kotlin support that omits `null` values and coerces no JSON type into another. */
        val MAPPER: JsonMapper = JsonMapper.builder()
            .addModule(KotlinModule.Builder().build())
            // Jackson's own UUID reader takes uppercase, other groupings and 24 characters of base64.
            .addModule(SimpleModule("cloak-strict-uuid").addDeserializer(UUID::class.java, StrictUuidDeserializer()))
            .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
            .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT)
            // Jackson takes a number or a boolean for a string even without scalar coercion.
            .withCoercionConfig(LogicalType.Textual) { config ->
                for (shape in listOf(CoercionInputShape.Integer, CoercionInputShape.Float, CoercionInputShape.Boolean)) {
                    config.setCoercion(shape, CoercionAction.Fail)
                }
            }
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .changeDefaultPropertyInclusion { it.withValueInclusion(JsonInclude.Include.NON_NULL) }
            .build()
    }
}
