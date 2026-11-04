package dev.voir.cloak.spring.web

import com.fasterxml.jackson.annotation.JsonInclude
import org.springframework.core.ResolvableType
import org.springframework.http.MediaType
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.KotlinModule

/**
 * Reads and writes the generated Cloak models with Cloak's own JSON settings, so the host's
 * Jackson configuration can never change the wire format. It handles only classes of
 * [MODELS_PACKAGE]; everything else falls through to the host's converters.
 *
 * Absent optional values are omitted, as the API contract requires.
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

        /** Mapper with Kotlin support that omits `null` values. */
        val MAPPER: JsonMapper = JsonMapper.builder()
            .addModule(KotlinModule.Builder().build())
            .changeDefaultPropertyInclusion { it.withValueInclusion(JsonInclude.Include.NON_NULL) }
            .build()
    }
}
