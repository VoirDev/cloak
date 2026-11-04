package dev.voir.cloak.spring.web

/**
 * Names the API operation a Cloak handler method serves, by its `operationId` in the OpenAPI
 * contract. The request interceptor reads it to tell the host's request guard which operation is
 * asked for; a test checks every handler carries the right one.
 *
 * @property value The operation's `operationId`.
 */
@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
internal annotation class CloakOperation(
    /** The operation's `operationId`. */
    val value: String,
)
