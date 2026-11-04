package dev.voir.cloak.spring.web

import dev.voir.cloak.api.models.BatchGetUserKeysRequest
import dev.voir.cloak.api.models.BatchGetUserKeysResponse
import dev.voir.cloak.api.models.DeleteIdentityRequest
import dev.voir.cloak.api.models.Identity
import dev.voir.cloak.api.models.Meta
import dev.voir.cloak.api.models.RegisterIdentityRequest
import dev.voir.cloak.api.models.ReplaceKeysRequest
import dev.voir.cloak.api.models.UpdateCredentialsRequest
import dev.voir.cloak.api.models.UserKeys
import dev.voir.cloak.server.CloakServer
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.spring.web.mapping.Wire
import dev.voir.cloak.spring.web.mapping.toApi
import dev.voir.cloak.spring.web.mapping.toCommand
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

/**
 * `/meta`, `/identity…` and `/users…`.
 *
 * @property cloak Cloak operations.
 * @property callers Caller resolution.
 */
@RestController
@RequestMapping(CloakPaths.BASE)
internal class IdentityController(
    private val cloak: CloakServer,
    private val callers: Callers,
) {
    /** `GET /meta`; needs no session. */
    @GetMapping("/meta")
    @CloakOperation("getMeta")
    fun meta(): Meta = cloak.meta().toApi()

    /** `GET /identity`. */
    @GetMapping("/identity")
    @CloakOperation("getIdentity")
    fun get(request: HttpServletRequest): Identity = cloak.identity.get(callers.require(request)).toApi()

    /** `POST /identity`. */
    @PostMapping("/identity")
    @ResponseStatus(HttpStatus.CREATED)
    @CloakOperation("registerIdentity")
    fun register(request: HttpServletRequest, @RequestBody body: RegisterIdentityRequest): Identity =
        cloak.identity.register(callers.requireHost(request), body.toCommand()).toApi()

    /** `POST /identity/deletion`: the caller's signed, expiring deletion (`PROTOCOL.md` §5.7). */
    @PostMapping("/identity/deletion")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @CloakOperation("deleteIdentity")
    fun delete(request: HttpServletRequest, @RequestBody body: DeleteIdentityRequest) {
        cloak.identity.delete(callers.require(request), body.toCommand())
    }

    /** `PUT /identity/credentials`. */
    @PutMapping("/identity/credentials")
    @CloakOperation("updateCredentials")
    fun updateCredentials(request: HttpServletRequest, @RequestBody body: UpdateCredentialsRequest): Identity =
        cloak.identity.updateCredentials(callers.require(request), body.toCommand()).toApi()

    /** `PUT /identity/keys`. */
    @PutMapping("/identity/keys")
    @CloakOperation("replaceKeys")
    fun replaceKeys(request: HttpServletRequest, @RequestBody body: ReplaceKeysRequest): Identity =
        cloak.identity.replaceKeys(callers.require(request), body.toCommand()).toApi()

    /** `GET /users/{userId}/keys`. */
    @GetMapping("/users/{userId}/keys")
    @CloakOperation("getUserKeys")
    fun userKeys(request: HttpServletRequest, @PathVariable userId: String): UserKeys =
        cloak.identity.userKeys(callers.require(request), Params.user(userId)).toApi()

    /** `POST /users/keys/batch-get`. */
    @PostMapping("/users/keys/batch-get")
    @CloakOperation("batchGetUserKeys")
    fun batchUserKeys(request: HttpServletRequest, @RequestBody body: BatchGetUserKeysRequest): BatchGetUserKeysResponse =
        cloak.identity.userKeys(callers.require(request), body.userIds.map { UserId(Wire.uuid(it)) }).toApi()
}
