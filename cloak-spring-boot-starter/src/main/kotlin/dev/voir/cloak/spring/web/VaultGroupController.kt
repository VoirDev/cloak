package dev.voir.cloak.spring.web

import dev.voir.cloak.api.models.AcceptInviterRequest
import dev.voir.cloak.api.models.BatchRotateVaultsRequest
import dev.voir.cloak.api.models.BatchRotateVaultsResponse
import dev.voir.cloak.api.models.WritePause
import dev.voir.cloak.api.models.WritePauseRequest
import dev.voir.cloak.server.CloakServer
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.spring.web.mapping.Wire
import dev.voir.cloak.spring.web.mapping.toApi
import dev.voir.cloak.spring.web.mapping.toCore
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

/**
 * Requests over several vaults at once: `/rotations/batch-apply`, `/write-pauses`,
 * `/write-pauses/release` and `/invitations/acceptance` (`PROTOCOL.md` §7.5, §12.4).
 *
 * @property cloak Cloak operations.
 * @property callers Caller resolution.
 */
@RestController
@RequestMapping(CloakPaths.BASE)
internal class VaultGroupController(
    private val cloak: CloakServer,
    private val callers: Callers,
) {
    /** `POST /rotations/batch-apply`. */
    @PostMapping("/rotations/batch-apply")
    @CloakOperation("batchRotateVaults")
    fun rotateMany(request: HttpServletRequest, @RequestBody body: BatchRotateVaultsRequest): BatchRotateVaultsResponse =
        BatchRotateVaultsResponse(cloak.members.rotateMany(callers.require(request), body.toCore()).map { it.toApi() })

    /** `POST /write-pauses`. */
    @PostMapping("/write-pauses")
    @CloakOperation("pauseWrites")
    fun pause(request: HttpServletRequest, @RequestBody body: WritePauseRequest): WritePause =
        WritePause(Wire.instant(cloak.members.pauseWrites(callers.require(request), body.toCore())))

    /** `POST /invitations/acceptance`: the caller accepts every vault one person adds them to. */
    @PostMapping("/invitations/acceptance")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @CloakOperation("acceptInviter")
    fun acceptInviter(request: HttpServletRequest, @RequestBody body: AcceptInviterRequest) {
        cloak.members.acceptInviter(callers.require(request), UserId(Wire.uuid(body.inviterUserId)))
    }

    /** `POST /write-pauses/release`. */
    @PostMapping("/write-pauses/release")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @CloakOperation("releaseWritePauses")
    fun release(request: HttpServletRequest, @RequestBody body: WritePauseRequest) {
        cloak.members.releaseWritePauses(callers.require(request), body.toCore())
    }
}
