package dev.voir.cloak.spring.web

import dev.voir.cloak.api.models.AddMemberRequest
import dev.voir.cloak.api.models.DeliverEnvelopeRequest
import dev.voir.cloak.api.models.LeaveVaultRequest
import dev.voir.cloak.api.models.RecordKeyReplacementRequest
import dev.voir.cloak.api.models.RotateVaultRequest
import dev.voir.cloak.api.models.SetMemberRoleRequest
import dev.voir.cloak.api.models.Vault
import dev.voir.cloak.server.CloakServer
import dev.voir.cloak.spring.web.mapping.toApi
import dev.voir.cloak.spring.web.mapping.toCommand
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

/**
 * `…/members`, `…/members/{userId}`, `…/members/{userId}/envelope`, `…/acceptance`,
 * `…/departures`, `…/rotations` and `…/key-replacements` of a vault.
 *
 * @property cloak Cloak operations.
 * @property callers Caller resolution.
 */
@RestController
@RequestMapping("${CloakPaths.BASE}/vaults/{vaultId}")
internal class MemberController(
    private val cloak: CloakServer,
    private val callers: Callers,
) {
    /** `POST /vaults/{vaultId}/members`. */
    @PostMapping("/members")
    @ResponseStatus(HttpStatus.CREATED)
    @CloakOperation("addMember")
    fun add(request: HttpServletRequest, @PathVariable vaultId: String, @RequestBody body: AddMemberRequest): Vault =
        cloak.members.add(callers.require(request), Params.vault(vaultId), body.toCommand()).toApi()

    /** `PATCH /vaults/{vaultId}/members/{userId}`. */
    @PatchMapping("/members/{userId}")
    @CloakOperation("setMemberRole")
    fun setRole(
        request: HttpServletRequest,
        @PathVariable vaultId: String,
        @PathVariable userId: String,
        @RequestBody body: SetMemberRoleRequest,
    ): Vault = cloak.members.setRole(callers.require(request), Params.vault(vaultId), Params.user(userId), body.toCommand()).toApi()

    /** `PUT /vaults/{vaultId}/members/{userId}/envelope`. */
    @PutMapping("/members/{userId}/envelope")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @CloakOperation("deliverEnvelope")
    fun deliverEnvelope(
        request: HttpServletRequest,
        @PathVariable vaultId: String,
        @PathVariable userId: String,
        @RequestBody body: DeliverEnvelopeRequest,
    ) {
        cloak.members.deliverEnvelope(callers.require(request), Params.vault(vaultId), Params.user(userId), body.toCommand())
    }

    /** `POST /vaults/{vaultId}/departures`. */
    @PostMapping("/departures")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @CloakOperation("leaveVault")
    fun leave(request: HttpServletRequest, @PathVariable vaultId: String, @RequestBody body: LeaveVaultRequest) {
        cloak.members.leave(callers.require(request), Params.vault(vaultId), body.toCommand())
    }

    /** `POST /vaults/{vaultId}/rotations`. */
    @PostMapping("/rotations")
    @CloakOperation("rotateVault")
    fun rotate(request: HttpServletRequest, @PathVariable vaultId: String, @RequestBody body: RotateVaultRequest): Vault =
        cloak.members.rotate(callers.require(request), Params.vault(vaultId), body.toCommand()).toApi()

    /** `PUT /vaults/{vaultId}/acceptance`: the caller accepts a vault they were added to. */
    @PutMapping("/acceptance")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @CloakOperation("acceptVault")
    fun accept(request: HttpServletRequest, @PathVariable vaultId: String) {
        cloak.members.accept(callers.require(request), Params.vault(vaultId))
    }

    /** `POST /vaults/{vaultId}/key-replacements`. */
    @PostMapping("/key-replacements")
    @CloakOperation("recordKeyReplacement")
    fun recordKeyReplacement(
        request: HttpServletRequest,
        @PathVariable vaultId: String,
        @RequestBody body: RecordKeyReplacementRequest,
    ): Vault = cloak.members.recordKeyReplacement(callers.require(request), Params.vault(vaultId), body.toCommand()).toApi()
}
