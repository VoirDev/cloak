package dev.voir.cloak.spring.web

import dev.voir.cloak.api.models.BatchGetCheckpointProofsRequest
import dev.voir.cloak.api.models.BatchGetCheckpointProofsResponse
import dev.voir.cloak.api.models.BatchGetVaultsRequest
import dev.voir.cloak.api.models.BatchGetVaultsResponse
import dev.voir.cloak.api.models.CheckpointLeafPage
import dev.voir.cloak.api.models.CreateVaultRequest
import dev.voir.cloak.api.models.LogEntryRequest
import dev.voir.cloak.api.models.Vault
import dev.voir.cloak.api.models.VaultKeyList
import dev.voir.cloak.api.models.VaultLogPage
import dev.voir.cloak.api.models.VaultPage
import dev.voir.cloak.server.CloakServer
import dev.voir.cloak.spring.web.mapping.toApi
import dev.voir.cloak.spring.web.mapping.toCommand
import dev.voir.cloak.spring.web.mapping.toCore
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.net.URI

/**
 * `/vaults`, `/vaults/batch-get`, `/vaults/{vaultId}`, `…/deletion`, `…/node-entries`, `…/log`, `…/keys`,
 * `…/checkpoints/{seq}/leaves` and `…/checkpoint-proofs/batch-get`.
 *
 * @property cloak Cloak operations.
 * @property callers Caller resolution.
 */
@RestController
@RequestMapping(CloakPaths.BASE)
internal class VaultController(
    private val cloak: CloakServer,
    private val callers: Callers,
) {
    /** `GET /vaults`. */
    @GetMapping("/vaults")
    @CloakOperation("listVaults")
    fun list(
        request: HttpServletRequest,
        @RequestParam(required = false) pending: String?,
        @RequestParam(required = false) limit: String?,
        @RequestParam(required = false) cursor: String?,
    ): VaultPage = cloak.vaults.list(callers.require(request), Params.page(limit, cursor), Params.queryFlag(pending, "pending")).toApi()

    /** `POST /vaults`. */
    @PostMapping("/vaults")
    @CloakOperation("createVault")
    fun create(request: HttpServletRequest, @RequestBody body: CreateVaultRequest): ResponseEntity<Vault> {
        val vault = cloak.vaults.create(callers.require(request), body.toCommand())
        return ResponseEntity.created(URI("${CloakPaths.BASE}/vaults/${vault.id.value}")).body(vault.toApi())
    }

    /** `GET /vaults/{vaultId}`. */
    @GetMapping("/vaults/{vaultId}")
    @CloakOperation("getVault")
    fun get(request: HttpServletRequest, @PathVariable vaultId: String): Vault =
        cloak.vaults.get(callers.require(request), Params.vault(vaultId)).toApi()

    /** `POST /vaults/{vaultId}/deletion`: an owner's signed `vault_deleted` (`PROTOCOL.md` §12.3). */
    @PostMapping("/vaults/{vaultId}/deletion")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @CloakOperation("deleteVault")
    fun delete(request: HttpServletRequest, @PathVariable vaultId: String, @RequestBody body: LogEntryRequest) {
        cloak.vaults.delete(callers.require(request), Params.vault(vaultId), body.log.toCore("/log"))
    }

    /** `POST /vaults/{vaultId}/node-entries`: a signed `node_created`, `node_shared` or `node_unshared`. */
    @PostMapping("/vaults/{vaultId}/node-entries")
    @CloakOperation("appendNodeEntry")
    fun appendNodeEntry(request: HttpServletRequest, @PathVariable vaultId: String, @RequestBody body: LogEntryRequest): Vault =
        cloak.vaults.appendNodeEntry(callers.require(request), Params.vault(vaultId), body.log.toCore("/log")).toApi()

    /** `GET /vaults/{vaultId}/log`. */
    @GetMapping("/vaults/{vaultId}/log")
    @CloakOperation("listVaultLog")
    fun log(
        request: HttpServletRequest,
        @PathVariable vaultId: String,
        @RequestParam(required = false) afterSeq: String?,
        @RequestParam(required = false) limit: String?,
    ): VaultLogPage =
        cloak.vaults.log(callers.require(request), Params.vault(vaultId), Params.queryLong(afterSeq, "afterSeq"), Params.limit(limit)).toApi()

    /** `GET /vaults/{vaultId}/keys`. */
    @GetMapping("/vaults/{vaultId}/keys")
    @CloakOperation("listVaultKeys")
    fun keys(
        request: HttpServletRequest,
        @PathVariable vaultId: String,
        @RequestParam(required = false) afterVersion: String?,
        @RequestParam(required = false) limit: String?,
    ): VaultKeyList =
        cloak.vaults.keys(
            callers.require(request),
            Params.vault(vaultId),
            Params.queryInt(afterVersion, "afterVersion"),
            Params.limit(limit),
        ).toApi()

    /** `GET /vaults/{vaultId}/checkpoints/{seq}/leaves`. */
    @GetMapping("/vaults/{vaultId}/checkpoints/{seq}/leaves")
    @CloakOperation("listCheckpointLeaves")
    fun checkpointLeaves(
        request: HttpServletRequest,
        @PathVariable vaultId: String,
        @PathVariable seq: String,
        @RequestParam(required = false) cursor: String?,
        @RequestParam(required = false) limit: String?,
    ): CheckpointLeafPage =
        cloak.vaults.checkpointLeaves(
            callers.require(request),
            Params.vault(vaultId),
            Params.checkpointSeq(seq),
            cursor,
            Params.indexLimit(limit),
        ).toApi()

    /** `POST /vaults/{vaultId}/checkpoint-proofs/batch-get`. */
    @PostMapping("/vaults/{vaultId}/checkpoint-proofs/batch-get")
    @CloakOperation("batchGetCheckpointProofs")
    fun checkpointProofs(
        request: HttpServletRequest,
        @PathVariable vaultId: String,
        @RequestBody body: BatchGetCheckpointProofsRequest,
    ): BatchGetCheckpointProofsResponse =
        cloak.vaults.checkpointProofs(callers.require(request), Params.vault(vaultId), body.toCore()).toApi()

    /** `POST /vaults/batch-get`. */
    @PostMapping("/vaults/batch-get")
    @CloakOperation("batchGetVaults")
    fun getMany(request: HttpServletRequest, @RequestBody body: BatchGetVaultsRequest): BatchGetVaultsResponse =
        cloak.vaults.getMany(callers.require(request), body.toCore()).toApi()
}
