package dev.voir.cloak.spring.web

import dev.voir.cloak.api.models.BatchGetNodesRequest
import dev.voir.cloak.api.models.BatchGetNodesResponse
import dev.voir.cloak.api.models.BatchWriteRequest
import dev.voir.cloak.api.models.BatchWriteResponse
import dev.voir.cloak.api.models.NodeSections
import dev.voir.cloak.api.models.SectionHeader
import dev.voir.cloak.api.models.SectionHeaderPage
import dev.voir.cloak.api.models.SectionPage
import dev.voir.cloak.api.models.SectionWrite
import dev.voir.cloak.api.models.SectionWriteInput
import dev.voir.cloak.server.CloakServer
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.SectionRef
import dev.voir.cloak.spring.web.mapping.Wire
import dev.voir.cloak.spring.web.mapping.toApi
import dev.voir.cloak.spring.web.mapping.toCore
import jakarta.servlet.http.HttpServletRequest
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

/**
 * `…/sections` and `…/section-headers` of a vault, `/sections/batch-write` and `/nodes…`.
 *
 * @property cloak Cloak operations.
 * @property callers Caller resolution.
 */
@RestController
@RequestMapping(CloakPaths.BASE)
internal class SectionController(
    private val cloak: CloakServer,
    private val callers: Callers,
) {
    /** `GET /vaults/{vaultId}/sections`. */
    @GetMapping("/vaults/{vaultId}/sections")
    @CloakOperation("listVaultSections")
    fun list(
        request: HttpServletRequest,
        @PathVariable vaultId: String,
        @RequestParam(required = false) afterChange: String?,
        @RequestParam(required = false) limit: String?,
    ): SectionPage =
        cloak.sections.list(callers.require(request), Params.vault(vaultId), Params.queryLong(afterChange, "afterChange"), Params.limit(limit))
            .toApi()

    /** `GET /vaults/{vaultId}/section-headers`. */
    @GetMapping("/vaults/{vaultId}/section-headers")
    @CloakOperation("listVaultSectionHeaders")
    fun headers(
        request: HttpServletRequest,
        @PathVariable vaultId: String,
        @RequestParam(required = false) afterChange: String?,
        @RequestParam(required = false) limit: String?,
    ): SectionHeaderPage =
        cloak.sections.headers(
            callers.require(request),
            Params.vault(vaultId),
            Params.queryLong(afterChange, "afterChange"),
            Params.indexLimit(limit),
        ).toApi()

    /** `GET /vaults/{vaultId}/sections/{nodeId}/{sectionName}`. */
    @GetMapping("/vaults/{vaultId}/sections/{nodeId}/{sectionName}")
    @CloakOperation("getSection")
    fun get(
        request: HttpServletRequest,
        @PathVariable vaultId: String,
        @PathVariable nodeId: String,
        @PathVariable sectionName: String,
    ): SectionWrite = cloak.sections.get(callers.require(request), ref(vaultId, nodeId, sectionName)).toApi()

    /** `PUT /vaults/{vaultId}/sections/{nodeId}/{sectionName}`. */
    @PutMapping("/vaults/{vaultId}/sections/{nodeId}/{sectionName}")
    @CloakOperation("writeSection")
    fun write(
        request: HttpServletRequest,
        @PathVariable vaultId: String,
        @PathVariable nodeId: String,
        @PathVariable sectionName: String,
        @RequestBody body: SectionWriteInput,
    ): SectionHeader = cloak.sections.write(callers.require(request), ref(vaultId, nodeId, sectionName), body.toCore()).header.toApi()

    /** `POST /sections/batch-write`. */
    @PostMapping("/sections/batch-write")
    @CloakOperation("batchWriteSections")
    fun batchWrite(request: HttpServletRequest, @RequestBody body: BatchWriteRequest): BatchWriteResponse =
        BatchWriteResponse(cloak.sections.batchWrite(callers.require(request), body.toCore()).map { it.header.toApi() })

    /** `GET /nodes/{nodeId}`. */
    @GetMapping("/nodes/{nodeId}")
    @CloakOperation("getNode")
    fun node(request: HttpServletRequest, @PathVariable nodeId: String): NodeSections =
        cloak.nodes.get(callers.require(request), Params.node(nodeId)).toApi()

    /** `POST /nodes/batch-get`. */
    @PostMapping("/nodes/batch-get")
    @CloakOperation("batchGetNodes")
    fun nodes(request: HttpServletRequest, @RequestBody body: BatchGetNodesRequest): BatchGetNodesResponse =
        cloak.nodes.get(callers.require(request), body.nodeIds.map { NodeId(Wire.uuid(it)) }).toApi()

    /** A section from path parameters. */
    private fun ref(vaultId: String, nodeId: String, sectionName: String): SectionRef =
        SectionRef(Params.vault(vaultId), Params.node(nodeId), Params.section(sectionName))
}
