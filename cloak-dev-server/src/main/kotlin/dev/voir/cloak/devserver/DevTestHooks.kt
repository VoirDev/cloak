package dev.voir.cloak.devserver

import dev.voir.cloak.server.CloakServer
import dev.voir.cloak.server.identity.domain.HostUserId
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

/**
 * Test-only hooks that stand in for what a real host does from its own code, so client
 * end-to-end tests can drive it over HTTP. Anyone may call them: this host is never deployed, and
 * the starter has no such endpoint.
 *
 * @property cloak Cloak operations.
 */
@RestController
internal class DevTestHooks(
    private val cloak: CloakServer,
) {
    /**
     * `POST /dev/users/{hostUserId}/erase`: the host's erasure of a user (`PROTOCOL.md` §5.7),
     * through [dev.voir.cloak.server.identity.IdentityOperations.erase]. Idempotent.
     *
     * @param hostUserId The host's id of the user to erase.
     */
    @PostMapping("/dev/users/{hostUserId}/erase")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun erase(@PathVariable hostUserId: String) {
        cloak.identity.erase(HostUserId.of(hostUserId))
    }

    /**
     * `POST /dev/nodes/{nodeId}/purge?user={hostUserId}`: the host removing a node's sections on a
     * user's behalf when it deletes the resource the node names, through
     * [dev.voir.cloak.server.section.NodeOperations.purge].
     *
     * @param nodeId The node.
     * @param user The host's id of the user on whose behalf it is removed.
     * @return The vaults where sections of the node remain.
     */
    @PostMapping("/dev/nodes/{nodeId}/purge")
    fun purge(@PathVariable nodeId: UUID, @RequestParam user: String): Map<String, List<String>> =
        mapOf("remainingVaultIds" to cloak.nodes.purge(user, nodeId).map(UUID::toString).sorted())
}
