package dev.voir.cloak.spring.web.mapping

import dev.voir.cloak.api.models.BatchGetCheckpointProofsResponse
import dev.voir.cloak.api.models.BatchGetNodesResponse
import dev.voir.cloak.api.models.BatchGetUserKeysResponse
import dev.voir.cloak.api.models.LimitsKdf
import dev.voir.cloak.api.models.MetaBlobFormats
import dev.voir.cloak.api.models.VaultKeyList
import dev.voir.cloak.api.models.VaultPage
import dev.voir.cloak.server.identity.domain.Identity
import dev.voir.cloak.server.identity.domain.KdfParams
import dev.voir.cloak.server.identity.domain.KeyStatement
import dev.voir.cloak.server.identity.domain.PublicKeys
import dev.voir.cloak.server.identity.domain.UserKeys
import dev.voir.cloak.server.identity.domain.UserKeysBatch
import dev.voir.cloak.server.meta.Meta
import dev.voir.cloak.server.paging.Page
import dev.voir.cloak.server.section.domain.NodeSections
import dev.voir.cloak.server.section.domain.NodeSectionsBatch
import dev.voir.cloak.server.section.domain.SectionHeader
import dev.voir.cloak.server.section.domain.SectionHeaderPage
import dev.voir.cloak.server.section.domain.SectionPage
import dev.voir.cloak.server.section.domain.SectionRemoval
import dev.voir.cloak.server.section.domain.SectionWrite
import dev.voir.cloak.server.vault.domain.CheckpointLeaf
import dev.voir.cloak.server.vault.domain.CheckpointLeafPage
import dev.voir.cloak.server.vault.domain.CheckpointProof
import dev.voir.cloak.server.vault.domain.LeafProof
import dev.voir.cloak.server.vault.domain.LogEntry
import dev.voir.cloak.server.vault.domain.Vault
import dev.voir.cloak.server.vault.domain.VaultKey
import dev.voir.cloak.server.vault.domain.VaultLogBatchItem
import dev.voir.cloak.server.vault.domain.VaultLogPage
import dev.voir.cloak.api.models.CheckpointLeaf as ApiCheckpointLeaf
import dev.voir.cloak.api.models.CheckpointLeafPage as ApiCheckpointLeafPage
import dev.voir.cloak.api.models.CheckpointProof as ApiCheckpointProof
import dev.voir.cloak.api.models.Identity as ApiIdentity
import dev.voir.cloak.api.models.KdfParams as ApiKdfParams
import dev.voir.cloak.api.models.KeyStatement as ApiKeyStatement
import dev.voir.cloak.api.models.LeafProof as ApiLeafProof
import dev.voir.cloak.api.models.Limits as ApiLimits
import dev.voir.cloak.api.models.LogEntry as ApiLogEntry
import dev.voir.cloak.api.models.Meta as ApiMeta
import dev.voir.cloak.api.models.NodeSections as ApiNodeSections
import dev.voir.cloak.api.models.PublicKeys as ApiPublicKeys
import dev.voir.cloak.api.models.SectionHeader as ApiSectionHeader
import dev.voir.cloak.api.models.SectionHeaderPage as ApiSectionHeaderPage
import dev.voir.cloak.api.models.SectionPage as ApiSectionPage
import dev.voir.cloak.api.models.SectionRemoval as ApiSectionRemoval
import dev.voir.cloak.api.models.BatchGetVaultsResponse as ApiBatchGetVaultsResponse
import dev.voir.cloak.api.models.BatchGetVaultsResponseItems as ApiBatchGetVaultsResponseItems
import dev.voir.cloak.api.models.SectionWrite as ApiSectionWrite
import dev.voir.cloak.api.models.UserKeys as ApiUserKeys
import dev.voir.cloak.api.models.Vault as ApiVault
import dev.voir.cloak.api.models.VaultKey as ApiVaultKey
import dev.voir.cloak.api.models.VaultLogPage as ApiVaultLogPage

// Core results to generated response models.

/** Maps the server's capabilities. */
internal fun Meta.toApi(): ApiMeta =
    ApiMeta(
        apiVersion = apiVersion,
        protocolVersion = protocolVersion,
        cryptoSuites = cryptoSuites,
        blobFormats = MetaBlobFormats(acceptedBlobFormats, deprecatedBlobFormats),
        limits = ApiLimits(
            maxPendingInvitations = limits.maxPendingInvitations,
            maxPendingInvitationsPerInviter = limits.maxPendingInvitationsPerInviter,
            maxSectionBytes = limits.maxSectionBytes,
            maxRequestBytes = limits.maxRequestBytes,
            maxBatchSize = limits.maxBatchSize,
            maxPageSize = limits.maxPageSize,
            maxIndexPageSize = limits.maxIndexPageSize,
            maxMembersPerVault = limits.maxMembersPerVault,
            maxSectionsPerVault = limits.maxSectionsPerVault,
            maxStoredSectionsPerVault = limits.maxStoredSectionsPerVault,
            writePauseSeconds = limits.writePauseSeconds,
            writePauseIntervalSeconds = limits.writePauseIntervalSeconds,
            kdf = LimitsKdf(limits.minKdfMemoryKib, limits.maxKdfMemoryKib, limits.minKdfIterations, limits.maxKdfIterations),
        ),
    )

/** Maps KDF parameters. */
internal fun KdfParams.toApi(): ApiKdfParams = ApiKdfParams("argon2id", Wire.text(salt), memoryKib, iterations, parallelism)

/** Maps one key version. */
internal fun PublicKeys.toApi(): ApiPublicKeys =
    ApiPublicKeys(
        userId = Wire.uuid(userId.value),
        keyVersion = keyVersion,
        cryptoSuite = cryptoSuite,
        encryptionPublicKey = Wire.text(encryptionPublicKey),
        signingPublicKey = Wire.text(signingPublicKey),
        recoverySigningPublicKey = Wire.text(recoverySigningPublicKey),
    )

/** Maps the caller's identity. */
internal fun Identity.toApi(): ApiIdentity =
    ApiIdentity(
        hostUserId = hostUserId.value,
        keys = keys.toApi(),
        kdf = kdf.toApi(),
        privateKeyBundle = Wire.text(privateKeyBundle),
        recoveryKeyBundle = Wire.text(recoveryKeyBundle),
        credentialsVersion = credentialsVersion,
        createdAt = Wire.instant(createdAt),
        updatedAt = Wire.instant(updatedAt),
    )

/** Maps a key statement. */
internal fun KeyStatement.toApi(): ApiKeyStatement =
    ApiKeyStatement(
        keys = keys.toApi(),
        previousKeysDigest = previousKeysDigest?.let(Wire::text),
        signature = Wire.text(signature),
        recoverySignature = recoverySignature?.let(Wire::text),
        createdAt = Wire.instant(createdAt),
    )

/** Maps a user's key versions. */
internal fun UserKeys.toApi(): ApiUserKeys =
    ApiUserKeys(userId = Wire.uuid(userId.value), hostUserId = hostUserId?.value, deleted = deleted, versions = versions.map { it.toApi() })

/** Maps several users' key versions. */
internal fun UserKeysBatch.toApi(): BatchGetUserKeysResponse =
    BatchGetUserKeysResponse(items.map { it.toApi() }, missingUserIds.map { Wire.uuid(it.value) })

/** Maps a vault. */
internal fun Vault.toApi(): ApiVault =
    ApiVault(
        id = Wire.uuid(id.value),
        accepted = accepted,
        addedByUserId = addedByUserId?.let { Wire.uuid(it.value) },
        deleted = deleted,
        role = Wire.role(role),
        keyVersion = keyVersion,
        keyEnvelope = keyEnvelope?.let(Wire::text),
        envelopeUserKeyVersion = envelopeUserKeyVersion,
        logSeq = logSeq,
        logHeadHash = Wire.text(logHeadHash),
        createdByUserId = Wire.uuid(createdByUserId.value),
        createdAt = Wire.instant(createdAt),
    )

/** Maps a page of vaults. */
internal fun Page<Vault>.toApi(): VaultPage = VaultPage(nextCursor = nextCursor, items = items.map { it.toApi() })

/** Maps key versions. */
internal fun List<VaultKey>.toApi(): VaultKeyList =
    VaultKeyList(map { ApiVaultKey(it.version, it.previousWrappedKey?.let(Wire::text), Wire.instant(it.createdAt)) })

/** Maps a log entry. */
internal fun LogEntry.toApi(): ApiLogEntry =
    ApiLogEntry(
        seq = input.seq,
        kind = Wire.kind(input.kind),
        subjectUserId = input.subjectUserId?.let { Wire.uuid(it.value) },
        role = input.role?.let(Wire::role),
        keyVersion = input.keyVersion,
        subjectKeys = input.subjectKeys?.let(Wire::text),
        subjectKeyVersion = input.subjectKeyVersion,
        keyCommitment = input.keyCommitment?.let(Wire::text),
        checkpoint = input.checkpoint?.let(Wire::text),
        requestEnd = input.requestEnd,
        authorKeyVersion = input.authorKeyVersion,
        nodeId = input.nodeId?.let { Wire.uuid(it.value) },
        homeVaultId = input.homeVaultId?.let { Wire.uuid(it.value) },
        nodeKey = input.nodeKey,
        sections = input.sections,
        signature = Wire.text(input.signature),
        authorUserId = Wire.uuid(authorUserId.value),
        entryHash = Wire.text(entryHash),
        createdAt = Wire.instant(createdAt),
    )

/** Maps a page of the log. */
internal fun VaultLogPage.toApi(): ApiVaultLogPage = ApiVaultLogPage(items.map { it.toApi() }, headSeq)

/** Maps a checkpoint leaf. */
private fun CheckpointLeaf.toApi(): ApiCheckpointLeaf =
    ApiCheckpointLeaf(Wire.uuid(nodeId.value), sectionName.value, dataVersion, Wire.text(writeHash))

/** Maps a leaf with its path. */
private fun LeafProof.toApi(): ApiLeafProof = ApiLeafProof(index, leaf.toApi(), path.map(Wire::text))

/** Maps a checkpoint proof. */
internal fun CheckpointProof.toApi(): ApiCheckpointProof =
    ApiCheckpointProof(checkpointSeq, size, inclusion?.toApi(), before?.toApi(), after?.toApi())

/** Maps proofs in query order. */
internal fun List<CheckpointProof>.toApi(): BatchGetCheckpointProofsResponse = BatchGetCheckpointProofsResponse(map { it.toApi() })

/** Maps a page of a checkpoint's leaves. */
internal fun CheckpointLeafPage.toApi(): ApiCheckpointLeafPage =
    ApiCheckpointLeafPage(nextCursor = nextCursor, checkpointSeq = checkpointSeq, size = size, leaves = leaves.map { it.toApi() })

/** Maps a stored write without its ciphertext. */
internal fun SectionHeader.toApi(): ApiSectionHeader =
    ApiSectionHeader(
        vaultId = Wire.uuid(section.vaultId.value),
        nodeId = Wire.uuid(section.nodeId.value),
        sectionName = section.sectionName.value,
        nodeType = nodeType.value,
        homeVaultId = Wire.uuid(homeVaultId.value),
        ownerUserId = Wire.uuid(ownerUserId.value),
        nodeKey = nodeKey,
        vaultKeyVersion = vaultKeyVersion,
        dataVersion = dataVersion,
        deleted = deleted,
        logSeq = logSeq,
        logHeadHash = Wire.text(logHeadHash),
        previousWriteHash = previousWriteHash?.let(Wire::text),
        writerUserId = Wire.uuid(writerUserId.value),
        writerKeyVersion = writerKeyVersion,
        ciphertextHash = ciphertextHash?.let(Wire::text),
        signature = Wire.text(signature),
        writeHash = Wire.text(writeHash),
        changeSeq = changeSeq,
        writtenAt = Wire.instant(writtenAt),
    )

/** Maps a page of a vault's section headers. */
internal fun SectionHeaderPage.toApi(): ApiSectionHeaderPage =
    ApiSectionHeaderPage(items.map { it.toApi() }, removed.map { it.toApi() }, throughChangeSeq, lastChangeSeq)

/** Maps a section the host removed. */
private fun SectionRemoval.toApi(): ApiSectionRemoval = ApiSectionRemoval(Wire.uuid(nodeId.value), sectionName.value, changeSeq)

/** Maps the answers of a batch read of vaults. */
internal fun List<VaultLogBatchItem>.toApi(): ApiBatchGetVaultsResponse =
    ApiBatchGetVaultsResponse(map { ApiBatchGetVaultsResponseItems(Wire.uuid(it.vaultId.value), it.found, it.vault?.toApi(), it.log?.toApi()) })

/** Maps a section's latest write. */
internal fun SectionWrite.toApi(): ApiSectionWrite =
    ApiSectionWrite(
        nodeType = input.nodeType.value,
        homeVaultId = Wire.uuid(input.homeVaultId.value),
        ownerUserId = Wire.uuid(input.ownerUserId.value),
        nodeKey = input.nodeKey,
        vaultKeyVersion = input.vaultKeyVersion,
        dataVersion = input.dataVersion,
        deleted = input.deleted,
        logSeq = input.logSeq,
        logHeadHash = Wire.text(input.logHeadHash),
        previousWriteHash = input.previousWriteHash?.let(Wire::text),
        writerKeyVersion = input.writerKeyVersion,
        ciphertextHash = ciphertextHash?.let(Wire::text),
        ciphertext = input.ciphertext?.let(Wire::text),
        signature = Wire.text(input.signature),
        vaultId = Wire.uuid(section.vaultId.value),
        nodeId = Wire.uuid(section.nodeId.value),
        sectionName = section.sectionName.value,
        writerUserId = Wire.uuid(writerUserId.value),
        writeHash = Wire.text(writeHash),
        changeSeq = changeSeq,
        writtenAt = Wire.instant(writtenAt),
    )

/** Maps a page of a vault's sections. */
internal fun SectionPage.toApi(): ApiSectionPage =
    ApiSectionPage(items.map { it.toApi() }, removed.map { it.toApi() }, throughChangeSeq, lastChangeSeq)

/** Maps a node's readable sections. */
internal fun NodeSections.toApi(): ApiNodeSections = ApiNodeSections(Wire.uuid(nodeId.value), sections.map { it.toApi() })

/** Maps several nodes. */
internal fun NodeSectionsBatch.toApi(): BatchGetNodesResponse =
    BatchGetNodesResponse(items.map { it.toApi() }, missingNodeIds.map { Wire.uuid(it.value) })
