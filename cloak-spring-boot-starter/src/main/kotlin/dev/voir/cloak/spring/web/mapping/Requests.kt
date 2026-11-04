package dev.voir.cloak.spring.web.mapping

import dev.voir.cloak.api.models.AddMemberRequest
import dev.voir.cloak.api.models.BatchGetCheckpointProofsRequest
import dev.voir.cloak.api.models.BatchGetVaultsRequest
import dev.voir.cloak.api.models.BatchRotateVaultsRequest
import dev.voir.cloak.api.models.BatchWriteRequest
import dev.voir.cloak.api.models.CreateVaultRequest
import dev.voir.cloak.api.models.DeleteIdentityRequest
import dev.voir.cloak.api.models.DeliverEnvelopeRequest
import dev.voir.cloak.api.models.LeaveVaultRequest
import dev.voir.cloak.api.models.RecordKeyReplacementRequest
import dev.voir.cloak.api.models.RegisterIdentityRequest
import dev.voir.cloak.api.models.ReplaceKeysRequest
import dev.voir.cloak.api.models.RotateVaultRequest
import dev.voir.cloak.api.models.SetMemberRoleRequest
import dev.voir.cloak.api.models.UpdateCredentialsRequest
import dev.voir.cloak.api.models.WritePauseRequest
import dev.voir.cloak.server.identity.domain.DeleteIdentityCommand
import dev.voir.cloak.server.identity.domain.KdfParams
import dev.voir.cloak.server.identity.domain.RegisterIdentityCommand
import dev.voir.cloak.server.identity.domain.ReplaceKeysCommand
import dev.voir.cloak.server.identity.domain.UpdateCredentialsCommand
import dev.voir.cloak.server.identity.domain.UserId
import dev.voir.cloak.server.section.domain.BatchWriteItem
import dev.voir.cloak.server.section.domain.NodeId
import dev.voir.cloak.server.section.domain.SectionRef
import dev.voir.cloak.server.section.domain.SectionWriteInput
import dev.voir.cloak.server.vault.domain.AddMemberCommand
import dev.voir.cloak.server.vault.domain.CheckpointProofQuery
import dev.voir.cloak.server.vault.domain.CreateVaultCommand
import dev.voir.cloak.server.vault.domain.DeliverEnvelopeCommand
import dev.voir.cloak.server.vault.domain.LeaveVaultCommand
import dev.voir.cloak.server.vault.domain.LeftOutWrite
import dev.voir.cloak.server.vault.domain.LogEntryInput
import dev.voir.cloak.server.vault.domain.MemberEnvelope
import dev.voir.cloak.server.vault.domain.RecordKeyReplacementCommand
import dev.voir.cloak.server.vault.domain.RotateVaultCommand
import dev.voir.cloak.server.vault.domain.SetMemberRoleCommand
import dev.voir.cloak.server.vault.domain.VaultId
import dev.voir.cloak.server.vault.domain.VaultLogQuery
import dev.voir.cloak.server.vault.domain.VaultRotation
import dev.voir.cloak.api.models.BatchWriteItem as ApiBatchWriteItem
import dev.voir.cloak.api.models.KdfParams as ApiKdfParams
import dev.voir.cloak.api.models.LeftOutWrite as ApiLeftOutWrite
import dev.voir.cloak.api.models.LogEntryInput as ApiLogEntryInput
import dev.voir.cloak.api.models.MemberEnvelope as ApiMemberEnvelope
import dev.voir.cloak.api.models.SectionWriteInput as ApiSectionWriteInput

// Generated request models to core commands. Jackson already enforced required fields, JSON
// types, UUIDs and enums; these parse the strings left and name each JSON Pointer.

/** Maps KDF parameters at [pointer]. */
internal fun ApiKdfParams.toCore(pointer: String): KdfParams {
    if (algorithm != "argon2id") throw Wire.invalid("$pointer/algorithm", "const", "Must be argon2id.")
    return KdfParams(Wire.bytes(salt, "$pointer/salt"), memoryKib, iterations, parallelism)
}

/** Maps a registration. */
internal fun RegisterIdentityRequest.toCommand(): RegisterIdentityCommand =
    RegisterIdentityCommand(
        cryptoSuite = cryptoSuite,
        encryptionPublicKey = Wire.bytes(encryptionPublicKey, "/encryptionPublicKey"),
        signingPublicKey = Wire.bytes(signingPublicKey, "/signingPublicKey"),
        recoverySigningPublicKey = Wire.bytes(recoverySigningPublicKey, "/recoverySigningPublicKey"),
        signature = Wire.bytes(signature, "/signature"),
        kdf = kdf.toCore("/kdf"),
        privateKeyBundle = Wire.bytes(privateKeyBundle, "/privateKeyBundle"),
        recoveryKeyBundle = Wire.bytes(recoveryKeyBundle, "/recoveryKeyBundle"),
    )

/** Maps a credentials change. */
internal fun UpdateCredentialsRequest.toCommand(): UpdateCredentialsCommand =
    UpdateCredentialsCommand(
        expectedCredentialsVersion = expectedCredentialsVersion,
        kdf = kdf.toCore("/kdf"),
        privateKeyBundle = Wire.bytes(privateKeyBundle, "/privateKeyBundle"),
        signature = Wire.bytes(signature, "/signature"),
    )

/** Maps a signed identity deletion. */
internal fun DeleteIdentityRequest.toCommand(): DeleteIdentityCommand =
    DeleteIdentityCommand(credentialsVersion, notAfter, Wire.bytes(signature, "/signature"))

/** Maps a key replacement. */
internal fun ReplaceKeysRequest.toCommand(): ReplaceKeysCommand =
    ReplaceKeysCommand(
        expectedKeyVersion = expectedKeyVersion,
        encryptionPublicKey = Wire.bytes(encryptionPublicKey, "/encryptionPublicKey"),
        signingPublicKey = Wire.bytes(signingPublicKey, "/signingPublicKey"),
        recoverySigningPublicKey = Wire.bytes(recoverySigningPublicKey, "/recoverySigningPublicKey"),
        signature = Wire.bytes(signature, "/signature"),
        recoverySignature = Wire.bytes(recoverySignature, "/recoverySignature"),
        kdf = kdf.toCore("/kdf"),
        privateKeyBundle = Wire.bytes(privateKeyBundle, "/privateKeyBundle"),
        recoveryKeyBundle = Wire.bytes(recoveryKeyBundle, "/recoveryKeyBundle"),
    )

/** Maps a log entry at [pointer]. */
internal fun ApiLogEntryInput.toCore(pointer: String): LogEntryInput =
    LogEntryInput(
        seq = seq,
        kind = Wire.kind(kind),
        subjectUserId = subjectUserId?.let { UserId(Wire.uuid(it)) },
        role = role?.let(Wire::role),
        keyVersion = keyVersion,
        subjectKeys = Wire.optionalBytes(subjectKeys, "$pointer/subjectKeys"),
        subjectKeyVersion = subjectKeyVersion,
        keyCommitment = Wire.optionalBytes(keyCommitment, "$pointer/keyCommitment"),
        checkpoint = Wire.optionalBytes(checkpoint, "$pointer/checkpoint"),
        requestEnd = requestEnd,
        authorKeyVersion = authorKeyVersion,
        signature = Wire.bytes(signature, "$pointer/signature"),
        nodeId = nodeId?.let { NodeId(Wire.uuid(it)) },
        homeVaultId = homeVaultId?.let { VaultId(Wire.uuid(it)) },
        nodeKey = nodeKey,
        sections = sections,
    )

/** Maps the writes a checkpoint leaves out. */
private fun List<ApiLeftOutWrite>?.toCore(): List<LeftOutWrite> =
    orEmpty().mapIndexed { index, write ->
        LeftOutWrite(
            nodeId = NodeId(Wire.uuid(write.nodeId)),
            sectionName = Wire.sectionName(write.sectionName, "/leftOut/$index/sectionName"),
            writeHash = Wire.bytes(write.writeHash, "/leftOut/$index/writeHash"),
        )
    }

/** Maps a vault creation. */
internal fun CreateVaultRequest.toCommand(): CreateVaultCommand =
    CreateVaultCommand(VaultId(Wire.uuid(id)), Wire.bytes(keyEnvelope, "/keyEnvelope"), log.toCore("/log"))

/** Maps a new member. */
internal fun AddMemberRequest.toCommand(): AddMemberCommand =
    AddMemberCommand(
        userId = UserId(Wire.uuid(userId)),
        role = Wire.role(role),
        keyVersion = keyVersion,
        userKeyVersion = userKeyVersion,
        keyEnvelope = Wire.bytes(keyEnvelope, "/keyEnvelope"),
        log = log.toCore("/log"),
    )

/** Maps a role change. */
internal fun SetMemberRoleRequest.toCommand(): SetMemberRoleCommand =
    SetMemberRoleCommand(Wire.role(role), log.toCore("/log"), leftOut.toCore())

/** Maps an envelope delivery. */
internal fun DeliverEnvelopeRequest.toCommand(): DeliverEnvelopeCommand =
    DeliverEnvelopeCommand(keyVersion, userKeyVersion, Wire.bytes(keyEnvelope, "/keyEnvelope"))

/** Maps a departure. */
internal fun LeaveVaultRequest.toCommand(): LeaveVaultCommand = LeaveVaultCommand(log.toCore("/log"), leftOut.toCore())

/** Maps a rotation. */
internal fun RotateVaultRequest.toCommand(): RotateVaultCommand =
    rotation(keyVersion, previousWrappedKey, envelopes, log, leftOut, "")

/** Maps a batch of rotations, one per vault. */
internal fun BatchRotateVaultsRequest.toCore(): List<VaultRotation> =
    items.mapIndexed { index, item ->
        VaultRotation(
            VaultId(Wire.uuid(item.vaultId)),
            rotation(item.keyVersion, item.previousWrappedKey, item.envelopes, item.log, item.leftOut, "/items/$index"),
        )
    }

/** Maps a batch read of vaults. */
internal fun BatchGetVaultsRequest.toCore(): List<VaultLogQuery> =
    items.map { VaultLogQuery(VaultId(Wire.uuid(it.vaultId)), it.afterSeq) }

/** Maps the vaults of a write pause or its release. */
internal fun WritePauseRequest.toCore(): List<VaultId> = vaultIds.map { VaultId(Wire.uuid(it)) }

/** Maps the fields of a rotation; [prefix] leads every JSON Pointer. */
private fun rotation(
    keyVersion: Int,
    previousWrappedKey: String,
    envelopes: List<ApiMemberEnvelope>,
    log: List<ApiLogEntryInput>,
    leftOut: List<ApiLeftOutWrite>?,
    prefix: String,
): RotateVaultCommand =
    RotateVaultCommand(
        keyVersion = keyVersion,
        previousWrappedKey = Wire.bytes(previousWrappedKey, "$prefix/previousWrappedKey"),
        envelopes = envelopes.mapIndexed { index, envelope ->
            MemberEnvelope(
                UserId(Wire.uuid(envelope.userId)),
                envelope.userKeyVersion,
                Wire.bytes(envelope.keyEnvelope, "$prefix/envelopes/$index/keyEnvelope"),
            )
        },
        log = log.mapIndexed { index, entry -> entry.toCore("$prefix/log/$index") },
        leftOut = leftOut.toCore(),
    )

/** Maps a key replacement record. */
internal fun RecordKeyReplacementRequest.toCommand(): RecordKeyReplacementCommand =
    RecordKeyReplacementCommand(log.toCore("/log"), Wire.optionalBytes(keyEnvelope, "/keyEnvelope"), leftOut.toCore())

/** Maps a section write at [pointer]. */
internal fun ApiSectionWriteInput.toCore(pointer: String = ""): SectionWriteInput =
    SectionWriteInput(
        nodeType = Wire.nodeType(nodeType, "$pointer/nodeType"),
        vaultKeyVersion = vaultKeyVersion,
        dataVersion = dataVersion,
        deleted = deleted,
        logSeq = logSeq,
        logHeadHash = Wire.bytes(logHeadHash, "$pointer/logHeadHash"),
        previousWriteHash = Wire.optionalBytes(previousWriteHash, "$pointer/previousWriteHash"),
        writerKeyVersion = writerKeyVersion,
        ciphertext = Wire.optionalBytes(ciphertext, "$pointer/ciphertext"),
        signature = Wire.bytes(signature, "$pointer/signature"),
        homeVaultId = VaultId(Wire.uuid(homeVaultId)),
        ownerUserId = UserId(Wire.uuid(ownerUserId)),
        nodeKey = nodeKey,
    )

/** Maps one batch item at [pointer]. */
private fun ApiBatchWriteItem.toCore(pointer: String): BatchWriteItem =
    BatchWriteItem(
        section = SectionRef(
            VaultId(Wire.uuid(vaultId)),
            NodeId(Wire.uuid(nodeId)),
            Wire.sectionName(sectionName, "$pointer/sectionName"),
        ),
        input = ApiSectionWriteInput(
            nodeType = nodeType,
            homeVaultId = homeVaultId,
            ownerUserId = ownerUserId,
            nodeKey = nodeKey,
            vaultKeyVersion = vaultKeyVersion,
            dataVersion = dataVersion,
            deleted = deleted,
            logSeq = logSeq,
            logHeadHash = logHeadHash,
            previousWriteHash = previousWriteHash,
            writerKeyVersion = writerKeyVersion,
            ciphertext = ciphertext,
            signature = signature,
        ).toCore(pointer),
    )

/** Maps a batch of checkpoint proof queries. */
internal fun BatchGetCheckpointProofsRequest.toCore(): List<CheckpointProofQuery> =
    items.mapIndexed { index, item ->
        CheckpointProofQuery(
            checkpointSeq = item.checkpointSeq,
            nodeId = NodeId(Wire.uuid(item.nodeId)),
            sectionName = Wire.sectionName(item.sectionName, "/items/$index/sectionName"),
        )
    }

/** Maps a batch write. */
internal fun BatchWriteRequest.toCore(): List<BatchWriteItem> = items.mapIndexed { index, item -> item.toCore("/items/$index") }
