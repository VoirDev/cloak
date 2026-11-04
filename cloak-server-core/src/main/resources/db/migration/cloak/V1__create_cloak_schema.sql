-- Cloak server schema, version 1.
--
-- Flyway runs this history with `schemas = cloak` and `table = flyway_schema_history`, so it
-- creates the `cloak` schema and keeps its own history inside it, apart from the host app.
--
-- Model (PROTOCOL.md §1): independent vaults of members with roles; a versioned vault key sealed
-- to each member; a signed, hash-chained log of every change to members, roles and keys; and
-- sections of nodes, each living in one vault, stored as their latest signed write.
--
-- Conventions:
-- * Columns named *_envelope, *_wrapped_key, *_bundle, ciphertext and *signature hold opaque,
--   self-describing blobs whose first byte is a format version. The server checks size and
--   format, stores and returns them, and never parses them.
-- * Public keys, digests, commitments and checkpoints are raw 32-byte values.
-- * user_id values come from the host app's authentication. Cloak never stores credentials.
-- * Every instant is TIMESTAMPTZ with microsecond precision; the application truncates to it.
-- * Concurrency: every request that changes a vault locks its `vaults` row first (several vaults
--   in id order), so log appends, rotations and section writes of one vault run one at a time and
--   the change numbers of sections commit in order.

-- ---------------------------------------------------------------------------------------------
-- identities: one row per registered user: the host's id of the user, the current key version and
-- the credentials that unlock it. user_id is UUIDv5 of host_user_id (PROTOCOL.md §5.0), derived by
-- the server. Every key version itself is in identity_keys.
--
-- A deleted identity (PROTOCOL.md §5.7) keeps its row as a tombstone: deleted_at is set and the host
-- user id, the KDF parameters and both bundles are erased. The row stays so that its key versions,
-- which signed log entries name, remain, and so that its user id, the primary key, can never
-- register again.
-- ---------------------------------------------------------------------------------------------
create table cloak.identities (
    user_id                uuid        not null,
    host_user_id           varchar(255),
    key_version            integer     not null,
    kdf_salt               bytea,
    kdf_memory_kib         integer,
    kdf_iterations         integer,
    kdf_parallelism        integer,
    private_key_bundle     bytea,
    recovery_key_bundle    bytea,
    credentials_version    integer     not null,
    created_at             timestamptz not null,
    updated_at             timestamptz not null,
    deleted_at             timestamptz,
    constraint pk_identities primary key (user_id),
    constraint uq_identities__host_user_id unique (host_user_id),
    constraint ck_identities__host_user_id_length check (octet_length(host_user_id) between 1 and 255),
    constraint ck_identities__key_version check (key_version >= 1),
    constraint ck_identities__kdf_salt_length check (octet_length(kdf_salt) = 16),
    constraint ck_identities__kdf_memory_kib check (kdf_memory_kib between 65536 and 1048576),
    constraint ck_identities__kdf_iterations check (kdf_iterations between 2 and 10),
    constraint ck_identities__kdf_parallelism check (kdf_parallelism = 1),
    constraint ck_identities__credentials_version check (credentials_version >= 1),
    constraint ck_identities__updated_after_created check (updated_at >= created_at),
    constraint ck_identities__deleted check (
        (deleted_at is null and host_user_id is not null and kdf_salt is not null and kdf_memory_kib is not null
            and kdf_iterations is not null and kdf_parallelism is not null and private_key_bundle is not null
            and recovery_key_bundle is not null) or
        (deleted_at is not null and host_user_id is null and kdf_salt is null and kdf_memory_kib is null
            and kdf_iterations is null and kdf_parallelism is null and private_key_bundle is null
            and recovery_key_bundle is null)
    )
);

-- ---------------------------------------------------------------------------------------------
-- identity_keys: every key version of every user with its key statement (PROTOCOL.md §5.2).
-- Version 1 is signed by its own signing key; version n + 1 names the digest of version n and is
-- signed again by version n's recovery signing key. Never updated or deleted.
-- ---------------------------------------------------------------------------------------------
create table cloak.identity_keys (
    user_id                      uuid        not null,
    key_version                  integer     not null,
    crypto_suite                 smallint    not null,
    encryption_public_key        bytea       not null,
    signing_public_key           bytea       not null,
    recovery_signing_public_key  bytea       not null,
    keys_digest                  bytea       not null,
    previous_keys_digest         bytea,
    signature                    bytea       not null,
    recovery_signature           bytea,
    created_at                   timestamptz not null,
    constraint pk_identity_keys primary key (user_id, key_version),
    constraint fk_identity_keys__user_id__identities foreign key (user_id)
        references cloak.identities (user_id) on delete restrict on update restrict,
    constraint uq_identity_keys__signing_public_key unique (signing_public_key),
    constraint ck_identity_keys__crypto_suite check (crypto_suite = 1),
    constraint ck_identity_keys__encryption_public_key_length check (octet_length(encryption_public_key) = 32),
    constraint ck_identity_keys__signing_public_key_length check (octet_length(signing_public_key) = 32),
    constraint ck_identity_keys__recovery_signing_public_key_length check (octet_length(recovery_signing_public_key) = 32),
    constraint ck_identity_keys__keys_digest_length check (octet_length(keys_digest) = 32),
    constraint ck_identity_keys__signature_length check (octet_length(signature) = 65),
    constraint ck_identity_keys__chain check (
        (key_version = 1 and previous_keys_digest is null and recovery_signature is null) or
        (key_version > 1 and previous_keys_digest is not null and recovery_signature is not null
            and octet_length(previous_keys_digest) = 32 and octet_length(recovery_signature) = 65)
    )
);

-- ---------------------------------------------------------------------------------------------
-- vaults: units of access. key_version is the current vault key; log_seq and log_head_hash the
-- last vault_log entry; change_seq the last section change number, so a client reads only what
-- changed since. live_section_count counts the sections whose latest write is not a deletion,
-- kept within the limit of live sections so every checkpoint stays bounded; stored_section_count
-- counts every stored section, deletions included, kept within the much larger stored limit so the
-- database stays bounded (PROTOCOL.md §7.5, §13).
-- pause_*: a write pause (PROTOCOL.md §7.5): who holds it, whether as an admin, and until when;
-- while it holds, section writes to the vault answer busy. All three are set or none.
-- deleted_at: when an owner's signed vault_deleted ended the vault (PROTOCOL.md §12.3); its keys,
-- envelopes, sections and checkpoint leaves are gone, its log and member list stay.
-- ---------------------------------------------------------------------------------------------
create table cloak.vaults (
    id                  uuid        not null,
    key_version         integer     not null,
    log_seq             bigint      not null,
    log_head_hash       bytea       not null,
    change_seq          bigint      not null,
    live_section_count  integer     not null,
    stored_section_count integer    not null,
    pause_user_id       uuid,
    pause_by_admin      boolean,
    pause_until         timestamptz,
    deleted_at          timestamptz,
    created_by_user_id  uuid        not null,
    created_at          timestamptz not null,
    constraint pk_vaults primary key (id),
    constraint fk_vaults__created_by_user_id__identities foreign key (created_by_user_id)
        references cloak.identities (user_id) on delete restrict on update restrict,
    constraint ck_vaults__key_version check (key_version >= 1),
    constraint ck_vaults__log_seq check (log_seq >= 1),
    constraint ck_vaults__log_head_hash_length check (octet_length(log_head_hash) = 32),
    constraint ck_vaults__change_seq check (change_seq >= 0),
    constraint ck_vaults__live_section_count check (live_section_count >= 0),
    constraint ck_vaults__stored_section_count check (stored_section_count >= live_section_count),
    constraint ck_vaults__pause_complete check (
        (pause_user_id is null and pause_by_admin is null and pause_until is null) or
        (pause_user_id is not null and pause_by_admin is not null and pause_until is not null)
    )
);

-- ---------------------------------------------------------------------------------------------
-- write_pause_requests: when each editor last paused a vault's writes, so an editor who is not an
-- admin pauses a vault only once per interval (PROTOCOL.md §7.5).
-- ---------------------------------------------------------------------------------------------
create table cloak.write_pause_requests (
    vault_id    uuid        not null,
    user_id     uuid        not null,
    paused_at   timestamptz not null,
    constraint pk_write_pause_requests primary key (vault_id, user_id),
    constraint fk_write_pause_requests__vault_id__vaults foreign key (vault_id)
        references cloak.vaults (id) on delete cascade on update restrict
);

create index ix_vaults__created_by_user_id on cloak.vaults (created_by_user_id);

-- ---------------------------------------------------------------------------------------------
-- vault_keys: every key version of a vault with its commitment from the signed log. Version
-- v > 1 carries key v - 1 wrapped by key v (PROTOCOL.md §6.2).
-- ---------------------------------------------------------------------------------------------
create table cloak.vault_keys (
    vault_id              uuid        not null,
    version               integer     not null,
    key_commitment        bytea       not null,
    previous_wrapped_key  bytea,
    created_at            timestamptz not null,
    constraint pk_vault_keys primary key (vault_id, version),
    constraint fk_vault_keys__vault_id__vaults foreign key (vault_id)
        references cloak.vaults (id) on delete cascade on update restrict,
    constraint ck_vault_keys__key_commitment_length check (octet_length(key_commitment) = 32),
    constraint ck_vault_keys__previous_only_after_first check (
        (version = 1 and previous_wrapped_key is null) or
        (version > 1 and previous_wrapped_key is not null and octet_length(previous_wrapped_key) = 73)
    )
);

-- ---------------------------------------------------------------------------------------------
-- vault_members: members with their role and committed key version (PROTOCOL.md §7.2), and the
-- current vault key sealed to them. The envelope is absent while it awaits delivery, such as
-- after a rotation that skipped a member whose committed key version was superseded. accepted says
-- whether the member accepted the vault (unsigned, PROTOCOL.md §12.4); added_by_user_id is who
-- added them per the log, absent for the vault's creator.
-- ---------------------------------------------------------------------------------------------
create table cloak.vault_members (
    vault_id                    uuid        not null,
    user_id                     uuid        not null,
    role                        varchar(16) not null,
    user_key_version            integer     not null,
    keys_digest                 bytea       not null,
    key_envelope                bytea,
    envelope_key_version        integer,
    accepted                    boolean     not null,
    added_by_user_id            uuid,
    added_at                    timestamptz not null,
    constraint pk_vault_members primary key (vault_id, user_id),
    constraint fk_vault_members__vault_id__vaults foreign key (vault_id)
        references cloak.vaults (id) on delete cascade on update restrict,
    constraint fk_vault_members__user_id_user_key_version__identity_keys foreign key (user_id, user_key_version)
        references cloak.identity_keys (user_id, key_version) on delete restrict on update restrict,
    constraint fk_vault_members__vault_id_envelope_key_version__vault_keys foreign key (vault_id, envelope_key_version)
        references cloak.vault_keys (vault_id, version) on delete no action on update restrict,
    constraint ck_vault_members__role check (role in ('owner', 'admin', 'editor', 'viewer')),
    constraint ck_vault_members__keys_digest_length check (octet_length(keys_digest) = 32),
    constraint ck_vault_members__envelope_complete check (
        (key_envelope is null and envelope_key_version is null) or
        (key_envelope is not null and envelope_key_version is not null and octet_length(key_envelope) = 81)
    )
);

create index ix_vault_members__user_id on cloak.vault_members (user_id);
create index ix_vault_members__user_id_accepted on cloak.vault_members (user_id, accepted);

-- ---------------------------------------------------------------------------------------------
-- accepted_inviters: people whose every vault a user accepts, now and later (PROTOCOL.md §12.4).
-- Acceptance is the server's help against being added unasked; the log alone decides rights.
-- ---------------------------------------------------------------------------------------------
create table cloak.accepted_inviters (
    user_id          uuid        not null,
    inviter_user_id  uuid        not null,
    accepted_at      timestamptz not null,
    constraint pk_accepted_inviters primary key (user_id, inviter_user_id)
);

-- ---------------------------------------------------------------------------------------------
-- vault_log: the signed, hash-chained history of a vault (PROTOCOL.md §7), append-only. Each
-- entry is signed by its author over its canonical message, which includes the previous entry's
-- hash. The subject is a plain id without a foreign key: removed members' entries remain.
-- checkpoint_size is the number of leaves of the entry's checkpoint, if it carries one.
-- ---------------------------------------------------------------------------------------------
create table cloak.vault_log (
    vault_id             uuid        not null,
    seq                  bigint      not null,
    kind                 varchar(32) not null,
    subject_user_id      uuid,
    role                 varchar(16),
    key_version          integer     not null,
    subject_keys         bytea,
    subject_key_version  integer,
    key_commitment       bytea,
    checkpoint           bytea,
    checkpoint_size      integer,
    request_end          boolean     not null,
    author_user_id       uuid        not null,
    author_key_version   integer     not null,
    node_id              uuid,
    home_vault_id        uuid,
    node_key             varchar(255),
    sections             varchar(6500),
    signature            bytea       not null,
    entry_hash           bytea       not null,
    created_at           timestamptz not null,
    constraint pk_vault_log primary key (vault_id, seq),
    constraint fk_vault_log__vault_id__vaults foreign key (vault_id)
        references cloak.vaults (id) on delete cascade on update restrict,
    constraint fk_vault_log__author_user_id_author_key_version__identity_keys foreign key (author_user_id, author_key_version)
        references cloak.identity_keys (user_id, key_version) on delete restrict on update restrict,
    constraint ck_vault_log__key_version check (key_version >= 1),
    constraint ck_vault_log__role check (role is null or role in ('owner', 'admin', 'editor', 'viewer')),
    constraint ck_vault_log__signature_length check (octet_length(signature) = 65),
    constraint ck_vault_log__entry_hash_length check (octet_length(entry_hash) = 32),
    constraint ck_vault_log__subject_keys_complete check (
        (subject_keys is null and subject_key_version is null) or
        (subject_keys is not null and subject_key_version is not null and octet_length(subject_keys) = 32 and subject_key_version >= 1)
    ),
    constraint ck_vault_log__key_commitment_length check (key_commitment is null or octet_length(key_commitment) = 32),
    constraint ck_vault_log__checkpoint_length check (checkpoint is null or octet_length(checkpoint) = 32),
    constraint ck_vault_log__checkpoint_size check (
        (checkpoint is null and checkpoint_size is null) or
        (checkpoint is not null and checkpoint_size is not null and checkpoint_size >= 0)
    ),
    constraint ck_vault_log__kind_shape check (
        (kind = 'vault_created'        and seq = 1 and subject_user_id is not null and coalesce(role, '') = 'owner'     and subject_keys is not null and key_commitment is not null and checkpoint is null) or
        (kind = 'member_added'         and seq > 1 and subject_user_id is not null and role is not null   and subject_keys is not null and key_commitment is null     and checkpoint is null) or
        (kind = 'member_role_set'      and seq > 1 and subject_user_id is not null and role is not null   and subject_keys is not null and key_commitment is null) or
        (kind = 'member_removed'       and seq > 1 and subject_user_id is not null and role is null       and subject_keys is not null and key_commitment is null) or
        (kind = 'member_keys_replaced' and seq > 1 and subject_user_id is not null and role is null       and subject_keys is not null and key_commitment is null) or
        (kind = 'key_rotated'          and seq > 1 and subject_user_id is null     and role is null       and subject_keys is null     and key_commitment is not null and checkpoint is not null) or
        (kind in ('node_created', 'node_shared', 'node_unshared', 'vault_deleted') and seq > 1 and subject_user_id is null and role is null
            and subject_keys is null and key_commitment is null and checkpoint is null)
    ),
    constraint ck_vault_log__node_fields check (
        (kind = 'node_created'  and node_id is not null and home_vault_id is null     and node_key is not null and sections is null) or
        (kind = 'node_shared'   and node_id is not null and home_vault_id is not null and node_key is not null and sections is not null) or
        (kind = 'node_unshared' and node_id is not null and home_vault_id is null     and node_key is null     and sections is not null) or
        (kind not in ('node_created', 'node_shared', 'node_unshared') and node_id is null and home_vault_id is null
            and node_key is null and sections is null)
    )
);

create index ix_vault_log__author_user_id_author_key_version on cloak.vault_log (author_user_id, author_key_version);

-- ---------------------------------------------------------------------------------------------
-- checkpoint_leaves: the leaves of every checkpoint in the log (PROTOCOL.md §7.5), so the server can
-- prove what a checkpoint holds for any section. Each row is one section's leaf over a span of
-- checkpoints: it belongs to the checkpoint of entry s when from_seq <= s < until_seq, and to every
-- later one while until_seq is null. A new checkpoint closes and opens rows only for the sections
-- whose leaf changed, so storage grows with the writes checkpointed, not with checkpoints times
-- sections. Positions are not stored: a checkpoint's leaves are its rows ordered by (node_id,
-- section_name), byte order, which section_name's "C" collation gives.
-- ---------------------------------------------------------------------------------------------
create table cloak.checkpoint_leaves (
    vault_id      uuid        not null,
    node_id       uuid        not null,
    section_name  varchar(64) collate "C" not null,
    data_version  bigint      not null,
    write_hash    bytea       not null,
    from_seq      bigint      not null,
    until_seq     bigint,
    constraint pk_checkpoint_leaves primary key (vault_id, node_id, section_name, from_seq),
    constraint fk_checkpoint_leaves__vault_id_from_seq__vault_log foreign key (vault_id, from_seq)
        references cloak.vault_log (vault_id, seq) on delete cascade on update restrict,
    constraint fk_checkpoint_leaves__vault_id_until_seq__vault_log foreign key (vault_id, until_seq)
        references cloak.vault_log (vault_id, seq) on delete cascade on update restrict,
    constraint ck_checkpoint_leaves__span check (until_seq is null or until_seq > from_seq),
    constraint ck_checkpoint_leaves__section_name_format check (section_name ~ '^[a-z][a-z0-9_]{0,63}$'),
    constraint ck_checkpoint_leaves__data_version check (data_version >= 1),
    constraint ck_checkpoint_leaves__write_hash_length check (octet_length(write_hash) = 32)
);

-- At most one open span per section: the leaf every later checkpoint holds until it changes.
create unique index uq_checkpoint_leaves__vault_id_node_id_section_name__open
    on cloak.checkpoint_leaves (vault_id, node_id, section_name) where until_seq is null;

-- ---------------------------------------------------------------------------------------------
-- sections: the latest signed write of every section, deletions included, so the next write
-- chains to it (PROTOCOL.md §8); a deletion is kept without content and is never a checkpoint leaf. A section is (vault_id, node_id, section_name); change_seq
-- orders a vault's writes for incremental reads. ciphertext_hash is SHA-256 of the ciphertext, the
-- digest the write signs, so headers are served without reading the ciphertext. home_vault_id,
-- owner_user_id and node_key are the node's origin every write signs (PROTOCOL.md §8.1).
-- ---------------------------------------------------------------------------------------------
create table cloak.sections (
    vault_id             uuid        not null,
    node_id              uuid        not null,
    section_name         varchar(64) not null,
    node_type            varchar(64) not null,
    home_vault_id        uuid        not null,
    owner_user_id        uuid        not null,
    node_key             varchar(255) not null,
    vault_key_version    integer     not null,
    data_version         bigint      not null,
    deleted              boolean     not null,
    log_seq              bigint      not null,
    log_head_hash        bytea       not null,
    previous_write_hash  bytea,
    writer_user_id       uuid        not null,
    writer_key_version   integer     not null,
    ciphertext           bytea,
    ciphertext_hash      bytea,
    signature            bytea       not null,
    write_hash           bytea       not null,
    change_seq           bigint      not null,
    written_at           timestamptz not null,
    constraint pk_sections primary key (vault_id, node_id, section_name),
    constraint fk_sections__vault_id__vaults foreign key (vault_id)
        references cloak.vaults (id) on delete cascade on update restrict,
    constraint fk_sections__vault_id_vault_key_version__vault_keys foreign key (vault_id, vault_key_version)
        references cloak.vault_keys (vault_id, version) on delete no action on update restrict,
    constraint fk_sections__writer_user_id_writer_key_version__identity_keys foreign key (writer_user_id, writer_key_version)
        references cloak.identity_keys (user_id, key_version) on delete restrict on update restrict,
    constraint uq_sections__vault_id_change_seq unique (vault_id, change_seq),
    constraint ck_sections__section_name_format check (section_name ~ '^[a-z][a-z0-9_]{0,63}$'),
    constraint ck_sections__node_type_format check (node_type ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    constraint ck_sections__data_version check (data_version >= 1),
    constraint ck_sections__log_seq check (log_seq >= 1),
    constraint ck_sections__log_head_hash_length check (octet_length(log_head_hash) = 32),
    constraint ck_sections__previous_write_hash check (
        (data_version = 1 and previous_write_hash is null) or
        (data_version > 1 and previous_write_hash is not null and octet_length(previous_write_hash) = 32)
    ),
    constraint ck_sections__deleted_has_no_ciphertext check (deleted = (ciphertext is null)),
    constraint ck_sections__ciphertext_size check (
        ciphertext is null or (octet_length(ciphertext) between 297 and 1048576 and (octet_length(ciphertext) - 41) % 256 = 0)
    ),
    constraint ck_sections__ciphertext_hash check (
        (ciphertext is null and ciphertext_hash is null) or
        (ciphertext is not null and ciphertext_hash is not null and octet_length(ciphertext_hash) = 32)
    ),
    constraint ck_sections__signature_length check (octet_length(signature) = 65),
    constraint ck_sections__write_hash_length check (octet_length(write_hash) = 32),
    constraint ck_sections__change_seq check (change_seq >= 1)
);

create index ix_sections__node_id on cloak.sections (node_id);

-- ---------------------------------------------------------------------------------------------
-- section_removals: sections the host removed with their node (a purge), each with the change
-- number it took in its vault, so a client's change feed drops them (PROTOCOL.md §15). The removed
-- rows are gone from sections; this is all that is left of them.
-- ---------------------------------------------------------------------------------------------
create table cloak.section_removals (
    vault_id      uuid        not null,
    change_seq    bigint      not null,
    node_id       uuid        not null,
    section_name  varchar(64) not null,
    constraint pk_section_removals primary key (vault_id, change_seq),
    constraint fk_section_removals__vault_id__vaults foreign key (vault_id)
        references cloak.vaults (id) on delete cascade on update restrict,
    constraint ck_section_removals__change_seq check (change_seq >= 1),
    constraint ck_section_removals__section_name_format check (section_name ~ '^[a-z][a-z0-9_]{0,63}$')
);
create index ix_sections__writer_user_id_writer_key_version on cloak.sections (writer_user_id, writer_key_version);

-- ---------------------------------------------------------------------------------------------
-- nodes: the nodes created in a vault, their home, by the owner's signed node_created (PROTOCOL.md
-- §7.7): who owns each, its key and the seq from which its sections are valid there. A write with
-- content in its node's home is stored only if the node is here.
-- ---------------------------------------------------------------------------------------------
create table cloak.nodes (
    vault_id        uuid         not null,
    node_id         uuid         not null,
    owner_user_id   uuid         not null,
    node_key        varchar(255) not null,
    created_seq     bigint       not null,
    constraint pk_nodes primary key (vault_id, node_id),
    constraint fk_nodes__vault_id__vaults foreign key (vault_id)
        references cloak.vaults (id) on delete cascade on update restrict,
    constraint ck_nodes__created_seq check (created_seq >= 2)
);

create index ix_nodes__node_id on cloak.nodes (node_id);

-- ---------------------------------------------------------------------------------------------
-- node_shares: nodes shared into a vault from their home by the owner's signed node_shared, as the
-- log leaves them (PROTOCOL.md §7.7): owner, home and key, and the seq from which every name is
-- shared when shared with *. node_share_names holds the names shared by name, each with its seq.
-- A share ends with node_unshared or when its owner stops being a member.
-- ---------------------------------------------------------------------------------------------
create table cloak.node_shares (
    vault_id        uuid         not null,
    node_id         uuid         not null,
    owner_user_id   uuid         not null,
    home_vault_id   uuid         not null,
    node_key        varchar(255) not null,
    all_since       bigint,
    constraint pk_node_shares primary key (vault_id, node_id),
    constraint fk_node_shares__vault_id__vaults foreign key (vault_id)
        references cloak.vaults (id) on delete cascade on update restrict,
    constraint ck_node_shares__home_elsewhere check (home_vault_id <> vault_id)
);

create index ix_node_shares__vault_id_owner_user_id on cloak.node_shares (vault_id, owner_user_id);
create index ix_node_shares__node_id on cloak.node_shares (node_id);

create table cloak.node_share_names (
    vault_id        uuid        not null,
    node_id         uuid        not null,
    section_name    varchar(64) not null,
    since           bigint      not null,
    constraint pk_node_share_names primary key (vault_id, node_id, section_name),
    constraint fk_node_share_names__vault_id_node_id__node_shares foreign key (vault_id, node_id)
        references cloak.node_shares (vault_id, node_id) on delete cascade on update restrict,
    constraint ck_node_share_names__section_name_format check (section_name ~ '^[a-z][a-z0-9_]{0,63}$')
);
