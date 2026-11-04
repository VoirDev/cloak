-- Cloak server schema, version 1.
--
-- Flyway runs this history with `schemas = cloak` and `table = flyway_schema_history`, so it
-- creates the `cloak` schema and keeps its own history inside it, apart from the host app.
--
-- Conventions:
-- * Columns named *_bundle, wrapped_key, ciphertext and signature hold opaque, self-describing
--   blobs: 1-byte format version || nonce (when the format has one) || payload. The server
--   stores and returns them, and never parses them.
-- * Public keys are raw 32-byte keys; their algorithm is fixed by identities.crypto_suite.
-- * user_id values come from the host app's authentication. Cloak never stores credentials.
-- * Every instant is TIMESTAMPTZ with microsecond precision; the application truncates to it.

-- ---------------------------------------------------------------------------------------------
-- identities: one row per user who has unlocked Cloak at least once.
-- ---------------------------------------------------------------------------------------------
create table cloak.identities (
    user_id                uuid        not null,
    crypto_suite           smallint    not null,
    encryption_public_key  bytea       not null,
    signing_public_key     bytea       not null,
    kdf_salt               bytea       not null,
    kdf_memory_kib         integer     not null,
    kdf_iterations         integer     not null,
    kdf_parallelism        integer     not null,
    private_key_bundle     bytea       not null,
    recovery_key_bundle    bytea       not null,
    credentials_version    integer     not null,
    created_at             timestamptz not null,
    updated_at             timestamptz not null,
    constraint pk_identities primary key (user_id),
    constraint uq_identities__signing_public_key unique (signing_public_key),
    constraint ck_identities__crypto_suite check (crypto_suite = 1),
    constraint ck_identities__encryption_public_key_length check (octet_length(encryption_public_key) = 32),
    constraint ck_identities__signing_public_key_length check (octet_length(signing_public_key) = 32),
    constraint ck_identities__kdf_salt_length check (octet_length(kdf_salt) = 16),
    constraint ck_identities__kdf_memory_kib check (kdf_memory_kib >= 65536),
    constraint ck_identities__kdf_iterations check (kdf_iterations >= 2),
    constraint ck_identities__kdf_parallelism check (kdf_parallelism between 1 and 16),
    constraint ck_identities__credentials_version check (credentials_version >= 1),
    constraint ck_identities__updated_after_created check (updated_at >= created_at)
);

-- ---------------------------------------------------------------------------------------------
-- nodes: the entity tree. A whole tree has one owner, the owner of its root.
-- ---------------------------------------------------------------------------------------------
create table cloak.nodes (
    id                  uuid        not null,
    parent_id           uuid,
    owner_user_id       uuid        not null,
    created_by_user_id  uuid        not null,
    type                varchar(64) not null,
    created_at          timestamptz not null,
    constraint pk_nodes primary key (id),
    constraint fk_nodes__parent_id__nodes foreign key (parent_id)
        references cloak.nodes (id) on delete restrict on update restrict,
    constraint fk_nodes__owner_user_id__identities foreign key (owner_user_id)
        references cloak.identities (user_id) on delete restrict on update restrict,
    constraint fk_nodes__created_by_user_id__identities foreign key (created_by_user_id)
        references cloak.identities (user_id) on delete restrict on update restrict,
    constraint ck_nodes__type_format check (type ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    constraint ck_nodes__not_own_parent check (parent_id is null or parent_id <> id)
);

create index ix_nodes__parent_id on cloak.nodes (parent_id);
create index ix_nodes__owner_user_id on cloak.nodes (owner_user_id);
create index ix_nodes__created_by_user_id on cloak.nodes (created_by_user_id);

-- ---------------------------------------------------------------------------------------------
-- sections: the current encrypted content of one named part of a node. No history is kept.
-- ---------------------------------------------------------------------------------------------
create table cloak.sections (
    node_id             uuid        not null,
    name                varchar(64) not null,
    key_version         integer     not null,
    data_version        bigint      not null,
    ciphertext          bytea       not null,
    signature           bytea       not null,
    written_by_user_id  uuid        not null,
    created_at          timestamptz not null,
    updated_at          timestamptz not null,
    constraint pk_sections primary key (node_id, name),
    constraint fk_sections__node_id__nodes foreign key (node_id)
        references cloak.nodes (id) on delete cascade on update restrict,
    constraint fk_sections__written_by_user_id__identities foreign key (written_by_user_id)
        references cloak.identities (user_id) on delete restrict on update restrict,
    constraint ck_sections__name_format check (name ~ '^[a-z][a-z0-9_]{0,63}$'),
    constraint ck_sections__key_version check (key_version >= 1),
    constraint ck_sections__data_version check (data_version >= 1),
    constraint ck_sections__ciphertext_size check (octet_length(ciphertext) <= 1048576),
    constraint ck_sections__updated_after_created check (updated_at >= created_at)
);

create index ix_sections__written_by_user_id on cloak.sections (written_by_user_id);

-- ---------------------------------------------------------------------------------------------
-- share_links: guest links. The link secret never reaches the server; it keeps only a hash of
-- an auth token derived from the secret, to check that a guest holds the link.
-- ---------------------------------------------------------------------------------------------
create table cloak.share_links (
    id                  uuid        not null,
    node_id             uuid        not null,
    auth_hash           bytea       not null,
    created_by_user_id  uuid        not null,
    expires_at          timestamptz,
    created_at          timestamptz not null,
    constraint pk_share_links primary key (id),
    constraint fk_share_links__node_id__nodes foreign key (node_id)
        references cloak.nodes (id) on delete cascade on update restrict,
    constraint fk_share_links__created_by_user_id__identities foreign key (created_by_user_id)
        references cloak.identities (user_id) on delete restrict on update restrict,
    constraint ck_share_links__auth_hash_length check (octet_length(auth_hash) = 32),
    constraint ck_share_links__expires_after_created check (expires_at is null or expires_at > created_at)
);

create index ix_share_links__node_id on cloak.share_links (node_id);
create index ix_share_links__created_by_user_id on cloak.share_links (created_by_user_id);
create index ix_share_links__expires_at on cloak.share_links (expires_at) where expires_at is not null;

-- ---------------------------------------------------------------------------------------------
-- invites: pending shares to people without an account. Deleted (with their grants) when
-- accepted, since acceptance turns them into user grants.
-- ---------------------------------------------------------------------------------------------
create table cloak.invites (
    id                  uuid        not null,
    node_id             uuid        not null,
    auth_hash           bytea       not null,
    invited_by_user_id  uuid        not null,
    expires_at          timestamptz not null,
    created_at          timestamptz not null,
    constraint pk_invites primary key (id),
    constraint fk_invites__node_id__nodes foreign key (node_id)
        references cloak.nodes (id) on delete cascade on update restrict,
    constraint fk_invites__invited_by_user_id__identities foreign key (invited_by_user_id)
        references cloak.identities (user_id) on delete restrict on update restrict,
    constraint ck_invites__auth_hash_length check (octet_length(auth_hash) = 32),
    constraint ck_invites__expires_after_created check (expires_at > created_at)
);

create index ix_invites__node_id on cloak.invites (node_id);
create index ix_invites__invited_by_user_id on cloak.invites (invited_by_user_id);
create index ix_invites__expires_at on cloak.invites (expires_at);

-- ---------------------------------------------------------------------------------------------
-- grants: one section key, at one key version, wrapped for exactly one recipient.
-- The owner holds ordinary grants too, so every read goes through the same path.
-- ---------------------------------------------------------------------------------------------
create table cloak.grants (
    id                  uuid        not null,
    node_id             uuid        not null,
    section_name        varchar(64) not null,
    key_version         integer     not null,
    recipient_type      varchar(16) not null,
    recipient_user_id   uuid,
    share_link_id       uuid,
    invite_id           uuid,
    permission          varchar(16) not null,
    wrapped_key         bytea       not null,
    signature           bytea       not null,
    granted_by_user_id  uuid        not null,
    created_at          timestamptz not null,
    constraint pk_grants primary key (id),
    constraint fk_grants__node_id_section_name__sections foreign key (node_id, section_name)
        references cloak.sections (node_id, name) on delete cascade on update restrict,
    constraint fk_grants__recipient_user_id__identities foreign key (recipient_user_id)
        references cloak.identities (user_id) on delete cascade on update restrict,
    constraint fk_grants__share_link_id__share_links foreign key (share_link_id)
        references cloak.share_links (id) on delete cascade on update restrict,
    constraint fk_grants__invite_id__invites foreign key (invite_id)
        references cloak.invites (id) on delete cascade on update restrict,
    constraint fk_grants__granted_by_user_id__identities foreign key (granted_by_user_id)
        references cloak.identities (user_id) on delete restrict on update restrict,
    constraint ck_grants__key_version check (key_version >= 1),
    constraint ck_grants__permission check (permission in ('read', 'write')),
    constraint ck_grants__recipient_type check (recipient_type in ('user', 'link', 'invite')),
    constraint ck_grants__single_recipient check (
        (recipient_type = 'user'   and recipient_user_id is not null and share_link_id is null and invite_id is null) or
        (recipient_type = 'link'   and recipient_user_id is null and share_link_id is not null and invite_id is null) or
        (recipient_type = 'invite' and recipient_user_id is null and share_link_id is null and invite_id is not null)
    ),
    constraint ck_grants__link_is_read_only check (recipient_type <> 'link' or permission = 'read')
);

create unique index uq_grants__section_version__user
    on cloak.grants (node_id, section_name, key_version, recipient_user_id) where recipient_type = 'user';
create unique index uq_grants__section_version__link
    on cloak.grants (node_id, section_name, key_version, share_link_id) where recipient_type = 'link';
create unique index uq_grants__section_version__invite
    on cloak.grants (node_id, section_name, key_version, invite_id) where recipient_type = 'invite';
create index ix_grants__recipient_user_id on cloak.grants (recipient_user_id);
create index ix_grants__share_link_id on cloak.grants (share_link_id);
create index ix_grants__invite_id on cloak.grants (invite_id);
create index ix_grants__granted_by_user_id on cloak.grants (granted_by_user_id);

-- ---------------------------------------------------------------------------------------------
-- rotation_tasks: sections that need a new key after a revocation. At most one task per
-- section; later revocations fold into the pending one. Deleted when the rotation completes.
-- ---------------------------------------------------------------------------------------------
create table cloak.rotation_tasks (
    node_id             uuid        not null,
    section_name        varchar(64) not null,
    from_key_version    integer     not null,
    claimed_by_user_id  uuid,
    claim_expires_at    timestamptz,
    owner_warned_at     timestamptz,
    created_at          timestamptz not null,
    constraint pk_rotation_tasks primary key (node_id, section_name),
    constraint fk_rotation_tasks__node_id_section_name__sections foreign key (node_id, section_name)
        references cloak.sections (node_id, name) on delete cascade on update restrict,
    constraint fk_rotation_tasks__claimed_by_user_id__identities foreign key (claimed_by_user_id)
        references cloak.identities (user_id) on delete set null on update restrict,
    constraint ck_rotation_tasks__from_key_version check (from_key_version >= 1),
    constraint ck_rotation_tasks__claim_complete check ((claimed_by_user_id is null) = (claim_expires_at is null))
);

create index ix_rotation_tasks__claimed_by_user_id on cloak.rotation_tasks (claimed_by_user_id);
create index ix_rotation_tasks__created_at__unwarned on cloak.rotation_tasks (created_at) where owner_warned_at is null;
