import type { Role } from '@voirdev/cloak-crypto';

import type { CloakSectionErrorReason } from './CloakSectionError.ts';

/** A member of a vault as its verified log shows them. */
export interface VaultMember {
  /**
   * The member's host user id; `undefined` only for a deleted member this device never knew by
   * name (`PROTOCOL.md` §5.0).
   */
  readonly userId: string | undefined;
  /** Their role. */
  readonly role: Role;
  /** The identity key version the log committed for them. */
  readonly keyVersion: number;
  /** Whether that version is still their newest one this device knows. */
  readonly keysCurrent: boolean;
  /**
   * Whether the server marks the member deleted (`PROTOCOL.md` §5.7). Unsigned: nobody gets the
   * vault key sealed to them again, and an admin should remove them with a rotation.
   */
  readonly deleted: boolean;
}

/** A vault as this session verified it: every field comes from its signed log. */
export interface VerifiedVault {
  /** The vault. */
  readonly id: string;
  /** The signed-in user's role. */
  readonly role: Role;
  /** Current vault key version. */
  readonly keyVersion: number;
  /** `seq` of the verified head. */
  readonly logSeq: number;
  /** Members by the log. */
  readonly members: readonly VaultMember[];
  /**
   * Whether someone left or replaced their keys since the last rotation and still knows the
   * current key; an admin should rotate (`PROTOCOL.md` §7.4).
   */
  readonly rotationDue: boolean;
  /**
   * Whether an owner deleted the vault, by its signed log (`PROTOCOL.md` §12.3). Its content is
   * gone; this device forgot it, keeping its verified head.
   */
  readonly deleted: boolean;
}

/** A vault after this user's newest keys were recorded in it (`PROTOCOL.md` §5.6). */
export interface KeyReplacementRecord {
  /** The vault, verified after the replacement. */
  readonly vault: VerifiedVault;
  /**
   * `seq` of log entries signed with this user's replaced keys that this device did not sign.
   * Another device of the user may have made them; otherwise whoever held the old keys did.
   * Review them, and undo unwanted changes with a rotation (`PROTOCOL.md` §5.6, §16).
   */
  readonly unrecognizedEntries: readonly number[];
}

/** A vault as the server lists it, before verification. */
export interface VaultSummary {
  /** The vault. */
  readonly id: string;
  /** The role the server claims for the signed-in user; `openVault` verifies it. */
  readonly role: Role;
  /** Instant it was created. */
  readonly createdAt: string;
  /** Whether the user accepted the vault; the server's word, not the log's. */
  readonly accepted: boolean;
  /** Host user id of who added the user, when the server says. */
  readonly addedBy?: string | undefined;
}

/** One page of a listing. */
export interface Page<T> {
  /** Items of this page. */
  readonly items: readonly T[];
  /** Cursor of the next page; absent on the last page. */
  readonly nextCursor?: string | undefined;
}

/** Where a section lives and what its latest write says about it. */
export interface SectionInfo {
  /** Vault the section lives in. */
  readonly vaultId: string;
  /** Node of the section. */
  readonly nodeId: string;
  /** Section name. */
  readonly name: string;
  /** App-defined node type, as the writer signed it. */
  readonly type: string;
  /** Data version of the latest write. */
  readonly dataVersion: number;
  /** Change number of the latest write within its vault. */
  readonly changeSeq: number;
  /** Host user id of the latest write's writer. */
  readonly writerUserId: string;
  /**
   * The node as its writes name it: owner, home vault and key. A section shown with a node of the
   * user's record must come from that node, and its writer may be any editor where it lives.
   */
  readonly node: NodeRef;
}

/**
 * A section as read and checked (`PROTOCOL.md` §8.4): its content, a deletion, or the reason
 * its latest write was refused. Content is JSON and comes back as `unknown`; validate it.
 */
export type DecryptedSection = SectionInfo &
  (
    | {
        /** Discriminant. */
        readonly status: 'ok';
        /** The content. */
        readonly content: unknown;
      }
    | {
        /** Discriminant. */
        readonly status: 'deleted';
      }
    | {
        /** Discriminant. */
        readonly status: 'refused';
        /** Why the latest write was refused. */
        readonly reason: CloakSectionErrorReason;
      }
  );

/** The sections of a node this session can read, across vaults. */
export interface DecryptedNode {
  /** The node. */
  readonly nodeId: string;
  /** Its readable sections. */
  readonly sections: readonly DecryptedSection[];
  /** Whether its live sections name different node types (`PROTOCOL.md` §8.1). */
  readonly typeConflict: boolean;
  /** Section names live in more than one vault; each is a separate section (§8.1). */
  readonly duplicateNames: readonly string[];
}

/**
 * A node as the application names it (`PROTOCOL.md` §8.1): who created it, its home vault and the
 * application's key for it, such as the id of the record it holds secrets for. Keep it beside the
 * record; the node's id derives from it ({@link nodeIdFor}).
 */
export interface NodeRef {
  /** Host user id of the node's owner, who created it. */
  readonly owner: string;
  /** The node's home vault. */
  readonly home: string;
  /** The application's key for the node, 1 to 255 bytes of UTF-8. */
  readonly key: string;
}

/** One write of {@link CloakSession.writeSections}. */
export interface SectionChange {
  /** Vault the section lives in: the node's home, or a vault that shares the section's name. */
  readonly vaultId: string;
  /** Node of the section. */
  readonly node: NodeRef;
  /** Section name. */
  readonly name: string;
  /** App-defined node type. */
  readonly type: string;
  /** New content; `undefined` deletes the section. */
  readonly content?: unknown;
}

/**
 * A section the host removed, such as when it deleted the resource the section belonged to. The
 * server says so without a signature, which is no more than it hiding the section: drop it from
 * what you show.
 */
export interface SectionRemoval {
  /** Node of the section. */
  readonly nodeId: string;
  /** Section name. */
  readonly name: string;
  /** Change number of the removal. */
  readonly changeSeq: number;
}

/** Changes of a vault's sections since a change number. */
export interface SectionChanges {
  /** Latest writes of the sections that changed, checked, by change number. */
  readonly sections: readonly DecryptedSection[];
  /** Sections the host removed in the same range of changes. */
  readonly removed: readonly SectionRemoval[];
  /** The vault's latest change number; pass it back to read only later changes. */
  readonly lastChangeSeq: number;
}

/** A vault where a change of {@link CloakSession.addMemberToVaults} failed, and why. */
export interface VaultFailure {
  /** The vault. */
  readonly vaultId: string;
  /** What was thrown. */
  readonly error: unknown;
}

/** The outcome of a change applied vault by vault. */
export interface VaultBatchResult {
  /** Vaults where the change was made. */
  readonly added: readonly string[];
  /** Vaults where it failed; the rest of the change still went ahead. */
  readonly failed: readonly VaultFailure[];
}

/** Every live section of a vault, as {@link CloakSession.readVault} reads it. */
export interface VaultContents {
  /** The latest write of each live section, checked, by change number; refused ones say why. */
  readonly sections: readonly DecryptedSection[];
  /** The vault's latest change number. */
  readonly lastChangeSeq: number;
}
