import {
  cloakUserId,
  equalBytes,
  fingerprint,
  followKeyChain,
  keysDigest,
  toFingerprintCode,
  verifyKeyStatement,
  type KeyStatement,
  type PublicKeys,
} from '@voirdev/cloak-crypto';

import { CloakApiError } from './CloakApiError.ts';
import { CloakKeyChangedError } from './CloakKeyChangedError.ts';
import { body, type CloakApi } from './api.ts';
import type { LocalState } from './storage/localState.ts';
import { fromWireStatement } from './wire.ts';

/**
 * The key versions this device trusts for each person (`PROTOCOL.md` §5.2, §9): the version it
 * pinned when it first met them, and every later version a chain of statements reaches from it.
 * Lookups are synchronous once [load] has fetched the people a check needs.
 */
export interface Keyring {
  /**
   * Fetches and verifies the key chains of people, pinning anyone met for the first time at their
   * first version.
   *
   * @param userIds People to load; those already loaded are fetched again only with [refresh].
   * @param refresh Whether to fetch again people already loaded, to learn of newer versions.
   * @throws {CloakKeyChangedError} when the server's keys disagree with what this device trusts.
   */
  load(userIds: Iterable<string>, refresh?: boolean): Promise<void>;

  /**
   * A trusted key version of a loaded person.
   *
   * @param userId Person.
   * @param keyVersion Key version.
   * @returns The keys, or `undefined` when untrusted or not loaded.
   */
  keysOf(userId: string, keyVersion: number): PublicKeys | undefined;

  /**
   * The newest trusted key version of a loaded person.
   *
   * @param userId Person.
   * @returns The keys, or `undefined` when not loaded or without an identity.
   */
  newest(userId: string): PublicKeys | undefined;

  /**
   * Whether this device knows a later version of a person's keys.
   *
   * @param userId Person.
   * @param keyVersion Key version.
   * @returns Whether it is superseded.
   */
  isSuperseded(userId: string, keyVersion: number): boolean;

  /**
   * The newest key version of a person, verified from their first version but without pinning
   * them: what to show before the user confirmed their fingerprint.
   *
   * @param userId Person.
   * @returns The keys, or `undefined` when the person has no identity.
   * @throws {CloakKeyChangedError} when the served statements do not chain.
   */
  peek(userId: string): Promise<PublicKeys | undefined>;

  /**
   * Trusts a person at the key version whose fingerprint the user compared with them out of band.
   *
   * @param userId Person.
   * @param confirmed Fingerprint the user confirmed.
   * @throws {CloakKeyChangedError} when no version the server serves has that fingerprint, or the
   *   person is pinned at other keys.
   */
  confirm(userId: string, confirmed: string): Promise<void>;

  /**
   * Returns a person's host user id, as the server named it beside their keys and this device
   * checked it derives their Cloak id (`PROTOCOL.md` §5.0), or as this device kept it from such a
   * check; `undefined` until their keys loaded, and for a deleted person this device never knew.
   *
   * @param userId Cloak id of the person.
   * @returns Their host user id.
   */
  hostIdOf(userId: string): string | undefined;

  /**
   * Whether the server marked a loaded person deleted (`PROTOCOL.md` §5.7). The mark is not signed:
   * use it only to do less, such as not sealing vault keys to them.
   *
   * @param userId Cloak id of the person.
   * @returns Whether they are deleted.
   */
  isDeleted(userId: string): boolean;

  /**
   * Learns people's host user ids, each checked to derive their Cloak id, without pinning or
   * trusting their keys: for naming people, such as who added the user to a vault.
   *
   * @param userIds People whose names are not known yet; known ones are skipped.
   */
  learnNames(userIds: Iterable<string>): Promise<void>;
}

/**
 * Creates the keyring of a signed-in user.
 *
 * @param api HTTP client.
 * @param state The user's local state, where pins live.
 * @param own The user's own current keys, trusted from the unlocked bundle.
 * @param ownHostId The user's host user id, which derives `own.userId`.
 * @returns The keyring.
 */
export function createKeyring(
  api: CloakApi,
  state: LocalState,
  own: PublicKeys,
  ownHostId: string,
): Keyring {
  const versions = new Map<string, readonly PublicKeys[]>();
  /** Host user ids by Cloak id, each checked to derive its Cloak id. */
  const hostIds = new Map<string, string>([[own.userId, ownHostId]]);
  /** People the server marked deleted. */
  const deleted = new Set<string>();

  /** Fetches statements of several people; absent people have no identity. */
  async function fetchStatements(
    userIds: readonly string[],
  ): Promise<Map<string, readonly KeyStatement[]>> {
    const result = new Map<string, readonly KeyStatement[]>();
    for (let start = 0; start < userIds.length; start += 100) {
      const batch = userIds.slice(start, start + 100);
      const response = await body(api.POST('/users/keys/batch-get', { body: { userIds: batch } }));
      for (const item of response.items) {
        if (!batch.includes(item.userId)) continue;
        await learnName(item.userId, item.hostUserId, item.deleted);
        result.set(item.userId, item.versions.map(fromWireStatement));
      }
    }
    return result;
  }

  /**
   * Takes in how the server names a person. A name must derive their id, or it is someone else's;
   * only a deleted person may come without one, and then the name this device kept stands in.
   */
  async function learnName(
    userId: string,
    hostUserId: string | undefined,
    isGone: boolean,
  ): Promise<void> {
    if (isGone) deleted.add(userId);
    else deleted.delete(userId);
    if (hostUserId === undefined) {
      if (!isGone) throw new CloakApiError(0, undefined);
      const kept = hostIds.get(userId) ?? (await state.hostId(userId));
      if (kept !== undefined) hostIds.set(userId, kept);
      return;
    }
    if (!isHostIdOf(hostUserId, userId)) throw new CloakApiError(0, undefined);
    if (hostIds.get(userId) === hostUserId) return;
    hostIds.set(userId, hostUserId);
    if ((await state.hostId(userId)) !== hostUserId) await state.setHostId(userId, hostUserId);
  }

  /** Verifies one person's chain from their pin, pinning their first version when there is none. */
  async function trust(
    userId: string,
    statements: readonly KeyStatement[],
  ): Promise<readonly PublicKeys[]> {
    const alarm = (keyVersion: number, served?: PublicKeys, trusted?: Uint8Array): never => {
      throw new CloakKeyChangedError(
        hostIds.get(userId) ?? userId,
        keyVersion,
        trusted === undefined ? undefined : toFingerprintCode(trusted),
        served === undefined ? undefined : fingerprint(served),
      );
    };
    const mine = statements.filter((statement) => statement.keys.userId === userId);
    let pin = await state.pin(userId);
    if (pin === undefined) {
      const first = mine.find((statement) => statement.keys.keyVersion === 1);
      if (first === undefined || !verifyKeyStatement(first)) return alarm(1, first?.keys);
      pin = { keyVersion: 1, keysDigest: keysDigest(first.keys) };
      await state.setPin(userId, pin);
    }
    const pinned = mine.find((statement) => statement.keys.keyVersion === pin.keyVersion);
    if (pinned === undefined || !equalBytes(keysDigest(pinned.keys), pin.keysDigest)) {
      return alarm(pin.keyVersion, pinned?.keys, pin.keysDigest);
    }
    const chain = followKeyChain(pinned.keys, mine);
    if (!chain.ok)
      return alarm(
        chain.keyVersion,
        mine.find((s) => s.keys.keyVersion === chain.keyVersion)?.keys,
        pin.keysDigest,
      );
    // A server that hides newer statements would make this device forget that old keys were
    // replaced, so the newest version it ever verified must still be on the chain.
    const newest = await state.newest(userId);
    if (
      newest !== undefined &&
      !chain.versions.some(
        (keys) =>
          keys.keyVersion === newest.keyVersion && equalBytes(keysDigest(keys), newest.keysDigest),
      )
    ) {
      return alarm(
        newest.keyVersion,
        mine.find((s) => s.keys.keyVersion === newest.keyVersion)?.keys,
        newest.keysDigest,
      );
    }
    const last = chain.versions.at(-1);
    if (last !== undefined)
      await state.raiseNewest(userId, {
        keyVersion: last.keyVersion,
        keysDigest: keysDigest(last),
      });
    return chain.versions;
  }

  /**
   * Verifies a person's chain from their first version without pinning them, for showing a
   * fingerprint before the user confirmed it.
   */
  async function peek(userId: string): Promise<readonly PublicKeys[] | undefined> {
    const served = (await fetchStatements([userId])).get(userId);
    if (served === undefined) return undefined;
    const mine = served.filter((statement) => statement.keys.userId === userId);
    const first = mine.find((statement) => statement.keys.keyVersion === 1);
    const chain =
      first !== undefined && verifyKeyStatement(first)
        ? followKeyChain(first.keys, mine)
        : undefined;
    if (chain?.ok !== true)
      throw new CloakKeyChangedError(
        hostIds.get(userId) ?? userId,
        1,
        undefined,
        first === undefined ? undefined : fingerprint(first.keys),
      );
    return chain.versions;
  }

  /** Trusts the user's own versions, after checking the current one is theirs. */
  async function trustSelf(statements: readonly KeyStatement[]): Promise<readonly PublicKeys[]> {
    const current = statements.find((statement) => statement.keys.keyVersion === own.keyVersion);
    if (current === undefined || !equalBytes(keysDigest(current.keys), keysDigest(own))) {
      throw new CloakKeyChangedError(
        ownHostId,
        own.keyVersion,
        fingerprint(own),
        current === undefined ? undefined : fingerprint(current.keys),
      );
    }
    // Like anyone else, the user is pinned at their first version and followed from there; their
    // current keys, which the unlocked bundle vouches for, must be on that chain.
    const chain = await trust(own.userId, statements);
    if (
      !chain.some(
        (keys) =>
          keys.keyVersion === own.keyVersion && equalBytes(keysDigest(keys), keysDigest(own)),
      )
    ) {
      throw new CloakKeyChangedError(ownHostId, own.keyVersion, fingerprint(own), undefined);
    }
    return chain;
  }

  /** Fetches and verifies people's chains. */
  async function load(userIds: Iterable<string>, refresh = false): Promise<void> {
    const wanted = [...new Set(userIds)].filter((id) => refresh || !versions.has(id));
    if (wanted.length === 0) return;
    const statements = await fetchStatements(wanted);
    for (const userId of wanted) {
      const served = statements.get(userId);
      if (served === undefined) {
        versions.set(userId, []);
        continue;
      }
      versions.set(
        userId,
        userId === own.userId ? await trustSelf(served) : await trust(userId, served),
      );
    }
  }

  return {
    load,
    async peek(userId) {
      return (await peek(userId))?.at(-1);
    },
    keysOf(userId, keyVersion) {
      return versions.get(userId)?.find((keys) => keys.keyVersion === keyVersion);
    },
    newest(userId) {
      return versions.get(userId)?.at(-1);
    },
    isSuperseded(userId, keyVersion) {
      return (versions.get(userId)?.at(-1)?.keyVersion ?? keyVersion) > keyVersion;
    },
    async confirm(userId, confirmed) {
      const wanted = normalize(confirmed);
      if ((await state.pin(userId)) === undefined) {
        // Never met: the confirmed keys must be on the chain from the first version, which is
        // then pinned, so earlier entries by this person still verify.
        const chain = await peek(userId);
        const first = chain?.[0];
        if (first === undefined || !chain?.some((keys) => fingerprint(keys) === wanted)) {
          throw new CloakKeyChangedError(hostIds.get(userId) ?? userId, 0, wanted, undefined);
        }
        await state.setPin(userId, { keyVersion: first.keyVersion, keysDigest: keysDigest(first) });
      }
      // Met before: the confirmed keys must be on the chain from the pin.
      await load([userId], true);
      if (!(versions.get(userId) ?? []).some((keys) => fingerprint(keys) === wanted)) {
        throw new CloakKeyChangedError(hostIds.get(userId) ?? userId, 0, wanted, undefined);
      }
    },
    hostIdOf(userId) {
      return hostIds.get(userId);
    },
    isDeleted(userId) {
      return deleted.has(userId);
    },
    async learnNames(userIds) {
      const unknown = [...new Set(userIds)].filter((userId) => !hostIds.has(userId));
      if (unknown.length > 0) await fetchStatements(unknown);
    },
  };
}

/** Whether a host user id derives a Cloak id (`PROTOCOL.md` §5.0). */
function isHostIdOf(hostUserId: string, userId: string): boolean {
  try {
    return cloakUserId(hostUserId) === userId;
  } catch {
    return false;
  }
}

/** A fingerprint as the user may have typed it: uppercase, groups of four. */
function normalize(code: string): string {
  return (
    code
      .toUpperCase()
      .replace(/[\s-]/g, '')
      .match(/.{1,4}/g) ?? []
  ).join('-');
}
