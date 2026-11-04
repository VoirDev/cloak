import { cloakUserId, nodeIdOf, type NodeOrigin } from '@voirdev/cloak-crypto';

import type { NodeRef } from './model.ts';

/**
 * The protocol's view of a node an application names (`PROTOCOL.md` §8.1).
 *
 * @param node The node as the application names it.
 * @returns Its owner's Cloak id, home vault and key.
 */
export function originOf(node: NodeRef): NodeOrigin {
  return { ownerUserId: cloakUserId(node.owner), homeVaultId: node.home, nodeKey: node.key };
}

/**
 * The id of a node (`PROTOCOL.md` §8.1), as reads take it and the host's access checks name it.
 *
 * @param node The node as the application names it.
 * @returns Its id.
 */
export function nodeIdFor(node: NodeRef): string {
  return nodeIdOf(originOf(node));
}
