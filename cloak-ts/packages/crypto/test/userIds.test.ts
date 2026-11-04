import { describe, expect, it } from 'vitest';

import { USER_NAMESPACE, cloakUserId } from '../src/index.ts';
import { objects, text, vectors } from './vectors.ts';

const IDENTITY = vectors('identity.json');

describe('user ids', () => {
  it('uses the namespace of the vectors', () => {
    expect(USER_NAMESPACE).toBe(text(IDENTITY, 'userNamespace'));
  });

  it.each(objects(IDENTITY, 'userIds').map((json) => [text(json, 'hostUserId'), json] as const))(
    'derives the vector id of %s',
    (hostUserId, json) => {
      expect(cloakUserId(hostUserId)).toBe(text(json, 'userId'));
    },
  );

  it('compares host ids byte for byte and refuses empty or overlong ones', () => {
    expect(cloakUserId('Alice')).not.toBe(cloakUserId('alice'));
    expect(() => cloakUserId('')).toThrow();
    expect(() => cloakUserId('é'.repeat(128))).toThrow();
    expect(cloakUserId('é'.repeat(127))).toMatch(/^[0-9a-f-]{36}$/);
  });
});
