import { describe, expect, expectTypeOf, it } from 'vitest';

import { CloakApiError, isCloakApiError, type CloakApiErrorCode } from '../src/CloakApiError.ts';
import type { Schemas } from '../src/api.ts';

/** The codes {@link CloakApiErrorCode} names, without the open end that keeps unknown ones. */
type NamedCode<Code = CloakApiErrorCode> = Code extends unknown
  ? string extends Code
    ? never
    : Code
  : never;

describe('CloakApiError', () => {
  it('reads code, version and field errors from a problem body', () => {
    const error = new CloakApiError(409, {
      type: 'urn:cloak:problem:version_conflict',
      code: 'version_conflict',
      detail: 'Someone wrote first.',
      currentVersion: 8,
      errors: [{ pointer: '/a', code: 'size', message: 'Too big.' }],
    });

    expect(error).toMatchObject({
      status: 409,
      code: 'version_conflict',
      currentVersion: 8,
      message: 'Someone wrote first.',
    });
    expect(error.fieldErrors).toHaveLength(1);
    expect(isCloakApiError(error, 'version_conflict')).toBe(true);
  });

  it('names the role a role_required problem asks for', () => {
    const error = new CloakApiError(403, { code: 'role_required', role: 'admin' });

    expect(error).toMatchObject({ code: 'role_required', role: 'admin' });
  });

  it('marks a body that is not a problem as unexpected', () => {
    const error = new CloakApiError(502, '<html>Bad gateway</html>');

    expect(error.code).toBe('unexpected_response');
    expect(isCloakApiError(error, 'not_found')).toBe(false);
  });

  it('names every error code the API has', () => {
    expectTypeOf<Exclude<Schemas['ErrorCode'], NamedCode>>().toEqualTypeOf<never>();
  });
});
