import type { Role } from '@voirdev/cloak-crypto';
import * as z from 'zod';

/** Error codes of the Cloak API; unknown future codes stay representable. */
export type CloakApiErrorCode =
  | 'validation_failed'
  | 'bad_signature'
  | 'log_rejected'
  | 'unsupported_format'
  | 'deprecated_format'
  | 'unauthenticated'
  | 'role_required'
  | 'not_found'
  | 'identity_required'
  | 'already_exists'
  | 'version_conflict'
  | 'stale_head'
  | 'vault_key_version_mismatch'
  | 'log_conflict'
  | 'checkpoint_conflict'
  | 'recipients_mismatch'
  | 'credentials_version_conflict'
  | 'identity_version_conflict'
  | 'identity_in_vaults'
  | 'pause_held'
  | 'identity_deleted'
  | 'payload_too_large'
  | 'rate_limited'
  | 'busy'
  | 'internal_error'
  | 'network_error'
  | 'unexpected_response'
  | (string & {});

/** One violated rule of a `validation_failed` problem. */
export interface CloakFieldError {
  /** JSON Pointer of the value. */
  readonly pointer: string;
  /** Violated rule. */
  readonly code: string;
  /** Explanation for developers. */
  readonly message: string;
}

/** RFC 9457 body the server sends; validated because error bodies are not trusted as typed. */
const problemSchema = z.object({
  /** Stable code. */
  code: z.string(),
  /** Explanation of this occurrence. */
  detail: z.string().optional(),
  /** Current version for the version-conflict codes. */
  currentVersion: z.number().optional(),
  /** Role a `role_required` problem asks for. */
  role: z.enum(['viewer', 'editor', 'admin', 'owner']).optional(),
  /** Correlation id for the server logs. */
  traceId: z.string().optional(),
  /** The vault a batch request was refused for. */
  vaultId: z.string().optional(),
  /** Field-level violations. */
  errors: z
    .array(z.object({ pointer: z.string(), code: z.string(), message: z.string() }))
    .optional(),
});

/** Failure of a request to the Cloak API. */
export class CloakApiError extends Error {
  /** HTTP status. */
  readonly status: number;
  /**
   * Stable code; `network_error` with status 0 when no response arrived (the cause is kept), and
   * `unexpected_response` when the body was not a Cloak problem.
   */
  readonly code: CloakApiErrorCode;
  /**
   * Current version for `version_conflict`, `vault_key_version_mismatch`,
   * `credentials_version_conflict` and `identity_version_conflict`; the log's head `seq` for
   * `log_conflict` and `stale_head`.
   */
  readonly currentVersion: number | undefined;
  /** Role a `role_required` problem asks for. */
  readonly role: Role | undefined;
  /** Field-level violations of a `validation_failed` problem. */
  readonly fieldErrors: readonly CloakFieldError[];
  /** Correlation id for the server logs. */
  readonly traceId: string | undefined;
  /** The vault a batch request was refused for, such as one of `removeFromVaults`. */
  readonly vaultId: string | undefined;

  /**
   * @param status HTTP status.
   * @param body Response body, parsed as JSON when possible.
   * @param options Standard error options, to keep the underlying `cause`.
   */
  constructor(status: number, body: unknown, options?: ErrorOptions) {
    const problem = problemSchema.safeParse(body);
    super(
      problem.success
        ? (problem.data.detail ?? problem.data.code)
        : `Unexpected ${String(status)} response`,
      options,
    );
    this.name = 'CloakApiError';
    this.status = status;
    this.code = problem.success ? problem.data.code : 'unexpected_response';
    this.currentVersion = problem.success ? problem.data.currentVersion : undefined;
    this.role = problem.success ? problem.data.role : undefined;
    this.fieldErrors = problem.success ? (problem.data.errors ?? []) : [];
    this.traceId = problem.success ? problem.data.traceId : undefined;
    this.vaultId = problem.success ? problem.data.vaultId : undefined;
  }
}

/**
 * Tells whether a value is a {@link CloakApiError}, optionally with a given code.
 *
 * @param error Caught value.
 * @param code Code to match.
 * @returns Whether it matches.
 */
export function isCloakApiError(error: unknown, code?: CloakApiErrorCode): error is CloakApiError {
  return error instanceof CloakApiError && (code === undefined || error.code === code);
}
