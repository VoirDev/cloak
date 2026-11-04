/**
 * The session was closed and its keys wiped. Unlock again with the password for a new session.
 */
export class CloakSessionClosedError extends Error {
  constructor() {
    super('The session is closed; unlock again');
    this.name = 'CloakSessionClosedError';
  }
}
