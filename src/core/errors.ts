// Every failure the OpenPGP code reports is a PgpError with a code the interface can turn
// into words. Parsing never lets a RangeError or a TypeError out: tests feed it broken data
// and check.

export type ErrorCode =
  /** The data is not well-formed OpenPGP. */
  | 'malformed'
  /** Well-formed, but outside what this program does (another algorithm, version, mode). */
  | 'unsupported'
  /** Larger than the limits (input, packets, unpacked data). */
  | 'too-large'
  /** Not the kind of data that was expected here (a key where a message was wanted…). */
  | 'unexpected'
  /** The passphrase does not open the key, or the password the container. */
  | 'bad-passphrase'
  /** None of our keys can open this message. */
  | 'no-key'
  /** The ciphertext or the key was altered: MDC, checksum or Key Overwriting check failed. */
  | 'integrity'
  /** A key is unusable: expired, revoked, without a valid self-signature. */
  | 'bad-key';

export class PgpError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = 'PgpError';
  }
}

export const malformed = (message: string): PgpError => new PgpError('malformed', message);
export const unsupported = (message: string): PgpError => new PgpError('unsupported', message);
