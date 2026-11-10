// Version 4 signature packets, RFC 4880 §5.2: reading, hashing, verifying and making them —
// whatever they sign. What they sign (a key, a user ID, a file, a text) is the caller's: it
// passes the bytes that go into the hash before the signature's own trailer.
//
// Only what the signature says in its hashed area is believed. The unhashed area is anyone's
// to change, so it is read for hints only (which key made it). A critical subpacket we do not
// understand makes the signature invalid, as RFC 4880 §5.2.3.1 requires.

import { HASH, PUBKEY, signatureHash } from './algorithms.ts';
import { Reader, Writer } from './bytes.ts';
import { ed25519Sign, ed25519Verify } from './crypto/ed25519.ts';
import { concat } from './crypto/util.ts';
import { malformed } from './errors.ts';
import { fixed, readMpi, writeMpi } from './mpi.ts';

export const SIG = {
  BINARY: 0x00,
  TEXT: 0x01,
  CERT_GENERIC: 0x10,
  CERT_PERSONA: 0x11,
  CERT_CASUAL: 0x12,
  CERT_POSITIVE: 0x13,
  SUBKEY_BINDING: 0x18,
  PRIMARY_BINDING: 0x19,
  DIRECT_KEY: 0x1f,
  KEY_REVOCATION: 0x20,
  SUBKEY_REVOCATION: 0x28,
  CERT_REVOCATION: 0x30,
} as const;

export const SUB = {
  CREATED: 2,
  EXPIRES: 3,
  EXPORTABLE: 4,
  TRUST: 5,
  REVOCABLE: 7,
  KEY_EXPIRES: 9,
  PREF_SYMMETRIC: 11,
  REVOCATION_KEY: 12,
  ISSUER: 16,
  NOTATION: 20,
  PREF_HASH: 21,
  PREF_COMPRESSION: 22,
  KEY_SERVER_PREFS: 23,
  PREFERRED_KEY_SERVER: 24,
  PRIMARY_USER_ID: 25,
  POLICY_URI: 26,
  KEY_FLAGS: 27,
  SIGNERS_USER_ID: 28,
  REASON: 29,
  FEATURES: 30,
  TARGET: 31,
  EMBEDDED: 32,
  ISSUER_FINGERPRINT: 33,
  PREF_AEAD: 34,
  INTENDED_RECIPIENT: 35,
  PREF_AEAD_SUITES: 39,
} as const;

/** Subpackets we understand: a critical one outside this set invalidates the signature. */
const UNDERSTOOD: ReadonlySet<number> = new Set([
  SUB.CREATED, SUB.EXPIRES, SUB.EXPORTABLE, SUB.REVOCABLE, SUB.KEY_EXPIRES, SUB.PREF_SYMMETRIC, SUB.ISSUER,
  SUB.PREF_HASH, SUB.PREF_COMPRESSION, SUB.KEY_SERVER_PREFS, SUB.PREFERRED_KEY_SERVER, SUB.PRIMARY_USER_ID,
  SUB.POLICY_URI, SUB.KEY_FLAGS, SUB.SIGNERS_USER_ID, SUB.REASON, SUB.FEATURES, SUB.EMBEDDED,
  SUB.ISSUER_FINGERPRINT, SUB.PREF_AEAD, SUB.INTENDED_RECIPIENT, SUB.PREF_AEAD_SUITES,
]);

export const KEY_FLAG = { CERTIFY: 0x01, SIGN: 0x02, ENCRYPT_COMMS: 0x04, ENCRYPT_STORAGE: 0x08 } as const;

export interface Subpacket {
  type: number;
  critical: boolean;
  body: Uint8Array;
}

export interface Signature {
  version: number;
  type: number;
  algorithm: number;
  hash: number;
  hashed: Subpacket[];
  unhashed: Subpacket[];
  /** Version through the hashed subpackets: what goes into the hash, with the trailer after it. */
  hashedPart: Uint8Array;
  left16: Uint8Array;
  /** EdDSA's R and S as 32 bytes each; empty for other algorithms. */
  r: Uint8Array;
  s: Uint8Array;
  /** The packet body as it came. */
  body: Uint8Array;
}

function readSubpackets(data: Uint8Array): Subpacket[] {
  const r = new Reader(data);
  const out: Subpacket[] = [];
  while (r.remaining > 0) {
    const first = r.byte('a subpacket length');
    let length: number;
    if (first < 192) length = first;
    else if (first < 255) length = ((first - 192) << 8) + r.byte('a subpacket length') + 192;
    else length = r.u32('a subpacket length');
    if (length === 0) throw malformed('a subpacket of length zero');
    const body = r.bytes(length, 'a subpacket');
    out.push({ type: body[0] & 0x7f, critical: (body[0] & 0x80) !== 0, body: body.subarray(1) });
  }
  return out;
}

/** Reads a signature packet's body. Versions other than 4 come back with `version` set and nothing else filled. */
export function readSignature(body: Uint8Array): Signature {
  const r = new Reader(body);
  const version = r.byte('the signature version');
  const empty = new Uint8Array(0);
  if (version !== 4) return { version, type: -1, algorithm: -1, hash: -1, hashed: [], unhashed: [], hashedPart: empty, left16: empty, r: empty, s: empty, body };
  const type = r.byte('the signature type');
  const algorithm = r.byte('the signature algorithm');
  const hash = r.byte('the signature hash');
  const hashedLength = r.u16('the hashed subpackets length');
  const hashed = readSubpackets(r.bytes(hashedLength, 'the hashed subpackets'));
  const hashedPart = body.subarray(0, r.at);
  const unhashed = readSubpackets(r.bytes(r.u16('the unhashed subpackets length'), 'the unhashed subpackets'));
  const left16 = r.bytes(2, 'the hash prefix');
  let sigR = empty;
  let sigS = empty;
  if (algorithm === PUBKEY.EDDSA) {
    sigR = fixed(readMpi(r), 32, 'the signature R');
    sigS = fixed(readMpi(r), 32, 'the signature S');
    r.done('the signature');
  }
  return { version, type, algorithm, hash, hashed, unhashed, hashedPart, left16, r: sigR, s: sigS, body };
}

const find = (list: Subpacket[], type: number): Subpacket | undefined => list.find((p) => p.type === type);

const u32 = (b: Uint8Array): number => ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;

/** The hashed subpacket's body, if it has one of exactly `length` bytes (or any length if omitted). */
function hashedBody(sig: Signature, type: number, length?: number): Uint8Array | null {
  const p = find(sig.hashed, type);
  if (!p) return null;
  if (length !== undefined && p.body.length !== length) throw malformed(`subpacket ${type} has the wrong length`);
  return p.body;
}

export const created = (sig: Signature): number | null => {
  const b = hashedBody(sig, SUB.CREATED, 4);
  return b ? u32(b) : null;
};

/** Seconds after creation when the signature expires; 0 or null: never. */
export const signatureExpires = (sig: Signature): number | null => {
  const b = hashedBody(sig, SUB.EXPIRES, 4);
  return b ? u32(b) : null;
};

/** Seconds after the key's creation when the key expires; 0 or null: never. */
export const keyExpires = (sig: Signature): number | null => {
  const b = hashedBody(sig, SUB.KEY_EXPIRES, 4);
  return b ? u32(b) : null;
};

export const keyFlags = (sig: Signature): number | null => {
  const b = hashedBody(sig, SUB.KEY_FLAGS);
  return b && b.length ? b[0] : null;
};

export const exportable = (sig: Signature): boolean => {
  const b = hashedBody(sig, SUB.EXPORTABLE, 1);
  return !b || b[0] !== 0;
};

export const isPrimaryUserId = (sig: Signature): boolean => {
  const b = hashedBody(sig, SUB.PRIMARY_USER_ID, 1);
  return !!b && b[0] !== 0;
};

export const preferences = (sig: Signature, type: number): number[] => [...(hashedBody(sig, type) ?? [])];

export const features = (sig: Signature): number => hashedBody(sig, SUB.FEATURES)?.[0] ?? 0;

export function revocationReason(sig: Signature): { code: number; text: string } | null {
  const b = hashedBody(sig, SUB.REASON);
  if (!b || b.length < 1) return null;
  return { code: b[0], text: new TextDecoder('utf-8', { fatal: false }).decode(b.subarray(1)) };
}

/** The issuer's fingerprint (hashed, or as a hint from the unhashed area). */
export function issuerFingerprint(sig: Signature): Uint8Array | null {
  const p = find(sig.hashed, SUB.ISSUER_FINGERPRINT) ?? find(sig.unhashed, SUB.ISSUER_FINGERPRINT);
  return p && p.body.length === 21 && p.body[0] === 4 ? p.body.subarray(1) : null;
}

/** The issuer's key ID: from the fingerprint, or the Issuer subpacket. */
export function issuerKeyId(sig: Signature): Uint8Array | null {
  const fpr = issuerFingerprint(sig);
  if (fpr) return fpr.subarray(12);
  const p = find(sig.hashed, SUB.ISSUER) ?? find(sig.unhashed, SUB.ISSUER);
  return p && p.body.length === 8 ? p.body : null;
}

/** Embedded signatures (the primary key binding of a signing subkey). */
export function embedded(sig: Signature): Signature[] {
  return [...sig.hashed, ...sig.unhashed].filter((p) => p.type === SUB.EMBEDDED).map((p) => readSignature(p.body));
}

export const intendedRecipients = (sig: Signature): Uint8Array[] =>
  sig.hashed.filter((p) => p.type === SUB.INTENDED_RECIPIENT && p.body.length === 21 && p.body[0] === 4).map((p) => p.body.subarray(1));

/** A signature we can check at all: v4, EdDSA, SHA-256 or SHA-512, no critical surprises. */
export function supported(sig: Signature): boolean {
  if (sig.version !== 4 || sig.algorithm !== PUBKEY.EDDSA || !signatureHash(sig.hash)) return false;
  return [...sig.hashed, ...sig.unhashed].every((p) => !p.critical || UNDERSTOOD.has(p.type));
}

/** The digest the signature covers: the signed data, the hashed part, the v4 trailer. */
export function signatureDigest(sig: Pick<Signature, 'hash' | 'hashedPart'>, data: Uint8Array[]): Uint8Array {
  const algo = signatureHash(sig.hash);
  if (!algo) throw malformed('a signature with an unsupported hash');
  const h = algo.create();
  for (const part of data) h.update(part);
  h.update(sig.hashedPart);
  const n = sig.hashedPart.length;
  h.update(Uint8Array.of(0x04, 0xff, n >>> 24, n >>> 16, n >>> 8, n));
  return h.digest();
}

/**
 * True when `sig` is a valid Ed25519 signature of `data` by `publicKey` (32 bytes). Says
 * nothing about whether that key may sign, or was valid then: the key's checks are keys.ts's.
 */
export function verifySignature(sig: Signature, publicKey: Uint8Array, data: Uint8Array[]): boolean {
  if (!supported(sig) || created(sig) === null) return false;
  const digest = signatureDigest(sig, data);
  if (digest[0] !== sig.left16[0] || digest[1] !== sig.left16[1]) return false;
  return ed25519Verify(publicKey, digest, concat(sig.r, sig.s));
}

export function subpacket(type: number, body: Uint8Array, critical = false): Uint8Array {
  const n = body.length + 1;
  const w = new Writer();
  if (n < 192) w.byte(n);
  else if (n < 16320) w.byte(((n - 192) >> 8) + 192).byte((n - 192) & 0xff);
  else w.byte(255).u32(n);
  return w.byte(type | (critical ? 0x80 : 0)).bytes(body).finish();
}

export const u32Bytes = (v: number): Uint8Array => Uint8Array.of(v >>> 24, v >>> 16, v >>> 8, v);

export interface Signer {
  seed: Uint8Array;
  fingerprint: Uint8Array;
}

/**
 * Makes a v4 Ed25519 signature over `data` with SHA-512. The creation time and the issuer
 * fingerprint go first in the hashed area, the issuer key ID in the unhashed one — as GnuPG
 * writes them.
 */
export function makeSignature(type: number, signer: Signer, data: Uint8Array[], time: number, hashed: Uint8Array[] = [], unhashed: Uint8Array[] = []): Uint8Array {
  const hashedArea = concat(subpacket(SUB.CREATED, u32Bytes(time)), subpacket(SUB.ISSUER_FINGERPRINT, concat(Uint8Array.of(4), signer.fingerprint)), ...hashed);
  const unhashedArea = concat(subpacket(SUB.ISSUER, signer.fingerprint.subarray(12)), ...unhashed);
  if (hashedArea.length > 0xffff || unhashedArea.length > 0xffff) throw malformed('too many subpackets');
  const hashedPart = new Writer().byte(4).byte(type).byte(PUBKEY.EDDSA).byte(HASH.SHA512).u16(hashedArea.length).bytes(hashedArea).finish();
  const digest = signatureDigest({ hash: HASH.SHA512, hashedPart }, data);
  const sig = ed25519Sign(signer.seed, digest);
  const w = new Writer().bytes(hashedPart).u16(unhashedArea.length).bytes(unhashedArea).bytes(digest.subarray(0, 2));
  writeMpi(w, sig.subarray(0, 32));
  writeMpi(w, sig.subarray(32));
  return w.finish();
}
