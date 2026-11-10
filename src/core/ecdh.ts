// Public-key encrypted session keys for Cv25519, RFC 4880 §5.1 with RFC 6637 §8: a fresh
// X25519 key per message and recipient, the shared secret through the KDF into a key that
// wraps the session key with AES Key Wrap.

import { OID_CV25519, PUBKEY, SYM, aesKeySize, kdfAllowed } from './algorithms.ts';
import { Reader, Writer, equalBytes, utf8 } from './bytes.ts';
import { aesKeyUnwrap, aesKeyWrap } from './crypto/keywrap.ts';
import { sha256 } from './crypto/sha256.ts';
import { sha512 } from './crypto/sha512.ts';
import { concat, constantTimeEqual, wipe } from './crypto/util.ts';
import { x25519, x25519Base } from './crypto/x25519.ts';
import { PgpError } from './errors.ts';
import type { KeyPacket } from './keys.ts';
import { readMpi, writeMpi } from './mpi.ts';

export interface Pkesk {
  /** All zeros when the sender hid the recipient (gpg --throw-keyids). */
  keyId: Uint8Array;
  algorithm: number;
  /** ECDH: the ephemeral public point (32 bytes) and the wrapped session key. */
  ephemeral: Uint8Array | null;
  wrapped: Uint8Array | null;
}

export function readPkesk(body: Uint8Array): Pkesk {
  const r = new Reader(body);
  const version = r.byte('the PKESK version');
  if (version !== 3) return { keyId: new Uint8Array(8), algorithm: -1, ephemeral: null, wrapped: null };
  const keyId = r.bytes(8, 'the recipient key ID');
  const algorithm = r.byte('the PKESK algorithm');
  if (algorithm !== PUBKEY.ECDH) return { keyId, algorithm, ephemeral: null, wrapped: null };
  const point = readMpi(r);
  const n = r.byte('the wrapped key length');
  const wrapped = r.bytes(n, 'the wrapped key');
  r.done('the encrypted session key');
  const ephemeral = point.length === 33 && point[0] === 0x40 ? point.subarray(1) : null;
  return { keyId, algorithm, ephemeral, wrapped };
}

const ANONYMOUS_SENDER = utf8('Anonymous Sender    ');

/** The KEK from the shared secret, RFC 6637 §7. */
function kek(recipient: KeyPacket, shared: Uint8Array): Uint8Array {
  const kdf = recipient.kdf!;
  const param = concat(Uint8Array.of(OID_CV25519.length), OID_CV25519, Uint8Array.of(PUBKEY.ECDH, 3, 1, kdf.hash, kdf.cipher), ANONYMOUS_SENDER, recipient.fingerprint);
  const input = concat(Uint8Array.of(0, 0, 0, 1), shared, param);
  const digest = kdf.hash === 8 ? sha256(input) : sha512(input);
  wipe(input);
  return digest.slice(0, aesKeySize(kdf.cipher)!);
}

function usable(recipient: KeyPacket): void {
  if (recipient.curve !== 'cv25519' || !recipient.point || !recipient.kdf || !kdfAllowed(recipient.kdf.hash, recipient.kdf.cipher)) {
    throw new PgpError('unsupported', 'this key cannot be encrypted to');
  }
}

/** The PKESK body for one recipient subkey: the session key for AES-256, wrapped. */
export function makePkesk(recipient: KeyPacket, sessionKey: Uint8Array, random: (n: number) => Uint8Array): Uint8Array {
  usable(recipient);
  const ephemeralSecret = random(32);
  const ephemeral = x25519Base(ephemeralSecret);
  const shared = x25519(ephemeralSecret, recipient.point!);
  const key = kek(recipient, shared);
  // The algorithm, the key, its 16-bit checksum, then PKCS#5 padding to a multiple of 8.
  let sum = 0;
  for (const b of sessionKey) sum = (sum + b) & 0xffff;
  const m = concat(Uint8Array.of(SYM.AES256), sessionKey, Uint8Array.of(sum >> 8, sum & 0xff));
  const pad = 8 - (m.length % 8);
  const padded = concat(m, new Uint8Array(pad).fill(pad));
  const wrapped = aesKeyWrap(key, padded);
  wipe(ephemeralSecret, shared, key, m, padded);
  const w = new Writer().byte(3).bytes(recipient.keyId).byte(PUBKEY.ECDH);
  writeMpi(w, concat(Uint8Array.of(0x40), ephemeral));
  return w.byte(wrapped.length).bytes(wrapped).finish();
}

export interface SessionKey {
  cipher: number;
  key: Uint8Array;
}

/**
 * The session key from a PKESK with our subkey's secret scalar, or null when it is not ours to
 * open. Every way of failing — a wrong key, altered data, bad padding — looks the same.
 */
export function openPkesk(pkesk: Pkesk, recipient: KeyPacket, scalar: Uint8Array): SessionKey | null {
  if (pkesk.algorithm !== PUBKEY.ECDH || !pkesk.ephemeral || !pkesk.wrapped) return null;
  usable(recipient);
  let shared: Uint8Array;
  try {
    shared = x25519(scalar, pkesk.ephemeral);
  } catch {
    return null;
  }
  const key = kek(recipient, shared);
  const m = aesKeyUnwrap(key, pkesk.wrapped);
  wipe(shared, key);
  if (!m) return null;
  try {
    const pad = m[m.length - 1];
    if (pad < 1 || pad > 8 || pad > m.length) return null;
    let padOk = 0;
    for (let i = m.length - pad; i < m.length; i++) padOk |= m[i] ^ pad;
    if (padOk) return null;
    const body = m.subarray(0, m.length - pad);
    const size = aesKeySize(body[0]);
    if (!size || body.length !== 1 + size + 2) return null;
    const sessionKey = body.slice(1, 1 + size);
    let sum = 0;
    for (const b of sessionKey) sum = (sum + b) & 0xffff;
    if (!constantTimeEqual(Uint8Array.of(sum >> 8, sum & 0xff), body.subarray(1 + size))) {
      wipe(sessionKey);
      return null;
    }
    return { cipher: body[0], key: sessionKey };
  } finally {
    wipe(m);
  }
}

/** Is this PKESK addressed to `subkey` (or to no one in particular)? */
export const addressedTo = (pkesk: Pkesk, subkey: KeyPacket): boolean =>
  pkesk.algorithm === PUBKEY.ECDH && (pkesk.keyId.every((b) => b === 0) || equalBytes(pkesk.keyId, subkey.keyId));

