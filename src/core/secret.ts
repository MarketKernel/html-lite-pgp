// The secret part of a key packet, RFC 4880 §5.5.3: reading it, unlocking it with the
// passphrase, protecting it again. We write what GnuPG imports — S2K usage 254: AES-256 in
// CFB under an Iterated+Salted SHA-256 key, the secret followed by its SHA-1 — and read that
// and unprotected keys (usage 0).
//
// Usage 254 does not protect the public part beside it. Someone who can change the stored key
// could swap the public point or the KDF parameters and learn the secret from what we then
// sign or decrypt ("Key Overwriting", Bruseghini, Paterson, Huigens 2022). So after every
// unlock the public key is computed again from the secret and must be the one in the packet,
// and the KDF parameters must be ours.
//
// A secret key packet may also say that its secret is not here: GnuPG's extension, S2K type
// 101, which `gpg --export-secret-subkeys` writes for the primary key and GnuPG keeps for keys
// on a smartcard. We write the same mark for a key kept on a passkey or a security key
// (Task.md §5.3); GnuPG imports such a key and lists it as `sec#`.

import { SYM, aesKeySize, HASH, kdfAllowed } from './algorithms.ts';
import { Reader, Writer, equalBytes, utf8 } from './bytes.ts';
import { cfbDecrypt, cfbEncrypt } from './crypto/cfb.ts';
import { ed25519PublicKey } from './crypto/ed25519.ts';
import { sha1 } from './crypto/sha1.ts';
import { constantTimeEqual, concat, wipe } from './crypto/util.ts';
import { clamp, x25519Base } from './crypto/x25519.ts';
import { PgpError, malformed, unsupported } from './errors.ts';
import type { Cert, KeyPacket } from './keys.ts';
import { fixed, readMpi, writeMpi } from './mpi.ts';
import { TAG } from './packets.ts';
import { deriveKey, readS2K, writeS2K } from './s2k.ts';
import type { S2K } from './s2k.ts';

/** An unlocked secret: the Ed25519 seed, or the Cv25519 scalar in X25519's own byte order. */
export type Secret = { kind: 'ed25519'; seed: Uint8Array } | { kind: 'cv25519'; scalar: Uint8Array };

export interface Protection {
  usage: number;
  /** GnuPG's mark: the secret is not in this packet (not exported, on a card or a device). */
  elsewhere: boolean;
  cipher: number;
  s2k: S2K | null;
  iv: Uint8Array;
  data: Uint8Array;
}

/** What GnuPG writes for a secret that is not there: usage 255, no cipher, S2K 101 "GNU" mode 1 (gnu-dummy). */
export const GNU_DUMMY = Uint8Array.of(0xff, 0x00, 0x65, 0x00, 0x47, 0x4e, 0x55, 0x01);

/** True when the packet carries GnuPG's mark instead of a secret: mode 1 (gnu-dummy) or 2 (on a smartcard). */
export function isElsewhere(key: KeyPacket): boolean {
  const b = key.secretBody;
  return !!b && b.length >= 8 && (b[0] === 254 || b[0] === 255) && b[2] === 101 && b[4] === 0x47 && b[5] === 0x4e && b[6] === 0x55 && (b[7] === 1 || b[7] === 2);
}

/** True when the secret itself is in the packet, under a passphrase or not. */
export const secretHere = (key: KeyPacket): boolean => !!key.secretBody && !isElsewhere(key);

export function readProtection(key: KeyPacket): Protection {
  if (!key.secretBody) throw new PgpError('unexpected', 'this key has no secret part');
  const r = new Reader(key.secretBody);
  const usage = r.byte('the S2K usage');
  if (isElsewhere(key)) return { usage, elsewhere: true, cipher: 0, s2k: null, iv: new Uint8Array(0), data: new Uint8Array(0) };
  if (usage === 0) return { usage, elsewhere: false, cipher: 0, s2k: null, iv: new Uint8Array(0), data: r.rest() };
  if (usage === 253) throw unsupported('a secret key protected with AEAD');
  if (usage !== 254) throw unsupported(`a secret key protected the old way (S2K usage ${usage})`);
  const cipher = r.byte('the cipher');
  if (!aesKeySize(cipher)) throw unsupported(`a secret key encrypted with cipher ${cipher}`);
  const s2k = readS2K(r);
  const iv = r.bytes(16, 'the IV');
  return { usage, elsewhere: false, cipher, s2k, iv, data: r.rest() };
}

/** True when the key opens without a passphrase. */
export const isUnprotected = (key: KeyPacket): boolean => readProtection(key).usage === 0;

function readSecret(key: KeyPacket, mpis: Uint8Array): Secret {
  const r = new Reader(mpis);
  const value = fixed(readMpi(r), 32, 'the secret key');
  r.done('the secret key');
  return secretOf(key, value);
}

/**
 * The secret from its 32 bytes as GnuPG stores them (the Ed25519 seed, or the Cv25519 scalar
 * big-endian), checked against the key's public part: a secret that does not make the
 * packet's public key, or a KDF that is not ours, is an 'integrity' error. A Cv25519 value
 * is wiped once turned around.
 */
export function secretOf(key: KeyPacket, value: Uint8Array): Secret {
  if (key.curve === 'ed25519') {
    if (!equalBytes(ed25519PublicKey(value), key.point!)) throw new PgpError('integrity', 'the secret key does not match its public key: the key was tampered with');
    return { kind: 'ed25519', seed: value };
  }
  if (key.curve === 'cv25519') {
    const scalar = value.slice().reverse();
    wipe(value);
    if (!key.kdf || !kdfAllowed(key.kdf.hash, key.kdf.cipher) || !equalBytes(x25519Base(scalar), key.point!)) {
      throw new PgpError('integrity', 'the secret key does not match its public key: the key was tampered with');
    }
    return { kind: 'cv25519', scalar };
  }
  throw unsupported('a secret key outside the profile');
}

/** Opens the secret with the passphrase ('' for an unprotected key). */
export async function unlock(key: KeyPacket, passphrase: string, onProgress?: (done: number) => void): Promise<Secret> {
  if (!key.curve) throw unsupported('a secret key outside the profile');
  const p = readProtection(key);
  if (p.elsewhere) throw new PgpError('unexpected', 'the secret part of this key is not here');
  if (p.usage === 0) {
    if (p.data.length < 2) throw malformed('the secret key is cut short');
    const mpis = p.data.subarray(0, p.data.length - 2);
    let sum = 0;
    for (const b of mpis) sum = (sum + b) & 0xffff;
    if (sum !== ((p.data[p.data.length - 2] << 8) | p.data[p.data.length - 1])) throw new PgpError('integrity', 'the secret key is damaged');
    return readSecret(key, mpis);
  }
  const k = await deriveKey(p.s2k!, utf8(passphrase), aesKeySize(p.cipher)!, onProgress);
  const plain = cfbDecrypt(k, p.data, p.iv);
  wipe(k);
  if (plain.length < 20) throw malformed('the secret key is cut short');
  const mpis = plain.subarray(0, plain.length - 20);
  const ok = constantTimeEqual(sha1(mpis), plain.subarray(plain.length - 20));
  try {
    if (!ok) throw new PgpError('bad-passphrase', 'the passphrase does not open this key');
    return readSecret(key, mpis);
  } finally {
    wipe(plain);
  }
}

/** The secret's 32 bytes as GnuPG stores them: Cv25519's scalar clamped and big-endian. */
export const secretValue = (secret: Secret): Uint8Array => (secret.kind === 'ed25519' ? secret.seed.slice() : clamp(secret.scalar).reverse());

/** The secret as the MPI GnuPG stores. */
function secretMpi(secret: Secret): Uint8Array {
  const value = secretValue(secret);
  const mpi = writeMpi(new Writer(), value).finish();
  wipe(value);
  return mpi;
}

export interface ProtectOptions {
  random: (n: number) => Uint8Array;
  /** The S2K count byte; 0xFF (65 MB hashed) unless a test wants it quicker. */
  countByte?: number;
  onProgress?: (done: number) => void;
}

/** The secret part of a key packet: under the passphrase, or unprotected for ''. */
export async function protect(secret: Secret, passphrase: string, options: ProtectOptions): Promise<Uint8Array> {
  const mpi = secretMpi(secret);
  try {
    if (passphrase === '') {
      let sum = 0;
      for (const b of mpi) sum = (sum + b) & 0xffff;
      return concat(Uint8Array.of(0), mpi, Uint8Array.of(sum >> 8, sum & 0xff));
    }
    const s2k: S2K = { type: 3, hash: HASH.SHA256, salt: options.random(8), countByte: options.countByte ?? 0xff };
    const iv = options.random(16);
    const k = await deriveKey(s2k, utf8(passphrase), 32, options.onProgress);
    const plain = concat(mpi, sha1(mpi));
    const data = cfbEncrypt(k, plain, iv);
    wipe(k, plain);
    const w = new Writer().byte(254).byte(SYM.AES256);
    writeS2K(w, s2k);
    return w.bytes(iv).bytes(data).finish();
  } finally {
    wipe(mpi);
  }
}

/** The key packet with this secret part (and the secret tag). */
export const withSecret = (key: KeyPacket, secretBody: Uint8Array, primary: boolean): KeyPacket => ({
  ...key,
  tag: primary ? TAG.SECRET_KEY : TAG.SECRET_SUBKEY,
  secretBody,
});

/** The public key alone. */
export const withoutSecret = (key: KeyPacket, primary: boolean): KeyPacket => ({ ...key, tag: primary ? TAG.PUBLIC_KEY : TAG.PUBLIC_SUBKEY, secretBody: null });

/** Every secret key packet of the certificate whose secret is here, unlocked with the passphrase. */
export async function unlockAll(cert: Cert, passphrase: string, onProgress?: (done: number) => void): Promise<Map<KeyPacket, Secret>> {
  const keys = [cert.primary, ...cert.subkeys.map((s) => s.key)].filter((k) => secretHere(k) && k.curve);
  const out = new Map<KeyPacket, Secret>();
  for (let i = 0; i < keys.length; i++) {
    out.set(keys[i], await unlock(keys[i], passphrase, onProgress && ((d) => onProgress((i + d) / keys.length))));
  }
  return out;
}

/** The certificate with its secrets protected under a (new) passphrase. */
export async function protectAll(cert: Cert, secrets: Map<KeyPacket, Secret>, passphrase: string, options: ProtectOptions): Promise<Cert> {
  const protectKey = async (key: KeyPacket, primary: boolean) => {
    const secret = secrets.get(key);
    return secret ? withSecret(key, await protect(secret, passphrase, options), primary) : key;
  };
  const primary = await protectKey(cert.primary, true);
  const subkeys = [];
  for (const s of cert.subkeys) subkeys.push({ ...s, key: await protectKey(s.key, false) });
  return { ...cert, primary, subkeys };
}

/** The certificate with GnuPG's mark in place of every secret: the secrets live elsewhere (on a device). */
export function secretsElsewhere(cert: Cert): Cert {
  const mark = (key: KeyPacket, primary: boolean): KeyPacket => (key.secretBody ? withSecret(key, GNU_DUMMY.slice(), primary) : key);
  return { ...cert, primary: mark(cert.primary, true), subkeys: cert.subkeys.map((s) => ({ ...s, key: mark(s.key, false) })) };
}

export function wipeSecret(secret: Secret): void {
  wipe(secret.kind === 'ed25519' ? secret.seed : secret.scalar);
}
