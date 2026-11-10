// A key's secrets for a passkey or a security key (Task.md §5.2–5.3), without the page's
// WebAuthn code (src/pwa/hardware.ts): what is kept, and how it is wrapped.
//
// The secrets are packed small — a largeBlob on a security key may hold only a kilobyte for
// all its credentials: a version byte, then for each (sub)key its fingerprint and its 32
// secret bytes as GnuPG stores them. Unpacked, every secret is checked against the public key
// in the keyring, as after a passphrase (Key Overwriting, §7.2): a device's copy is trusted
// no more than a stored one.
//
// The wrapping key comes from the device's PRF (WebAuthn's prf extension, CTAP's
// hmac-secret): K = HMAC-SHA-512(PRF output, "html-simple-pgp/prf/v1"), first 32 bytes. What
// it wraps is encrypted as our messages are, SEIPD v1 (AES-256-CFB + MDC): a changed byte or a
// wrong device is an 'integrity' error, and nothing comes out.

import { SYM } from './algorithms.ts';
import { Reader, Writer, equalBytes, utf8 } from './bytes.ts';
import { hmac } from './crypto/hmac.ts';
import { SHA512 } from './crypto/sha512.ts';
import { wipe } from './crypto/util.ts';
import { PgpError, malformed } from './errors.ts';
import { fingerprintHex } from './keys.ts';
import type { Cert } from './keys.ts';
import { decryptSeipd, encryptSeipd } from './seipd.ts';
import { secretOf, secretValue } from './secret.ts';
import type { Secret } from './secret.ts';

const PRF_LABEL = utf8('html-simple-pgp/prf/v1');
const PACK_VERSION = 1;

/** The 32-byte wrapping key from the device's PRF output. */
export function wrapKey(prf: Uint8Array): Uint8Array {
  const full = hmac(SHA512, prf, PRF_LABEL);
  const key = full.slice(0, 32);
  wipe(full);
  return key;
}

const keysOf = (cert: Cert) => [cert.primary, ...cert.subkeys.map((s) => s.key)];

/** The secrets (by hex fingerprint) of the certificate's keys, packed. */
export function packSecrets(cert: Cert, secrets: Map<string, Secret>): Uint8Array {
  const w = new Writer().byte(PACK_VERSION);
  let count = 0;
  for (const key of keysOf(cert)) {
    const secret = secrets.get(fingerprintHex(key.fingerprint));
    if (!secret) continue;
    const value = secretValue(secret);
    w.bytes(key.fingerprint).bytes(value);
    wipe(value);
    count++;
  }
  if (!count) throw new PgpError('unexpected', 'there is no secret to keep');
  return w.finish();
}

/** The secrets of a pack, by hex fingerprint, each checked against the certificate's public keys. */
export function unpackSecrets(cert: Cert, packed: Uint8Array): Map<string, Secret> {
  const r = new Reader(packed);
  if (r.byte('the version') !== PACK_VERSION) throw malformed('a device record of another version');
  const out = new Map<string, Secret>();
  try {
    while (r.remaining) {
      const fingerprint = r.bytes(20, 'a fingerprint');
      const value = new Uint8Array(r.bytes(32, 'a secret'));
      const key = keysOf(cert).find((k) => equalBytes(k.fingerprint, fingerprint));
      if (!key) throw new PgpError('integrity', 'the device holds a secret of another key');
      const hex = fingerprintHex(fingerprint);
      if (out.has(hex)) throw malformed('a secret twice');
      out.set(hex, secretOf(key, value));
    }
    if (!out.size) throw malformed('no secret');
    return out;
  } catch (error) {
    for (const s of out.values()) wipe(s.kind === 'ed25519' ? s.seed : s.scalar);
    throw error;
  }
}

/** The fingerprints a pack holds secrets for, without reading the secrets. */
export function packedFingerprints(packed: Uint8Array): string[] {
  const r = new Reader(packed);
  if (r.byte('the version') !== PACK_VERSION) throw malformed('a device record of another version');
  const out: string[] = [];
  while (r.remaining) {
    out.push(fingerprintHex(r.bytes(20, 'a fingerprint')));
    r.bytes(32, 'a secret');
  }
  return out;
}

export function wrap(key: Uint8Array, plain: Uint8Array, random: (n: number) => Uint8Array): Promise<Uint8Array> {
  return encryptSeipd({ cipher: SYM.AES256, key }, plain, random);
}

/** What `wrap` wrapped, after the MDC matched; an 'integrity' PgpError for a wrong key or a changed byte. */
export function unwrap(key: Uint8Array, wrapped: Uint8Array): Promise<Uint8Array> {
  return decryptSeipd({ cipher: SYM.AES256, key }, wrapped);
}

/**
 * What goes into a device's largeBlob: the pack as it is (0x00 — the device's own encryption
 * of large blobs protects it), or wrapped under the PRF's key when the device has a PRF (0x01).
 */
export async function sealBlob(packed: Uint8Array, key: Uint8Array | null, random: (n: number) => Uint8Array): Promise<Uint8Array> {
  if (!key) return new Writer().byte(0).bytes(packed).finish();
  return new Writer().byte(1).bytes(await wrap(key, packed, random)).finish();
}

/** The pack from a largeBlob; a blob wrapped under a PRF needs its key. */
export async function openBlob(blob: Uint8Array, key: Uint8Array | null): Promise<Uint8Array> {
  if (!blob.length) throw malformed('an empty device record');
  if (blob[0] === 0) return blob.slice(1);
  if (blob[0] !== 1) throw malformed('a device record of another kind');
  if (!key) throw new PgpError('integrity', 'the device record is wrapped, and the device gave no key for it');
  return unwrap(key, blob.subarray(1));
}

/** True when the blob needs the PRF's key to open. */
export const blobWrapped = (blob: Uint8Array): boolean => blob[0] === 1;
