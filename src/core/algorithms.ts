// The numbers OpenPGP gives algorithms (RFC 4880 §9, RFC 6637, RFC 9580 §9), and which of
// them this program accepts where.

import type { HashAlgorithm } from './crypto/hash.ts';
import { SHA1 } from './crypto/sha1.ts';
import { SHA256 } from './crypto/sha256.ts';
import { SHA512 } from './crypto/sha512.ts';

export const PUBKEY = { RSA: 1, RSA_E: 2, RSA_S: 3, ELGAMAL: 16, DSA: 17, ECDH: 18, ECDSA: 19, EDDSA: 22, X25519: 25, X448: 26, ED25519: 27, ED448: 28 } as const;
export const HASH = { MD5: 1, SHA1: 2, RIPEMD160: 3, SHA256: 8, SHA384: 9, SHA512: 10, SHA224: 11 } as const;
export const SYM = { AES128: 7, AES192: 8, AES256: 9 } as const;
export const COMPRESSION = { NONE: 0, ZIP: 1, ZLIB: 2, BZIP2: 3 } as const;

/** 1.3.6.1.4.1.11591.15.1 — Ed25519 in EdDSA (legacy) keys. */
export const OID_ED25519 = Uint8Array.of(0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01);
/** 1.3.6.1.4.1.3029.1.5.1 — Curve25519 in ECDH keys. */
export const OID_CV25519 = Uint8Array.of(0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01);

/** Hashes a signature may use: SHA-256 and SHA-512, nothing weaker and nothing else. */
export function signatureHash(id: number): HashAlgorithm | null {
  if (id === HASH.SHA256) return SHA256;
  if (id === HASH.SHA512) return SHA512;
  return null;
}

/** Hashes S2K may use when reading keys and messages: GnuPG still protects exports with SHA-1. */
export function s2kHash(id: number): HashAlgorithm | null {
  if (id === HASH.SHA1) return SHA1;
  return signatureHash(id);
}

/** AES key sizes by algorithm number: only AES-128 and AES-256. */
export function aesKeySize(id: number): number | null {
  if (id === SYM.AES128) return 16;
  if (id === SYM.AES256) return 32;
  return null;
}

/** ECDH KDF parameters this program accepts on a Cv25519 key: what GnuPG makes, and ours. */
export function kdfAllowed(hash: number, cipher: number): boolean {
  return (hash === HASH.SHA256 || hash === HASH.SHA512) && (cipher === SYM.AES128 || cipher === SYM.AES256);
}

const NAMES: Record<number, string> = {
  [PUBKEY.RSA]: 'RSA', [PUBKEY.RSA_E]: 'RSA', [PUBKEY.RSA_S]: 'RSA', [PUBKEY.ELGAMAL]: 'ElGamal', [PUBKEY.DSA]: 'DSA',
  [PUBKEY.ECDH]: 'ECDH', [PUBKEY.ECDSA]: 'ECDSA', [PUBKEY.EDDSA]: 'EdDSA', [PUBKEY.X25519]: 'X25519', [PUBKEY.X448]: 'X448',
  [PUBKEY.ED25519]: 'Ed25519', [PUBKEY.ED448]: 'Ed448',
};

export const algorithmName = (id: number): string => NAMES[id] ?? `algorithm ${id}`;
