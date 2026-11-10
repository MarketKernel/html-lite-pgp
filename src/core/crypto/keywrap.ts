// AES Key Wrap, RFC 3394 — how ECDH in OpenPGP (RFC 6637 §8) wraps the session key.

import { Aes } from './aes.ts';
import { constantTimeEqual } from './util.ts';

const IV = new Uint8Array([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]);

/** XORs the 64-bit big-endian counter t into the first 8 bytes of `b`. */
function xorCounter(b: Uint8Array, t: number): void {
  for (let i = 7; i >= 0 && t > 0; i--, t = Math.floor(t / 256)) b[i] ^= t & 0xff;
}

export function aesKeyWrap(kek: Uint8Array, plain: Uint8Array): Uint8Array {
  if (plain.length < 16 || plain.length % 8 !== 0) throw new RangeError('key wrap: the data is a multiple of 8 bytes, at least 16');
  const aes = new Aes(kek);
  const n = plain.length / 8;
  const out = new Uint8Array(plain.length + 8);
  out.set(IV, 0);
  out.set(plain, 8);
  const b = new Uint8Array(16);
  for (let j = 0; j < 6; j++) {
    for (let i = 1; i <= n; i++) {
      b.set(out.subarray(0, 8), 0);
      b.set(out.subarray(i * 8, i * 8 + 8), 8);
      aes.encryptBlock(b, 0, b, 0);
      xorCounter(b, n * j + i);
      out.set(b.subarray(0, 8), 0);
      out.set(b.subarray(8), i * 8);
    }
  }
  b.fill(0);
  aes.destroy();
  return out;
}

/** The wrapped key, or null when the integrity check fails (wrong key or altered data). */
export function aesKeyUnwrap(kek: Uint8Array, wrapped: Uint8Array): Uint8Array | null {
  if (wrapped.length < 24 || wrapped.length % 8 !== 0) return null;
  const aes = new Aes(kek);
  const n = wrapped.length / 8 - 1;
  const r = new Uint8Array(wrapped);
  const b = new Uint8Array(16);
  for (let j = 5; j >= 0; j--) {
    for (let i = n; i >= 1; i--) {
      b.set(r.subarray(0, 8), 0);
      xorCounter(b, n * j + i);
      b.set(r.subarray(i * 8, i * 8 + 8), 8);
      aes.decryptBlock(b, 0, b, 0);
      r.set(b.subarray(0, 8), 0);
      r.set(b.subarray(8), i * 8);
    }
  }
  b.fill(0);
  aes.destroy();
  const ok = constantTimeEqual(r.subarray(0, 8), IV);
  const plain = r.slice(8);
  r.fill(0);
  if (!ok) {
    plain.fill(0);
    return null;
  }
  return plain;
}
