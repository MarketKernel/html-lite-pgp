// scrypt, RFC 7914: what turns a passphrase into a key in "key from a passphrase" (Task.md
// §4.4). Memory-hard on purpose: N·r·128 bytes for each guess. Built from PBKDF2-HMAC-SHA-256
// and the Salsa20/8 core, both written out here from the RFC. Memory is read at addresses
// that depend on the data — that is the algorithm, and the reason it is memory-hard.

import { pbkdf2 } from './pbkdf2.ts';
import { SHA256 } from './sha256.ts';
import { wipe } from './util.ts';

const R = (a: number, b: number): number => (a << b) | (a >>> (32 - b));

/** Salsa20/8 of the 16 words at `B[at..]`, in place (RFC 7914 §3). `x` is scratch. */
function salsa208(B: Uint32Array, at: number, x: Uint32Array): void {
  for (let i = 0; i < 16; i++) x[i] = B[at + i];
  for (let i = 0; i < 8; i += 2) {
    x[4] ^= R(x[0] + x[12], 7); x[8] ^= R(x[4] + x[0], 9);
    x[12] ^= R(x[8] + x[4], 13); x[0] ^= R(x[12] + x[8], 18);
    x[9] ^= R(x[5] + x[1], 7); x[13] ^= R(x[9] + x[5], 9);
    x[1] ^= R(x[13] + x[9], 13); x[5] ^= R(x[1] + x[13], 18);
    x[14] ^= R(x[10] + x[6], 7); x[2] ^= R(x[14] + x[10], 9);
    x[6] ^= R(x[2] + x[14], 13); x[10] ^= R(x[6] + x[2], 18);
    x[3] ^= R(x[15] + x[11], 7); x[7] ^= R(x[3] + x[15], 9);
    x[11] ^= R(x[7] + x[3], 13); x[15] ^= R(x[11] + x[7], 18);
    x[1] ^= R(x[0] + x[3], 7); x[2] ^= R(x[1] + x[0], 9);
    x[3] ^= R(x[2] + x[1], 13); x[0] ^= R(x[3] + x[2], 18);
    x[6] ^= R(x[5] + x[4], 7); x[7] ^= R(x[6] + x[5], 9);
    x[4] ^= R(x[7] + x[6], 13); x[5] ^= R(x[4] + x[7], 18);
    x[11] ^= R(x[10] + x[9], 7); x[8] ^= R(x[11] + x[10], 9);
    x[9] ^= R(x[8] + x[11], 13); x[10] ^= R(x[9] + x[8], 18);
    x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9);
    x[14] ^= R(x[13] + x[12], 13); x[15] ^= R(x[14] + x[13], 18);
  }
  for (let i = 0; i < 16; i++) B[at + i] += x[i];
}

/** scryptBlockMix (RFC 7914 §4): `B` (2r blocks of 16 words) into `Y`. */
function blockMix(B: Uint32Array, Y: Uint32Array, r: number, X: Uint32Array, scratch: Uint32Array): void {
  X.set(B.subarray((2 * r - 1) * 16, 2 * r * 16));
  for (let i = 0; i < 2 * r; i++) {
    for (let k = 0; k < 16; k++) X[k] ^= B[i * 16 + k];
    salsa208(X, 0, scratch);
    // Even blocks to the first half, odd ones to the second.
    Y.set(X, ((i & 1) * r + (i >> 1)) * 16);
  }
}

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
  length: number;
}

/**
 * scrypt. `onProgress` (0…1) is called now and then; between calls the function yields to
 * the event loop, so a page stays alive through seconds of work.
 */
export async function scrypt(password: Uint8Array, salt: Uint8Array, { N, r, p, length }: ScryptParams, onProgress?: (done: number) => void): Promise<Uint8Array> {
  if (N < 2 || (N & (N - 1)) !== 0 || N > 2 ** 30) throw new RangeError('scrypt: N must be a power of two');
  if (r < 1 || p < 1 || r * p >= 2 ** 30) throw new RangeError('scrypt: bad r or p');
  const blockWords = 32 * r;
  const bytes = pbkdf2(SHA256, password, salt, 1, p * 128 * r);
  const B = new Uint32Array(p * blockWords);
  for (let i = 0; i < B.length; i++) B[i] = bytes[i * 4] | (bytes[i * 4 + 1] << 8) | (bytes[i * 4 + 2] << 16) | (bytes[i * 4 + 3] << 24);
  const V = new Uint32Array(N * blockWords);
  const X = new Uint32Array(blockWords);
  const Y = new Uint32Array(blockWords);
  const T = new Uint32Array(16);
  const scratch = new Uint32Array(16);
  const step = Math.max(1, Math.floor(N / 64));
  let ticks = 0;
  const total = 2 * N * p;
  const tick = async () => {
    ticks += step;
    onProgress?.(Math.min(1, ticks / total));
    await new Promise((resolve) => setTimeout(resolve, 0));
  };
  for (let b = 0; b < p; b++) {
    // ROMix (RFC 7914 §5) on block b.
    X.set(B.subarray(b * blockWords, (b + 1) * blockWords));
    for (let i = 0; i < N; i++) {
      V.set(X, i * blockWords);
      blockMix(X, Y, r, T, scratch);
      X.set(Y);
      if (i % step === step - 1) await tick();
    }
    for (let i = 0; i < N; i++) {
      const j = X[(2 * r - 1) * 16] & (N - 1);
      for (let k = 0; k < blockWords; k++) X[k] ^= V[j * blockWords + k];
      blockMix(X, Y, r, T, scratch);
      X.set(Y);
      if (i % step === step - 1) await tick();
    }
    B.set(X, b * blockWords);
  }
  for (let i = 0; i < B.length; i++) {
    const w = B[i];
    bytes[i * 4] = w;
    bytes[i * 4 + 1] = w >>> 8;
    bytes[i * 4 + 2] = w >>> 16;
    bytes[i * 4 + 3] = w >>> 24;
  }
  const out = pbkdf2(SHA256, password, bytes, 1, length);
  wipe(bytes, B, V, X, Y, T, scratch);
  onProgress?.(1);
  return out;
}
