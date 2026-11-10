// CFB mode with a 128-bit feedback, as OpenPGP uses it (RFC 4880 §13.9) for SEIPD v1 and for
// protected secret keys: each block of keystream is AES of the previous ciphertext block, the
// first of the IV. OpenPGP's own quirk — the random prefix and its two repeated bytes — is the
// caller's business (seipd.ts); this is the plain mode.
//
// Encryption is sequential by nature. Decryption is not: every block's input is ciphertext
// already at hand, so two blocks go through AES at once.

import { Aes } from './aes.ts';

const ZERO_IV = new Uint8Array(16);

/** Work is done in slices of this size, with a pause between them for the page to breathe. */
const SLICE = 1 << 20;

const pause = () => new Promise((resolve) => setTimeout(resolve, 0));

function encryptRange(aes: Aes, data: Uint8Array, out: Uint8Array, from: number, to: number, fr: Uint8Array): void {
  const ks = new Uint8Array(16);
  for (let at = from; at < to; at += 16) {
    aes.encryptBlock(fr, 0, ks, 0);
    const n = Math.min(16, to - at);
    for (let i = 0; i < n; i++) out[at + i] = data[at + i] ^ ks[i];
    if (n === 16) fr.set(out.subarray(at, at + 16));
  }
  ks.fill(0);
}

function decryptRange(aes: Aes, data: Uint8Array, out: Uint8Array, from: number, to: number, iv: Uint8Array): void {
  const input = new Uint8Array(32);
  const ks = new Uint8Array(32);
  // The block before `at`: the IV for the first one, ciphertext after that.
  const previous = (at: number, into: number) => input.set(at === 0 ? iv : data.subarray(at - 16, at), into);
  for (let at = from; at < to; at += 32) {
    previous(at, 0);
    const two = at + 16 < to;
    if (two) previous(at + 16, 16);
    aes.encryptTwo(input, 0, 16, ks, 0, 16);
    const n = Math.min(32, to - at);
    for (let i = 0; i < n; i++) out[at + i] = data[at + i] ^ ks[i];
  }
  input.fill(0);
  ks.fill(0);
}

export function cfbEncrypt(key: Uint8Array | Aes, data: Uint8Array, iv: Uint8Array = ZERO_IV): Uint8Array {
  const aes = key instanceof Aes ? key : new Aes(key);
  const out = new Uint8Array(data.length);
  encryptRange(aes, data, out, 0, data.length, new Uint8Array(iv));
  if (!(key instanceof Aes)) aes.destroy();
  return out;
}

export function cfbDecrypt(key: Uint8Array | Aes, data: Uint8Array, iv: Uint8Array = ZERO_IV): Uint8Array {
  const aes = key instanceof Aes ? key : new Aes(key);
  const out = new Uint8Array(data.length);
  decryptRange(aes, data, out, 0, data.length, iv);
  if (!(key instanceof Aes)) aes.destroy();
  return out;
}

/** The same as cfbEncrypt, a slice at a time, telling how far it got (0…1). */
export async function cfbEncryptAsync(key: Uint8Array, data: Uint8Array, onProgress?: (done: number) => void): Promise<Uint8Array> {
  const aes = new Aes(key);
  const out = new Uint8Array(data.length);
  const fr = ZERO_IV.slice();
  for (let at = 0; at < data.length; at += SLICE) {
    encryptRange(aes, data, out, at, Math.min(data.length, at + SLICE), fr);
    onProgress?.(Math.min(1, (at + SLICE) / data.length));
    if (at + SLICE < data.length) await pause();
  }
  aes.destroy();
  return out;
}

export async function cfbDecryptAsync(key: Uint8Array, data: Uint8Array, onProgress?: (done: number) => void): Promise<Uint8Array> {
  const aes = new Aes(key);
  const out = new Uint8Array(data.length);
  for (let at = 0; at < data.length; at += SLICE) {
    decryptRange(aes, data, out, at, Math.min(data.length, at + SLICE), ZERO_IV);
    onProgress?.(Math.min(1, (at + SLICE) / data.length));
    if (at + SLICE < data.length) await pause();
  }
  aes.destroy();
  return out;
}
