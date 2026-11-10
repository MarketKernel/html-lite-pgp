// String-to-key, RFC 4880 §3.7: how a passphrase becomes a key. Iterated+Salted (type 3) is
// what we write; GnuPG protects its exports with it too (with SHA-1, which we read). Simple
// and Salted are read for SKESK only if a message really uses them — we never write them.

import { s2kHash } from './algorithms.ts';
import { Reader, Writer } from './bytes.ts';
import { concat, wipe } from './crypto/util.ts';
import { malformed, unsupported } from './errors.ts';

export interface S2K {
  type: 0 | 1 | 3;
  hash: number;
  salt: Uint8Array;
  /** The coded count byte (type 3). */
  countByte: number;
}

/** How many bytes type 3 hashes for a coded count byte: 1024 up to 65 011 712. */
export const decodeCount = (c: number): number => (16 + (c & 15)) << ((c >> 4) + 6);

export function readS2K(r: Reader): S2K {
  const type = r.byte('the S2K type');
  if (type === 101) {
    // GnuPG's extension for a secret key kept elsewhere: on a smartcard, or not exported.
    throw unsupported('a key whose secret part is not here (on a smartcard, or exported without it)');
  }
  if (type !== 0 && type !== 1 && type !== 3) throw unsupported(`S2K type ${type}`);
  const hash = r.byte('the S2K hash');
  if (!s2kHash(hash)) throw unsupported(`an S2K hash (${hash})`);
  const salt = type === 0 ? new Uint8Array(0) : r.bytes(8, 'the S2K salt');
  const countByte = type === 3 ? r.byte('the S2K count') : 0;
  return { type, hash, salt: new Uint8Array(salt), countByte };
}

export function writeS2K(w: Writer, s2k: S2K): Writer {
  w.byte(s2k.type).byte(s2k.hash);
  if (s2k.type !== 0) w.bytes(s2k.salt);
  if (s2k.type === 3) w.byte(s2k.countByte);
  return w;
}

/**
 * The key of `size` bytes from the passphrase. When the hash is shorter than the key (SHA-1
 * and AES-256), more hash contexts are run, each preloaded with one more zero byte (§3.7.1).
 * It takes a second or so on purpose; `onProgress` hears how far it got, and the function
 * yields to the event loop between slices.
 */
export async function deriveKey(s2k: S2K, passphrase: Uint8Array, size: number, onProgress?: (done: number) => void): Promise<Uint8Array> {
  const algo = s2kHash(s2k.hash);
  if (!algo) throw malformed('an S2K hash');
  const pattern = concat(s2k.salt, passphrase);
  const total = s2k.type === 3 ? Math.max(decodeCount(s2k.countByte), pattern.length) : pattern.length;
  // A slice holding the pattern many times over, so the hash gets large updates.
  const repeats = Math.max(1, Math.floor(65536 / Math.max(1, pattern.length)));
  const slice = new Uint8Array(pattern.length * repeats);
  for (let i = 0; i < repeats; i++) slice.set(pattern, i * pattern.length);
  const contexts = Math.ceil(size / algo.outputLength);
  const out = new Uint8Array(contexts * algo.outputLength);
  let hashed = 0;
  for (let c = 0; c < contexts; c++) {
    const h = algo.create();
    if (c) h.update(new Uint8Array(c));
    let left = total;
    while (left >= slice.length) {
      h.update(slice);
      left -= slice.length;
      hashed += slice.length;
      if (hashed % (8 * slice.length) < slice.length) {
        onProgress?.(hashed / (total * contexts));
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }
    h.update(slice.subarray(0, left));
    hashed += left;
    out.set(h.digest(), c * algo.outputLength);
  }
  wipe(pattern, slice);
  onProgress?.(1);
  const key = out.slice(0, size);
  wipe(out);
  return key;
}
