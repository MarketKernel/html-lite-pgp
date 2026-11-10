// SHA-1, FIPS 180-4 §6.1. Only where OpenPGP v4 requires it: the key fingerprint, the MDC
// packet and the checksum of a protected secret key. Never for signatures: those are refused.

import { BlockHash, be32, digest, wordsToBytes } from './hash.ts';
import type { HashAlgorithm } from './hash.ts';

class Sha1 extends BlockHash {
  private readonly h = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
  private readonly w = new Uint32Array(80);

  constructor() {
    super(64, 8);
  }

  protected compress(block: Uint8Array, offset: number): void {
    const w = this.w;
    for (let t = 0; t < 16; t++) w[t] = be32(block, offset + t * 4);
    for (let t = 16; t < 80; t++) {
      const x = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
      w[t] = (x << 1) | (x >>> 31);
    }
    let [a, b, c, d, e] = this.h;
    for (let t = 0; t < 80; t++) {
      let f: number;
      let k: number;
      if (t < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (t < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (t < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }
      const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[t]) | 0;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = temp;
    }
    const h = this.h;
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
  }

  protected output(): Uint8Array {
    const out = wordsToBytes(this.h);
    this.h.fill(0);
    this.w.fill(0);
    return out;
  }
}

export const SHA1: HashAlgorithm = { name: 'SHA1', blockLength: 64, outputLength: 20, create: () => new Sha1() };

export const sha1 = (...parts: Uint8Array[]): Uint8Array => digest(SHA1, ...parts);
