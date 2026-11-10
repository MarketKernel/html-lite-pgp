// SHA-512, FIPS 180-4 §6.4: for Ed25519 and our signatures. JavaScript has no 64-bit integers
// without big integers (not constant-time, and banned here), so every word is a pair of 32-bit
// halves, high and low, kept in two Uint32Arrays. The constants are the first 64 bits of the
// fractional parts of the cube roots (K) and square roots (H) of the first primes;
// tests/hash.test.ts computes them again and compares.

import { BlockHash, be32, digest } from './hash.ts';
import type { HashAlgorithm } from './hash.ts';

// Each constant as its high and low halves.
export const SHA512_K = new Uint32Array([
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
  0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
  0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
  0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
  0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
  0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
  0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
  0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
  0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
  0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
  0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
  0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
]);

export const SHA512_H = new Uint32Array([
  0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
  0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
]);

class Sha512 extends BlockHash {
  // State and schedule as [high, low] pairs: h[2i] is word i's high half, h[2i+1] its low half.
  private readonly h = new Uint32Array(SHA512_H);
  private readonly w = new Uint32Array(160);

  constructor() {
    super(128, 16);
  }

  protected compress(block: Uint8Array, offset: number): void {
    const w = this.w;
    const K = SHA512_K;
    for (let i = 0; i < 32; i++) w[i] = be32(block, offset + i * 4);
    for (let t = 16; t < 80; t++) {
      // σ0 = rotr1 ^ rotr8 ^ shr7 of w[t-15]
      let xh = w[(t - 15) * 2];
      let xl = w[(t - 15) * 2 + 1];
      const s0h = ((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7);
      const s0l = ((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25));
      // σ1 = rotr19 ^ rotr61 ^ shr6 of w[t-2]
      xh = w[(t - 2) * 2];
      xl = w[(t - 2) * 2 + 1];
      const s1h = ((xh >>> 19) | (xl << 13)) ^ ((xl >>> 29) | (xh << 3)) ^ (xh >>> 6);
      const s1l = ((xl >>> 19) | (xh << 13)) ^ ((xh >>> 29) | (xl << 3)) ^ ((xl >>> 6) | (xh << 26));
      const lo = (s0l >>> 0) + (s1l >>> 0) + w[(t - 7) * 2 + 1] + w[(t - 16) * 2 + 1];
      const hi = (s0h >>> 0) + (s1h >>> 0) + w[(t - 7) * 2] + w[(t - 16) * 2] + ((lo / 0x100000000) >>> 0);
      w[t * 2] = hi;
      w[t * 2 + 1] = lo;
    }
    const H = this.h;
    let ah = H[0], al = H[1], bh = H[2], bl = H[3], ch = H[4], cl = H[5], dh = H[6], dl = H[7];
    let eh = H[8], el = H[9], fh = H[10], fl = H[11], gh = H[12], gl = H[13], hh = H[14], hl = H[15];
    for (let t = 0; t < 80; t++) {
      // Σ1(e) = rotr14 ^ rotr18 ^ rotr41
      const S1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23));
      const S1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23));
      const chh = (eh & fh) ^ (~eh & gh);
      const chl = (el & fl) ^ (~el & gl);
      let lo = (hl >>> 0) + (S1l >>> 0) + (chl >>> 0) + K[t * 2 + 1] + w[t * 2 + 1];
      const t1h = (hh >>> 0) + (S1h >>> 0) + (chh >>> 0) + K[t * 2] + w[t * 2] + ((lo / 0x100000000) >>> 0);
      const t1l = lo >>> 0;
      // Σ0(a) = rotr28 ^ rotr34 ^ rotr39
      const S0h = ((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25));
      const S0l = ((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25));
      const majh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
      const majl = (al & bl) ^ (al & cl) ^ (bl & cl);
      hh = gh;
      hl = gl;
      gh = fh;
      gl = fl;
      fh = eh;
      fl = el;
      lo = (dl >>> 0) + t1l;
      eh = ((dh >>> 0) + t1h + ((lo / 0x100000000) >>> 0)) | 0;
      el = lo | 0;
      dh = ch;
      dl = cl;
      ch = bh;
      cl = bl;
      bh = ah;
      bl = al;
      lo = t1l + (S0l >>> 0) + (majl >>> 0);
      ah = (t1h + (S0h >>> 0) + (majh >>> 0) + ((lo / 0x100000000) >>> 0)) | 0;
      al = lo | 0;
    }
    const add = (i: number, h: number, l: number) => {
      const lo = H[i * 2 + 1] + (l >>> 0);
      H[i * 2] = H[i * 2] + (h >>> 0) + ((lo / 0x100000000) >>> 0);
      H[i * 2 + 1] = lo;
    };
    add(0, ah, al);
    add(1, bh, bl);
    add(2, ch, cl);
    add(3, dh, dl);
    add(4, eh, el);
    add(5, fh, fl);
    add(6, gh, gl);
    add(7, hh, hl);
  }

  protected output(): Uint8Array {
    const out = new Uint8Array(64);
    for (let i = 0; i < 16; i++) {
      const v = this.h[i];
      out[i * 4] = v >>> 24;
      out[i * 4 + 1] = v >>> 16;
      out[i * 4 + 2] = v >>> 8;
      out[i * 4 + 3] = v;
    }
    this.h.fill(0);
    this.w.fill(0);
    return out;
  }
}

export const SHA512: HashAlgorithm = { name: 'SHA512', blockLength: 128, outputLength: 64, create: () => new Sha512() };

export const sha512 = (...parts: Uint8Array[]): Uint8Array => digest(SHA512, ...parts);
