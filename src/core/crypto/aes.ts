// AES-128 and AES-256, FIPS 197, in constant time.
//
// Bitsliced after BearSSL's aes_ct (Thomas Pornin, MIT license, https://bearssl.org): two
// blocks are spread over eight 32-bit words so that word i holds bit i of every byte, and
// SubBytes is the Boyar–Peralta circuit of 113 logic gates on those words. There is no S-box
// table: a table lookup indexed by key-dependent bytes leaks the key through the cache.
// ShiftRows and MixColumns are bit shuffles of the same words. The differences from aes_ct:
// the round keys stay in their expanded form (no compression), InvMixColumns is MixColumns
// three times (MixColumns has order 4), and the inverse S-box is the forward circuit between
// two inverse affine maps — all slower than BearSSL's, and simpler to check. Decryption is
// only needed by AES Key Wrap, on a few blocks.

/** The Boyar–Peralta S-box circuit on bitsliced words: q[7] is the most significant bit. */
function sbox(q: Uint32Array): void {
  const x0 = q[7], x1 = q[6], x2 = q[5], x3 = q[4], x4 = q[3], x5 = q[2], x6 = q[1], x7 = q[0];

  // Top linear transformation.
  const y14 = x3 ^ x5;
  const y13 = x0 ^ x6;
  const y9 = x0 ^ x3;
  const y8 = x0 ^ x5;
  const t0 = x1 ^ x2;
  const y1 = t0 ^ x7;
  const y4 = y1 ^ x3;
  const y12 = y13 ^ y14;
  const y2 = y1 ^ x0;
  const y5 = y1 ^ x6;
  const y3 = y5 ^ y8;
  const t1 = x4 ^ y12;
  const y15 = t1 ^ x5;
  const y20 = t1 ^ x1;
  const y6 = y15 ^ x7;
  const y10 = y15 ^ t0;
  const y11 = y20 ^ y9;
  const y7 = x7 ^ y11;
  const y17 = y10 ^ y11;
  const y19 = y10 ^ y8;
  const y16 = t0 ^ y11;
  const y21 = y13 ^ y16;
  const y18 = x0 ^ y16;

  // Non-linear section.
  const t2 = y12 & y15;
  const t3 = y3 & y6;
  const t4 = t3 ^ t2;
  const t5 = y4 & x7;
  const t6 = t5 ^ t2;
  const t7 = y13 & y16;
  const t8 = y5 & y1;
  const t9 = t8 ^ t7;
  const t10 = y2 & y7;
  const t11 = t10 ^ t7;
  const t12 = y9 & y11;
  const t13 = y14 & y17;
  const t14 = t13 ^ t12;
  const t15 = y8 & y10;
  const t16 = t15 ^ t12;
  const t17 = t4 ^ t14;
  const t18 = t6 ^ t16;
  const t19 = t9 ^ t14;
  const t20 = t11 ^ t16;
  const t21 = t17 ^ y20;
  const t22 = t18 ^ y19;
  const t23 = t19 ^ y21;
  const t24 = t20 ^ y18;

  const t25 = t21 ^ t22;
  const t26 = t21 & t23;
  const t27 = t24 ^ t26;
  const t28 = t25 & t27;
  const t29 = t28 ^ t22;
  const t30 = t23 ^ t24;
  const t31 = t22 ^ t26;
  const t32 = t31 & t30;
  const t33 = t32 ^ t24;
  const t34 = t23 ^ t33;
  const t35 = t27 ^ t33;
  const t36 = t24 & t35;
  const t37 = t36 ^ t34;
  const t38 = t27 ^ t36;
  const t39 = t29 & t38;
  const t40 = t25 ^ t39;

  const t41 = t40 ^ t37;
  const t42 = t29 ^ t33;
  const t43 = t29 ^ t40;
  const t44 = t33 ^ t37;
  const t45 = t42 ^ t41;
  const z0 = t44 & y15;
  const z1 = t37 & y6;
  const z2 = t33 & x7;
  const z3 = t43 & y16;
  const z4 = t40 & y1;
  const z5 = t29 & y7;
  const z6 = t42 & y11;
  const z7 = t45 & y17;
  const z8 = t41 & y10;
  const z9 = t44 & y12;
  const z10 = t37 & y3;
  const z11 = t33 & y4;
  const z12 = t43 & y13;
  const z13 = t40 & y5;
  const z14 = t29 & y2;
  const z15 = t42 & y9;
  const z16 = t45 & y14;
  const z17 = t41 & y8;

  // Bottom linear transformation.
  const t46 = z15 ^ z16;
  const t47 = z10 ^ z11;
  const t48 = z5 ^ z13;
  const t49 = z9 ^ z10;
  const t50 = z2 ^ z12;
  const t51 = z2 ^ z5;
  const t52 = z7 ^ z8;
  const t53 = z0 ^ z3;
  const t54 = z6 ^ z7;
  const t55 = z16 ^ z17;
  const t56 = z12 ^ t48;
  const t57 = t50 ^ t53;
  const t58 = z4 ^ t46;
  const t59 = z3 ^ t54;
  const t60 = t46 ^ t57;
  const t61 = z14 ^ t57;
  const t62 = t52 ^ t58;
  const t63 = t49 ^ t58;
  const t64 = z4 ^ t59;
  const t65 = t61 ^ t62;
  const t66 = z1 ^ t63;
  const s0 = t59 ^ t63;
  const s6 = t56 ^ ~t62;
  const s7 = t48 ^ ~t60;
  const t67 = t64 ^ t65;
  const s3 = t53 ^ t66;
  const s4 = t51 ^ t66;
  const s5 = t47 ^ t65;
  const s1 = t64 ^ ~s3;
  const s2 = t55 ^ ~t67;

  q[7] = s0;
  q[6] = s1;
  q[5] = s2;
  q[4] = s3;
  q[3] = s4;
  q[2] = s5;
  q[1] = s6;
  q[0] = s7;
}

/**
 * The inverse affine map of the S-box, x ↦ M⁻¹·(x ⊕ 0x63): bit i of the result is bits
 * i+2, i+5 and i+7 of the input, then 0x05 added (M⁻¹·0x63 = 0x05).
 */
function inverseAffine(q: Uint32Array): void {
  const a = Array.from(q);
  for (let i = 0; i < 8; i++) q[i] = a[(i + 2) & 7] ^ a[(i + 5) & 7] ^ a[(i + 7) & 7];
  q[0] = ~q[0];
  q[2] = ~q[2];
}

/** S⁻¹ = A⁻¹ ∘ S ∘ A⁻¹: inversion in GF(2⁸) is its own inverse, and S = A ∘ inverse. */
function invSbox(q: Uint32Array): void {
  inverseAffine(q);
  sbox(q);
  inverseAffine(q);
}

/** BearSSL's ortho: the transposition between plain words and bit planes, its own inverse. */
function ortho(q: Uint32Array, at = 0): void {
  const swap = (cl: number, ch: number, s: number, i: number, j: number) => {
    const a = q[at + i];
    const b = q[at + j];
    q[at + i] = (a & cl) | ((b & cl) << s);
    q[at + j] = ((a & ch) >>> s) | (b & ch);
  };
  swap(0x55555555, 0xaaaaaaaa, 1, 0, 1);
  swap(0x55555555, 0xaaaaaaaa, 1, 2, 3);
  swap(0x55555555, 0xaaaaaaaa, 1, 4, 5);
  swap(0x55555555, 0xaaaaaaaa, 1, 6, 7);
  swap(0x33333333, 0xcccccccc, 2, 0, 2);
  swap(0x33333333, 0xcccccccc, 2, 1, 3);
  swap(0x33333333, 0xcccccccc, 2, 4, 6);
  swap(0x33333333, 0xcccccccc, 2, 5, 7);
  swap(0x0f0f0f0f, 0xf0f0f0f0, 4, 0, 4);
  swap(0x0f0f0f0f, 0xf0f0f0f0, 4, 1, 5);
  swap(0x0f0f0f0f, 0xf0f0f0f0, 4, 2, 6);
  swap(0x0f0f0f0f, 0xf0f0f0f0, 4, 3, 7);
}

function shiftRows(q: Uint32Array): void {
  for (let i = 0; i < 8; i++) {
    const x = q[i];
    q[i] =
      (x & 0x000000ff) |
      ((x & 0x0000fc00) >>> 2) | ((x & 0x00000300) << 6) |
      ((x & 0x00f00000) >>> 4) | ((x & 0x000f0000) << 4) |
      ((x & 0xc0000000) >>> 6) | ((x & 0x3f000000) << 2);
  }
}

function invShiftRows(q: Uint32Array): void {
  for (let i = 0; i < 8; i++) {
    const x = q[i];
    q[i] =
      (x & 0x000000ff) |
      ((x & 0x00003f00) << 2) | ((x & 0x0000c000) >>> 6) |
      ((x & 0x000f0000) << 4) | ((x & 0x00f00000) >>> 4) |
      ((x & 0x03000000) << 6) | ((x & 0xfc000000) >>> 2);
  }
}

const rotr16 = (x: number): number => (x << 16) | (x >>> 16);

function mixColumns(q: Uint32Array): void {
  const q0 = q[0], q1 = q[1], q2 = q[2], q3 = q[3], q4 = q[4], q5 = q[5], q6 = q[6], q7 = q[7];
  const r0 = (q0 >>> 8) | (q0 << 24);
  const r1 = (q1 >>> 8) | (q1 << 24);
  const r2 = (q2 >>> 8) | (q2 << 24);
  const r3 = (q3 >>> 8) | (q3 << 24);
  const r4 = (q4 >>> 8) | (q4 << 24);
  const r5 = (q5 >>> 8) | (q5 << 24);
  const r6 = (q6 >>> 8) | (q6 << 24);
  const r7 = (q7 >>> 8) | (q7 << 24);
  q[0] = q7 ^ r7 ^ r0 ^ rotr16(q0 ^ r0);
  q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr16(q1 ^ r1);
  q[2] = q1 ^ r1 ^ r2 ^ rotr16(q2 ^ r2);
  q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr16(q3 ^ r3);
  q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr16(q4 ^ r4);
  q[5] = q4 ^ r4 ^ r5 ^ rotr16(q5 ^ r5);
  q[6] = q5 ^ r5 ^ r6 ^ rotr16(q6 ^ r6);
  q[7] = q6 ^ r6 ^ r7 ^ rotr16(q7 ^ r7);
}

function invMixColumns(q: Uint32Array): void {
  mixColumns(q);
  mixColumns(q);
  mixColumns(q);
}

function addRoundKey(q: Uint32Array, keys: Uint32Array, at: number): void {
  for (let i = 0; i < 8; i++) q[i] ^= keys[at + i];
}

/** SubWord of the key schedule, through the same circuit. */
function subWord(x: number): number {
  const q = new Uint32Array(8);
  q[0] = x;
  ortho(q);
  sbox(q);
  ortho(q);
  return q[0];
}

const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

const le32 = (b: Uint8Array, at: number): number => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;

function put32(b: Uint8Array, at: number, v: number): void {
  b[at] = v;
  b[at + 1] = v >>> 8;
  b[at + 2] = v >>> 16;
  b[at + 3] = v >>> 24;
}

export class Aes {
  private readonly rounds: number;
  /** Round keys, each as eight bit-plane words for two blocks. */
  private readonly keys: Uint32Array;
  private readonly q = new Uint32Array(8);

  constructor(key: Uint8Array) {
    if (key.length !== 16 && key.length !== 32) throw new RangeError('AES: the key is 16 or 32 bytes');
    const nk = key.length / 4;
    this.rounds = nk + 6;
    const words = (this.rounds + 1) * 4;
    const keys = new Uint32Array(words * 2);
    let tmp = 0;
    for (let i = 0; i < nk; i++) {
      tmp = le32(key, i * 4);
      keys[i * 2] = keys[i * 2 + 1] = tmp;
    }
    for (let i = nk, j = 0, k = 0; i < words; i++) {
      if (j === 0) tmp = subWord((tmp << 24) | (tmp >>> 8)) ^ RCON[k];
      else if (nk > 6 && j === 4) tmp = subWord(tmp);
      tmp ^= keys[(i - nk) * 2];
      keys[i * 2] = keys[i * 2 + 1] = tmp;
      if (++j === nk) {
        j = 0;
        k++;
      }
    }
    for (let i = 0; i < words * 2; i += 8) ortho(keys, i);
    this.keys = keys;
  }

  private load(a: Uint8Array, aAt: number, b: Uint8Array | null, bAt: number): void {
    const q = this.q;
    for (let i = 0; i < 4; i++) {
      q[i * 2] = le32(a, aAt + i * 4);
      q[i * 2 + 1] = b ? le32(b, bAt + i * 4) : 0;
    }
    ortho(q);
  }

  private store(a: Uint8Array, aAt: number, b: Uint8Array | null, bAt: number): void {
    const q = this.q;
    ortho(q);
    for (let i = 0; i < 4; i++) {
      put32(a, aAt + i * 4, q[i * 2]);
      if (b) put32(b, bAt + i * 4, q[i * 2 + 1]);
    }
    q.fill(0);
  }

  private forward(): void {
    const q = this.q;
    addRoundKey(q, this.keys, 0);
    for (let u = 1; u < this.rounds; u++) {
      sbox(q);
      shiftRows(q);
      mixColumns(q);
      addRoundKey(q, this.keys, u * 8);
    }
    sbox(q);
    shiftRows(q);
    addRoundKey(q, this.keys, this.rounds * 8);
  }

  private inverse(): void {
    const q = this.q;
    addRoundKey(q, this.keys, this.rounds * 8);
    for (let u = this.rounds - 1; u > 0; u--) {
      invShiftRows(q);
      invSbox(q);
      addRoundKey(q, this.keys, u * 8);
      invMixColumns(q);
    }
    invShiftRows(q);
    invSbox(q);
    addRoundKey(q, this.keys, 0);
  }

  /** Encrypts the 16 bytes at `input[inAt]` into `output[outAt]` (they may overlap exactly). */
  encryptBlock(input: Uint8Array, inAt: number, output: Uint8Array, outAt: number): void {
    this.load(input, inAt, null, 0);
    this.forward();
    this.store(output, outAt, null, 0);
  }

  /** Two blocks at once, at the cost of one: for CFB decryption, where the inputs are known ahead. */
  encryptTwo(input: Uint8Array, aAt: number, bAt: number, output: Uint8Array, outA: number, outB: number): void {
    this.load(input, aAt, input, bAt);
    this.forward();
    this.store(output, outA, output, outB);
  }

  decryptBlock(input: Uint8Array, inAt: number, output: Uint8Array, outAt: number): void {
    this.load(input, inAt, null, 0);
    this.inverse();
    this.store(output, outAt, null, 0);
  }

  destroy(): void {
    this.keys.fill(0);
    this.q.fill(0);
  }
}
