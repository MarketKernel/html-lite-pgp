// Arithmetic in GF(2^255 - 19), after TweetNaCl (Bernstein, van Gastel, Janssen, Lange,
// Schwabe, Smetsers; public domain) and its JavaScript port tweetnacl-js (Dmitry Chestnykh,
// public domain), which Cure53 audited in 2017.
//
// An element is 16 limbs of 16 bits in a Float64Array. Every operation does the same work
// whatever the values: no branch and no index depends on them. Products stay below 2^53, so
// doubles are exact (TweetNaCl's own analysis). The constants of Edwards25519 are not typed
// in: they are computed here from their definitions, and tests/curve25519.test.ts checks them.

export type Fe = Float64Array;

export const fe = (init?: ArrayLike<number>): Fe => {
  const r = new Float64Array(16);
  if (init) for (let i = 0; i < init.length; i++) r[i] = init[i];
  return r;
};

export function set(r: Fe, a: Fe): void {
  for (let i = 0; i < 16; i++) r[i] = a[i] | 0;
}

/** Carries each limb into the next; the top carry wraps around times 38 (2^256 = 38 mod p). */
export function carry(o: Fe): void {
  let c = 1;
  for (let i = 0; i < 16; i++) {
    const v = o[i] + c + 65535;
    c = Math.floor(v / 65536);
    o[i] = v - c * 65536;
  }
  o[0] += c - 1 + 37 * (c - 1);
}

/** Swaps p and q when b is 1, leaves them when b is 0 — by masks, not by a branch. */
export function select(p: Fe, q: Fe, b: number): void {
  const c = ~(b - 1);
  for (let i = 0; i < 16; i++) {
    const t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

/** The canonical 32 little-endian bytes (fully reduced mod p). */
export function pack(o: Uint8Array, n: Fe): void {
  const m = fe();
  const t = fe();
  for (let i = 0; i < 16; i++) t[i] = n[i];
  carry(t);
  carry(t);
  carry(t);
  for (let j = 0; j < 2; j++) {
    m[0] = t[0] - 0xffed;
    for (let i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    const b = (m[15] >> 16) & 1;
    m[14] &= 0xffff;
    select(t, m, 1 - b);
  }
  for (let i = 0; i < 16; i++) {
    o[2 * i] = t[i] & 0xff;
    o[2 * i + 1] = t[i] >> 8;
  }
}

/** Reads 32 little-endian bytes, dropping the top bit. */
export function unpack(o: Fe, n: Uint8Array): void {
  for (let i = 0; i < 16; i++) o[i] = n[2 * i] + (n[2 * i + 1] << 8);
  o[15] &= 0x7fff;
}

export function add(o: Fe, a: Fe, b: Fe): void {
  for (let i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

export function sub(o: Fe, a: Fe, b: Fe): void {
  for (let i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

export function mul(o: Fe, a: Fe, b: Fe): void {
  const t = new Float64Array(31);
  for (let i = 0; i < 16; i++) for (let j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
  for (let i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
  for (let i = 0; i < 16; i++) o[i] = t[i];
  carry(o);
  carry(o);
}

export const square = (o: Fe, a: Fe): void => mul(o, a, a);

/** a^(p-2) = 1/a (0 for 0), by a fixed chain of squarings and multiplications. */
export function invert(o: Fe, i: Fe): void {
  const c = fe(i);
  for (let a = 253; a >= 0; a--) {
    square(c, c);
    if (a !== 2 && a !== 4) mul(c, c, i);
  }
  set(o, c);
}

/** a^((p-5)/8), for square roots. */
export function pow2523(o: Fe, i: Fe): void {
  const c = fe(i);
  for (let a = 250; a >= 0; a--) {
    square(c, c);
    if (a !== 1) mul(c, c, i);
  }
  set(o, c);
}

/** a to a public exponent given as little-endian bytes. Only for computing constants. */
function power(base: Fe, exponent: Uint8Array): Fe {
  const r = fe([1]);
  for (let bit = exponent.length * 8 - 1; bit >= 0; bit--) {
    square(r, r);
    if ((exponent[bit >> 3] >> (bit & 7)) & 1) mul(r, r, base);
  }
  return r;
}

/** Equal elements, compared on their canonical bytes in constant time. */
export function equal(a: Fe, b: Fe): boolean {
  const c = new Uint8Array(32);
  const d = new Uint8Array(32);
  pack(c, a);
  pack(d, b);
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= c[i] ^ d[i];
  return diff === 0;
}

/** The low bit of the canonical form: the "sign" of x in Ed25519's encoding. */
export function parity(a: Fe): number {
  const d = new Uint8Array(32);
  pack(d, a);
  return d[0] & 1;
}

export const ZERO = fe();
export const ONE = fe([1]);
/** 121665 = (486662 - 2) / 4, the constant of the Montgomery ladder. */
export const A24 = fe([0xdb41, 1]);

/** d = -121665 / 121666, Edwards25519's curve constant. */
export const D = (() => {
  const d = fe();
  const den = fe([0xdb42, 1]);
  invert(den, den);
  sub(d, ZERO, A24);
  mul(d, d, den);
  return d;
})();

export const D2 = (() => {
  const d2 = fe();
  add(d2, D, D);
  carry(d2);
  return d2;
})();

/** √-1 = 2^((p-1)/4) = 2^(2^253 - 5). */
export const SQRT_M1 = (() => {
  const exponent = new Uint8Array(32).fill(0xff);
  exponent[0] = 0xfb;
  exponent[31] = 0x1f;
  return power(fe([2]), exponent);
})();
