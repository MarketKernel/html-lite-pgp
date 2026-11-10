// Ed25519, RFC 8032 (PureEdDSA): TweetNaCl's crypto_sign and crypto_sign_open (public
// domain) over field25519.ts, with what TweetNaCl leaves out added from RFC 8032 §5.1.3 and
// §5.1.7: a point's y must be below p, x = 0 must not carry the sign bit, and S must be below
// L. Without those, one signature could be turned into another valid one.
//
// Signing does the same work whatever the secret: the scalar multiplication goes through all
// 256 bits with masked swaps. Verifying works on public data only.

import { D, D2, ONE, SQRT_M1, ZERO, add as fadd, equal, fe, invert, mul, pack as fpack, parity, pow2523, select, set, square, sub, unpack } from './field25519.ts';
import type { Fe } from './field25519.ts';
import { sha512 } from './sha512.ts';

/** A point in extended coordinates (X : Y : Z : T), x = X/Z, y = Y/Z, xy = T/Z. */
type Point = [Fe, Fe, Fe, Fe];

const point = (): Point => [fe(), fe(), fe(), fe()];

/** p += q, the unified addition of twisted Edwards curves with a = -1 (complete). */
function add(p: Point, q: Point): void {
  const a = fe(), b = fe(), c = fe(), d = fe(), e = fe(), f = fe(), g = fe(), h = fe(), t = fe();
  sub(a, p[1], p[0]);
  sub(t, q[1], q[0]);
  mul(a, a, t);
  fadd(b, p[0], p[1]);
  fadd(t, q[0], q[1]);
  mul(b, b, t);
  mul(c, p[3], q[3]);
  mul(c, c, D2);
  mul(d, p[2], q[2]);
  fadd(d, d, d);
  sub(e, b, a);
  sub(f, d, c);
  fadd(g, d, c);
  fadd(h, b, a);
  mul(p[0], e, f);
  mul(p[1], h, g);
  mul(p[2], g, f);
  mul(p[3], e, h);
}

function swap(p: Point, q: Point, b: number): void {
  for (let i = 0; i < 4; i++) select(p[i], q[i], b);
}

function encode(r: Uint8Array, p: Point): void {
  const tx = fe(), ty = fe(), zi = fe();
  invert(zi, p[2]);
  mul(tx, p[0], zi);
  mul(ty, p[1], zi);
  fpack(r, ty);
  r[31] ^= parity(tx) << 7;
}

/** p = s · q over all 256 bits of s, in constant time. */
function scalarMult(p: Point, q: Point, s: Uint8Array): void {
  set(p[0], ZERO);
  set(p[1], ONE);
  set(p[2], ONE);
  set(p[3], ZERO);
  for (let i = 255; i >= 0; --i) {
    const b = (s[(i / 8) | 0] >> (i & 7)) & 1;
    swap(p, q, b);
    add(q, p);
    add(p, p);
    swap(p, q, b);
  }
}

/**
 * The point encoded in `s`, RFC 8032 §5.1.3, or null. With `negate`, the opposite point —
 * verification needs −A.
 */
function decode(s: Uint8Array, negate = false): Point | null {
  if (s.length !== 32) return null;
  const r = point();
  const t = fe(), chk = fe(), num = fe(), den = fe(), den2 = fe(), den4 = fe(), den6 = fe();
  set(r[2], ONE);
  unpack(r[1], s);
  // y must be canonical: below p.
  const again = new Uint8Array(32);
  fpack(again, r[1]);
  for (let i = 0; i < 31; i++) if (again[i] !== s[i]) return null;
  if (again[31] !== (s[31] & 0x7f)) return null;
  // x² = (y² − 1) / (d·y² + 1)
  square(num, r[1]);
  mul(den, num, D);
  sub(num, num, r[2]);
  fadd(den, r[2], den);
  square(den2, den);
  square(den4, den2);
  mul(den6, den4, den2);
  mul(t, den6, num);
  mul(t, t, den);
  pow2523(t, t);
  mul(t, t, num);
  mul(t, t, den);
  mul(t, t, den);
  mul(r[0], t, den);
  square(chk, r[0]);
  mul(chk, chk, den);
  if (!equal(chk, num)) mul(r[0], r[0], SQRT_M1);
  square(chk, r[0]);
  mul(chk, chk, den);
  if (!equal(chk, num)) return null;
  const sign = s[31] >> 7;
  if (sign === 1 && equal(r[0], ZERO)) return null;
  // Choose the root whose parity is the sign bit — or the other one, for −A.
  if ((parity(r[0]) === sign) === negate) sub(r[0], ZERO, r[0]);
  mul(r[3], r[0], r[1]);
  return r;
}

/** The base point B: y = 4/5, x positive — computed, not typed in. */
const BASE_ENCODED = new Uint8Array(32).fill(0x66);
BASE_ENCODED[0] = 0x58;
const BASE = decode(BASE_ENCODED)!;

function base(p: Point, s: Uint8Array): void {
  const q = point();
  for (let i = 0; i < 4; i++) set(q[i], BASE[i]);
  scalarMult(p, q, s);
}

/** L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
const L = new Float64Array([
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
]);

/** r = x mod L, x given as 64 limbs of bytes (TweetNaCl's modL). */
function modL(r: Uint8Array, x: Float64Array): void {
  let carry: number;
  for (let i = 63; i >= 32; --i) {
    carry = 0;
    let j: number;
    const k = i - 12;
    for (j = i - 32; j < k; ++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = Math.floor((x[j] + 128) / 256);
      x[j] -= carry * 256;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  for (let j = 0; j < 32; j++) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  for (let j = 0; j < 32; j++) x[j] -= carry * L[j];
  for (let i = 0; i < 32; i++) {
    x[i + 1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

/** A 64-byte hash reduced mod L. */
function reduce(h: Uint8Array): Uint8Array {
  const x = new Float64Array(64);
  for (let i = 0; i < 64; i++) x[i] = h[i];
  const r = new Uint8Array(32);
  modL(r, x);
  return r;
}

/** The secret scalar and the prefix, from the 32-byte seed (RFC 8032 §5.1.5). */
function expand(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new RangeError('ed25519: the seed is 32 bytes');
  const d = sha512(seed);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;
  return d;
}

export function ed25519PublicKey(seed: Uint8Array): Uint8Array {
  const d = expand(seed);
  const p = point();
  base(p, d);
  const pk = new Uint8Array(32);
  encode(pk, p);
  d.fill(0);
  return pk;
}

/** The 64-byte signature R ‖ S of `message` (RFC 8032 §5.1.6). */
export function ed25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array {
  const d = expand(seed);
  const publicKey = ed25519PublicKey(seed);
  const r = reduce(sha512(d.subarray(32), message));
  const p = point();
  base(p, r);
  const sig = new Uint8Array(64);
  encode(sig, p);
  const h = reduce(sha512(sig.subarray(0, 32), publicKey, message));
  const x = new Float64Array(64);
  for (let i = 0; i < 32; i++) x[i] = r[i];
  for (let i = 0; i < 32; i++) for (let j = 0; j < 32; j++) x[i + j] += h[i] * d[j];
  const s = new Uint8Array(32);
  modL(s, x);
  sig.set(s, 32);
  d.fill(0);
  r.fill(0);
  x.fill(0);
  return sig;
}

/** S < L, compared from the most significant byte (public data). */
function belowL(s: Uint8Array): boolean {
  for (let i = 31; i >= 0; i--) {
    if (s[i] < L[i]) return true;
    if (s[i] > L[i]) return false;
  }
  return false;
}

/** RFC 8032 §5.1.7: [S]B = R + [k]A, checked as R = [S]B − [k]A. */
export function ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  const s = signature.subarray(32);
  if (!belowL(s)) return false;
  const negA = decode(publicKey, true);
  if (!negA) return false;
  if (!decode(signature.subarray(0, 32))) return false;
  const k = reduce(sha512(signature.subarray(0, 32), publicKey, message));
  const p = point();
  const q = point();
  scalarMult(p, negA, k);
  base(q, s);
  add(p, q);
  const t = new Uint8Array(32);
  encode(t, p);
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= t[i] ^ signature[i];
  return diff === 0;
}
