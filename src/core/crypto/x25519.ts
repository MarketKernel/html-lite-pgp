// X25519, RFC 7748: the Montgomery ladder of TweetNaCl's crypto_scalarmult (public domain),
// over field25519.ts. 255 identical steps; the scalar's bits choose between two points only
// through masked swaps. OpenPGP's Cv25519 (RFC 6637 with the curve of draft-ietf-openpgp-
// rfc4880bis) is this function.

import { A24, add, fe, invert, mul, pack, select, square, sub, unpack } from './field25519.ts';

/** A scalar as X25519 uses it: the low three bits and the top bit cleared, bit 254 set. */
export function clamp(scalar: Uint8Array): Uint8Array {
  const z = new Uint8Array(scalar);
  z[31] = (z[31] & 127) | 64;
  z[0] &= 248;
  return z;
}

/**
 * scalar · u. Throws when the result is all zeros — a point of small order was given, and
 * the "shared secret" would be known to anyone (RFC 7748 §6.1).
 */
export function x25519(scalar: Uint8Array, u: Uint8Array): Uint8Array {
  if (scalar.length !== 32 || u.length !== 32) throw new RangeError('x25519: 32-byte inputs');
  const z = clamp(scalar);
  const x = fe();
  unpack(x, u);
  const a = fe([1]);
  const b = fe(x);
  const c = fe();
  const d = fe([1]);
  const e = fe();
  const f = fe();
  for (let i = 254; i >= 0; --i) {
    const r = (z[i >>> 3] >>> (i & 7)) & 1;
    select(a, b, r);
    select(c, d, r);
    add(e, a, c);
    sub(a, a, c);
    add(c, b, d);
    sub(b, b, d);
    square(d, e);
    square(f, a);
    mul(a, c, a);
    mul(c, b, e);
    add(e, a, c);
    sub(a, a, c);
    square(b, a);
    sub(c, d, f);
    mul(a, c, A24);
    add(a, a, d);
    mul(c, c, a);
    mul(a, d, f);
    mul(d, b, x);
    square(b, e);
    select(a, b, r);
    select(c, d, r);
  }
  invert(c, c);
  mul(a, a, c);
  const out = new Uint8Array(32);
  pack(out, a);
  z.fill(0);
  for (const t of [a, b, c, d, e, f, x]) t.fill(0);
  let any = 0;
  for (let i = 0; i < 32; i++) any |= out[i];
  if (any === 0) throw new Error('x25519: the result is zero (a point of small order)');
  return out;
}

const NINE = (() => {
  const u = new Uint8Array(32);
  u[0] = 9;
  return u;
})();

/** The public key of a secret: scalar · 9. */
export const x25519Base = (scalar: Uint8Array): Uint8Array => x25519(scalar, NINE);
