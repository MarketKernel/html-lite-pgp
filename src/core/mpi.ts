// Multiprecision integers, RFC 4880 §3.2: a 16-bit count of bits, then the bytes, big-endian,
// with no leading zero bytes. Curve25519 keys and signatures are MPIs in OpenPGP v4, and this
// is where implementations go wrong: a 32-byte value whose first byte is zero comes out as 31
// bytes, and must be padded back before use (fixed()).

import { Reader, Writer } from './bytes.ts';
import { malformed } from './errors.ts';

/**
 * Reads an MPI. Its bit count gives the byte length; the value may not be longer than the
 * count says. It may be shorter: GnuPG stores an Ed25519 secret as an "opaque" MPI whose
 * count is always 256, whatever its first bits.
 */
export function readMpi(r: Reader): Uint8Array {
  const bits = r.u16('an MPI');
  const value = r.bytes((bits + 7) >> 3, 'an MPI');
  if (bits > 0 && value[0] >> (((bits - 1) % 8) + 1) !== 0) throw malformed('an MPI longer than its bit count');
  return value;
}

export function writeMpi(w: Writer, value: Uint8Array): Writer {
  let start = 0;
  while (start < value.length && value[start] === 0) start++;
  const v = value.subarray(start);
  const bits = v.length === 0 ? 0 : (v.length - 1) * 8 + (32 - Math.clz32(v[0]));
  return w.u16(bits).bytes(v);
}

/** The MPI's value as exactly `size` bytes, padded with zeros on the left; longer is an error. */
export function fixed(value: Uint8Array, size: number, what: string): Uint8Array {
  if (value.length > size) throw malformed(`${what} is longer than ${size} bytes`);
  const out = new Uint8Array(size);
  out.set(value, size - value.length);
  return out;
}
