// PBKDF2, RFC 8018 §5.2, with HMAC. Here only inside scrypt, which runs it with one iteration.

import type { HashAlgorithm } from './hash.ts';
import { hmac } from './hmac.ts';

export function pbkdf2(algorithm: HashAlgorithm, password: Uint8Array, salt: Uint8Array, iterations: number, length: number): Uint8Array {
  if (iterations < 1 || length < 1) throw new RangeError('pbkdf2: bad parameters');
  const hLen = algorithm.outputLength;
  const out = new Uint8Array(length);
  const index = new Uint8Array(4);
  for (let block = 1, at = 0; at < length; block++, at += hLen) {
    index[0] = block >>> 24;
    index[1] = block >>> 16;
    index[2] = block >>> 8;
    index[3] = block;
    let u = hmac(algorithm, password, salt, index);
    const t = u.slice();
    for (let i = 1; i < iterations; i++) {
      u = hmac(algorithm, password, u);
      for (let j = 0; j < hLen; j++) t[j] ^= u[j];
    }
    out.set(t.subarray(0, Math.min(hLen, length - at)), at);
  }
  return out;
}
