// HMAC_DRBG with SHA-512, NIST SP 800-90A Rev. 1 §10.1.2, without prediction resistance: the
// generator every random byte of the program passes through. It is seeded from one source —
// the system generator or the mouse, as the user chose (Task.md §4) — and never from both.

import { hmac } from './hmac.ts';
import { SHA512 } from './sha512.ts';
import { concat, wipe } from './util.ts';

const OUT = 64;
const RESEED_INTERVAL = 2 ** 32;

export class HmacDrbg {
  private K = new Uint8Array(OUT);
  private V = new Uint8Array(OUT).fill(1);
  private counter = 0;

  /** Instantiate (§10.1.2.3) from at least 256 bits of entropy. */
  constructor(entropy: Uint8Array, nonce: Uint8Array = new Uint8Array(0), personalization: Uint8Array = new Uint8Array(0)) {
    if (entropy.length < 32) throw new RangeError('drbg: at least 256 bits of entropy');
    this.update(concat(entropy, nonce, personalization));
    this.counter = 1;
  }

  /** HMAC_DRBG_Update (§10.1.2.2). */
  private update(data: Uint8Array | null): void {
    const K = hmac(SHA512, this.K, this.V, Uint8Array.of(0), data ?? new Uint8Array(0));
    wipe(this.K);
    this.K = K;
    this.V = hmac(SHA512, this.K, this.V);
    if (!data || data.length === 0) return;
    const K2 = hmac(SHA512, this.K, this.V, Uint8Array.of(1), data);
    wipe(this.K);
    this.K = K2;
    this.V = hmac(SHA512, this.K, this.V);
  }

  /** Reseed (§10.1.2.4). */
  reseed(entropy: Uint8Array, additional: Uint8Array = new Uint8Array(0)): void {
    if (entropy.length < 32) throw new RangeError('drbg: at least 256 bits of entropy');
    this.update(concat(entropy, additional));
    this.counter = 1;
  }

  /** Generate (§10.1.2.5). */
  generate(length: number, additional: Uint8Array | null = null): Uint8Array {
    if (this.counter > RESEED_INTERVAL) throw new Error('drbg: reseed required');
    if (additional && additional.length) this.update(additional);
    const out = new Uint8Array(length);
    for (let at = 0; at < length; at += OUT) {
      this.V = hmac(SHA512, this.K, this.V);
      out.set(this.V.subarray(0, Math.min(OUT, length - at)), at);
    }
    this.update(additional && additional.length ? additional : null);
    this.counter++;
    return out;
  }

  destroy(): void {
    wipe(this.K, this.V);
  }
}
