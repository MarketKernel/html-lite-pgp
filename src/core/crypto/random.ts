// Where every random byte of the program comes from (Task.md §4): one source, chosen by the
// user, never mixed with the other.
//
//   - "hardware": the system's generator through crypto.getRandomValues — the only call to it
//     in the program. The browser has no direct way to the hardware generator; the system's
//     own is fed from it (RDRAND/RNDR, Apple's TRNG, the TPM) and from interrupt noise.
//   - "mouse": a pool fed by the movements of the pointer and the timing of keys, credited at
//     one bit per event at most; getRandomValues is not called at all.
//
// Either way the bytes come out of HMAC_DRBG with SHA-512, seeded from the source, and
// reseeded from it before each request when it has something new.

import { HmacDrbg } from './drbg.ts';
import { sha512 } from './sha512.ts';
import { wipe } from './util.ts';

export interface RandomSource {
  readonly kind: 'hardware' | 'mouse';
  bytes(n: number): Uint8Array;
}

function systemBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  // getRandomValues gives at most 65 536 bytes a call.
  for (let at = 0; at < n; at += 65536) globalThis.crypto.getRandomValues(out.subarray(at, Math.min(n, at + 65536)));
  return out;
}

/** The system generator is there and answers sensibly: two draws, not equal, not zero. */
export function hardwareAvailable(): boolean {
  try {
    if (typeof globalThis.crypto?.getRandomValues !== 'function') return false;
    const a = systemBytes(64);
    const b = systemBytes(64);
    let same = 0;
    let any = 0;
    for (let i = 0; i < 64; i++) {
      same |= a[i] ^ b[i];
      any |= a[i] | b[i];
    }
    return same !== 0 && any !== 0;
  } catch {
    return false;
  }
}

export function hardwareRandom(): RandomSource {
  if (!hardwareAvailable()) throw new Error('the system random generator is not available');
  const drbg = new HmacDrbg(systemBytes(64), new Uint8Array(0), new TextEncoder().encode('html-simple-pgp hardware'));
  return {
    kind: 'hardware',
    bytes(n: number) {
      const fresh = systemBytes(64);
      drbg.reseed(fresh);
      wipe(fresh);
      return drbg.generate(n);
    },
  };
}

/** What the pool asks of the collector before it is ready: 256 credited events over at least 2 seconds. */
export const POOL_TARGET_BITS = 256;
export const POOL_MIN_MS = 2000;

/**
 * The mouse pool: every event is hashed in; an event counts for one bit only if the pointer
 * moved and time went on since the last one. Credit is an estimate kept low on purpose:
 * browsers round timers, and a hand moves smoothly.
 */
export class EntropyPool {
  private state = new Uint8Array(64);
  private fresh = false;
  private lastX = NaN;
  private lastY = NaN;
  /** The time of the last event of any kind, credited or not. */
  private lastT = -Infinity;
  private firstT = NaN;
  private lastCredit = NaN;
  private events = 0;
  credited = 0;

  private mix(values: number[]): void {
    const f = new Float64Array([this.events++, ...values]);
    const next = sha512(this.state, new Uint8Array(f.buffer));
    wipe(this.state);
    this.state = next;
    this.fresh = true;
  }

  /** A pointer event (mouse, pen, finger). Returns true if it was credited. */
  addPointer(x: number, y: number, time: number, extra: number[] = []): boolean {
    this.mix([1, x, y, time, ...extra]);
    const moved = x !== this.lastX || y !== this.lastY;
    const later = time > this.lastT;
    this.lastX = x;
    this.lastY = y;
    this.lastT = Math.max(this.lastT, time);
    if (!moved || !later) return false;
    return this.credit(time);
  }

  /** A key press: its timing only, never which key. */
  addKey(time: number, extra: number[] = []): boolean {
    this.mix([2, time, ...extra]);
    const later = time > this.lastT;
    this.lastT = Math.max(this.lastT, time);
    if (!later) return false;
    return this.credit(time);
  }

  private credit(time: number): boolean {
    if (Number.isNaN(this.firstT)) this.firstT = time;
    this.lastCredit = time;
    this.credited++;
    return true;
  }

  get progress(): number {
    const span = Number.isNaN(this.firstT) ? 0 : this.lastCredit - this.firstT;
    return Math.min(1, this.credited / POOL_TARGET_BITS, span / POOL_MIN_MS);
  }

  get ready(): boolean {
    return this.progress >= 1;
  }

  /** The pool's state for a seed, and whether anything came in since the last call. */
  take(): { seed: Uint8Array; fresh: boolean } {
    const seed = sha512(this.state, new TextEncoder().encode('take'));
    const fresh = this.fresh;
    this.fresh = false;
    // Move the state on, so a seed once taken cannot be computed from what follows.
    const next = sha512(this.state, new TextEncoder().encode('next'));
    wipe(this.state);
    this.state = next;
    return { seed, fresh };
  }
}

export function mouseRandom(pool: EntropyPool): RandomSource {
  if (!pool.ready) throw new Error('the pool has not collected enough movement yet');
  const first = pool.take();
  const drbg = new HmacDrbg(first.seed, new Uint8Array(0), new TextEncoder().encode('html-simple-pgp mouse'));
  wipe(first.seed);
  return {
    kind: 'mouse',
    bytes(n: number) {
      const more = pool.take();
      if (more.fresh) drbg.reseed(more.seed);
      wipe(more.seed);
      return drbg.generate(n);
    },
  };
}

