// Unlocked secrets, as gpg-agent keeps them: a key unlocked once stays unlocked, in memory
// only, for the minutes the settings say, then is wiped. The passphrase itself is never kept.
// A cached secret belongs to the stored key it came from: when that key's record changes, the
// cache entry is dropped rather than trusted.

import { equalBytes } from './bytes.ts';
import type { Secret } from './secret.ts';
import { wipeSecret } from './secret.ts';

interface Cached {
  /** By the hex fingerprint of each (sub)key. */
  secrets: Map<string, Secret>;
  data: Uint8Array;
  timer: ReturnType<typeof setTimeout> | null;
}

export class Agent {
  private readonly cache = new Map<string, Cached>();
  private readonly listeners = new Set<() => void>();
  /** Milliseconds to keep a key; 0: ask every time. */
  ttl: number;

  constructor(ttl: number) {
    this.ttl = ttl;
  }

  onChange(listener: () => void): void {
    this.listeners.add(listener);
  }

  private changed(): void {
    for (const l of this.listeners) l();
  }

  get size(): number {
    return this.cache.size;
  }

  /** The cached secrets of the key whose stored record is `data`, if still cached. */
  get(fingerprint: string, data: Uint8Array): Map<string, Secret> | null {
    const c = this.cache.get(fingerprint);
    if (!c) return null;
    if (!equalBytes(c.data, data)) {
      this.forget(fingerprint);
      return null;
    }
    return c.secrets;
  }

  /** Keeps the secrets for the configured time; with a time of 0, does not keep them. */
  put(fingerprint: string, data: Uint8Array, secrets: Map<string, Secret>): void {
    this.forget(fingerprint);
    if (this.ttl <= 0) return;
    const timer = setTimeout(() => this.forget(fingerprint), this.ttl);
    this.cache.set(fingerprint, { secrets, data, timer });
    this.changed();
  }

  forget(fingerprint: string): void {
    const c = this.cache.get(fingerprint);
    if (!c) return;
    if (c.timer) clearTimeout(c.timer);
    for (const s of c.secrets.values()) wipeSecret(s);
    this.cache.delete(fingerprint);
    this.changed();
  }

  forgetAll(): void {
    for (const fingerprint of [...this.cache.keys()]) this.forget(fingerprint);
  }
}
