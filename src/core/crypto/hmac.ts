// HMAC, RFC 2104 / FIPS 198-1, over any hash here.

import type { Hash, HashAlgorithm } from './hash.ts';
import { wipe } from './util.ts';

export class Hmac {
  private readonly inner: Hash;
  private readonly outerKey: Uint8Array;
  private readonly algorithm: HashAlgorithm;

  constructor(algorithm: HashAlgorithm, key: Uint8Array) {
    this.algorithm = algorithm;
    const block = new Uint8Array(algorithm.blockLength);
    if (key.length > block.length) block.set(algorithm.create().update(key).digest());
    else block.set(key);
    const ipad = block.map((b) => b ^ 0x36);
    this.outerKey = block.map((b) => b ^ 0x5c);
    this.inner = algorithm.create().update(ipad);
    wipe(block, ipad);
  }

  update(data: Uint8Array): this {
    this.inner.update(data);
    return this;
  }

  digest(): Uint8Array {
    const inner = this.inner.digest();
    const out = this.algorithm.create().update(this.outerKey).update(inner).digest();
    wipe(inner, this.outerKey);
    return out;
  }
}

export function hmac(algorithm: HashAlgorithm, key: Uint8Array, ...parts: Uint8Array[]): Uint8Array {
  const mac = new Hmac(algorithm, key);
  for (const part of parts) mac.update(part);
  return mac.digest();
}
