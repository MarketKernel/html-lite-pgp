// What every hash here looks like, and the buffering they share: data comes in pieces of any
// size, the compression function sees whole blocks. FIPS 180-4 pads every hash the same way —
// 0x80, zeros, then the length in bits, big-endian — only the block and length sizes differ.

export interface Hash {
  update(data: Uint8Array): Hash;
  /** The digest; the object is used up after this. */
  digest(): Uint8Array;
}

export interface HashAlgorithm {
  readonly name: string;
  readonly blockLength: number;
  readonly outputLength: number;
  create(): Hash;
}

/** A Merkle–Damgård hash: subclasses give the block size, the length field's size and the compression. */
export abstract class BlockHash implements Hash {
  protected readonly buffer: Uint8Array;
  private filled = 0;
  private length = 0;
  private done = false;

  protected readonly blockLength: number;
  private readonly lengthBytes: number;

  constructor(blockLength: number, lengthBytes: number) {
    this.blockLength = blockLength;
    this.lengthBytes = lengthBytes;
    this.buffer = new Uint8Array(blockLength);
  }

  protected abstract compress(block: Uint8Array, offset: number): void;
  protected abstract output(): Uint8Array;

  update(data: Uint8Array): this {
    if (this.done) throw new Error('hash: update after digest');
    let at = 0;
    this.length += data.length;
    if (this.filled > 0) {
      const take = Math.min(data.length, this.blockLength - this.filled);
      this.buffer.set(data.subarray(0, take), this.filled);
      this.filled += take;
      at = take;
      if (this.filled < this.blockLength) return this;
      this.compress(this.buffer, 0);
      this.filled = 0;
    }
    for (; at + this.blockLength <= data.length; at += this.blockLength) this.compress(data, at);
    if (at < data.length) {
      this.buffer.set(data.subarray(at), 0);
      this.filled = data.length - at;
    }
    return this;
  }

  digest(): Uint8Array {
    if (this.done) throw new Error('hash: digest twice');
    this.done = true;
    const block = this.buffer;
    block[this.filled++] = 0x80;
    if (this.filled > this.blockLength - this.lengthBytes) {
      block.fill(0, this.filled);
      this.compress(block, 0);
      this.filled = 0;
    }
    block.fill(0, this.filled);
    // The length in bits, big-endian, in the last 8 bytes (a 16-byte field's upper half stays zero).
    const bits = this.length * 8;
    const end = this.blockLength;
    const high = Math.floor(bits / 0x100000000);
    const low = bits >>> 0;
    block[end - 8] = high >>> 24;
    block[end - 7] = high >>> 16;
    block[end - 6] = high >>> 8;
    block[end - 5] = high;
    block[end - 4] = low >>> 24;
    block[end - 3] = low >>> 16;
    block[end - 2] = low >>> 8;
    block[end - 1] = low;
    this.compress(block, 0);
    block.fill(0);
    return this.output();
  }
}

/** A big-endian 32-bit word of `bytes` at `at`. */
export const be32 = (bytes: Uint8Array, at: number): number => ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0;

/** Writes 32-bit words big-endian. */
export function wordsToBytes(words: ArrayLike<number>, count = words.length): Uint8Array {
  const out = new Uint8Array(count * 4);
  for (let i = 0; i < count; i++) {
    const w = words[i];
    out[i * 4] = w >>> 24;
    out[i * 4 + 1] = w >>> 16;
    out[i * 4 + 2] = w >>> 8;
    out[i * 4 + 3] = w;
  }
  return out;
}

/** The digest of `parts`, hashed one after another. */
export function digest(algorithm: HashAlgorithm, ...parts: Uint8Array[]): Uint8Array {
  const h = algorithm.create();
  for (const part of parts) h.update(part);
  return h.digest();
}
