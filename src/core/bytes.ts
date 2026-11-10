// Reading and writing bytes with every length checked: a Reader never reads past its end, it
// throws a 'malformed' PgpError instead.

import { malformed } from './errors.ts';

export class Reader {
  readonly data: Uint8Array;
  at: number;
  readonly end: number;

  constructor(data: Uint8Array, at = 0, end = data.length) {
    this.data = data;
    this.at = at;
    this.end = end;
  }

  get remaining(): number {
    return this.end - this.at;
  }

  private need(n: number, what: string): void {
    if (n < 0 || this.at + n > this.end) throw malformed(`${what} runs past the end of the data`);
  }

  byte(what = 'a byte'): number {
    this.need(1, what);
    return this.data[this.at++];
  }

  u16(what = 'a number'): number {
    this.need(2, what);
    const v = (this.data[this.at] << 8) | this.data[this.at + 1];
    this.at += 2;
    return v;
  }

  u32(what = 'a number'): number {
    this.need(4, what);
    const d = this.data;
    const v = ((d[this.at] << 24) | (d[this.at + 1] << 16) | (d[this.at + 2] << 8) | d[this.at + 3]) >>> 0;
    this.at += 4;
    return v;
  }

  bytes(n: number, what = 'a field'): Uint8Array {
    this.need(n, what);
    const out = this.data.subarray(this.at, this.at + n);
    this.at += n;
    return out;
  }

  rest(): Uint8Array {
    const out = this.data.subarray(this.at, this.end);
    this.at = this.end;
    return out;
  }

  /** Throws if anything is left: trailing bytes are an error, not something to skip. */
  done(what: string): void {
    if (this.at !== this.end) throw malformed(`${what} has ${this.end - this.at} unexpected bytes at its end`);
  }
}

export class Writer {
  private buffer = new Uint8Array(256);
  private length = 0;

  private room(n: number): void {
    if (this.length + n <= this.buffer.length) return;
    let size = this.buffer.length * 2;
    while (size < this.length + n) size *= 2;
    const bigger = new Uint8Array(size);
    bigger.set(this.buffer.subarray(0, this.length));
    this.buffer = bigger;
  }

  byte(v: number): this {
    this.room(1);
    this.buffer[this.length++] = v;
    return this;
  }

  u16(v: number): this {
    return this.byte(v >>> 8).byte(v);
  }

  u32(v: number): this {
    return this.byte(v >>> 24).byte(v >>> 16).byte(v >>> 8).byte(v);
  }

  bytes(data: Uint8Array): this {
    this.room(data.length);
    this.buffer.set(data, this.length);
    this.length += data.length;
    return this;
  }

  finish(): Uint8Array {
    return this.buffer.slice(0, this.length);
  }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const utf8 = (text: string): Uint8Array => encoder.encode(text);

/** UTF-8 to text; invalid UTF-8 is an error, not replacement characters. */
export function fromUtf8(data: Uint8Array): string {
  try {
    return decoder.decode(data);
  } catch {
    throw malformed('the text is not valid UTF-8');
  }
}

export const toHex = (data: Uint8Array): string => Array.from(data, (b) => b.toString(16).padStart(2, '0')).join('');

export function fromHex(hex: string): Uint8Array {
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(hex)) throw malformed('not hexadecimal');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Equal contents; for public data (fingerprints, packets). */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
