// Inflate, RFC 1951 (raw DEFLATE) and RFC 1950 (zlib): only to read what GnuPG compressed —
// `gpg --sign` always does, and a sender's own settings may. We never compress.
//
// After puff.c by Mark Adler (zlib license), the reference decoder written for clarity rather
// than speed: canonical Huffman codes decoded a bit at a time. The output may not grow past
// `limit`: a few kilobytes of DEFLATE can claim gigabytes ("decompression bombs").

export class InflateError extends Error {}

const LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DEXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
const MAXBITS = 15;

interface Huffman {
  count: Uint16Array;
  symbol: Uint16Array;
}

/**
 * Builds the decoding tables from code lengths. Returns 0 for a complete code, a positive
 * number for an incomplete one, a negative one for an over-subscribed one.
 */
function construct(h: Huffman, length: ArrayLike<number>, n: number): number {
  h.count.fill(0);
  for (let s = 0; s < n; s++) h.count[length[s]]++;
  if (h.count[0] === n) return 0;
  let left = 1;
  for (let len = 1; len <= MAXBITS; len++) {
    left <<= 1;
    left -= h.count[len];
    if (left < 0) return left;
  }
  const offs = new Uint16Array(MAXBITS + 1);
  for (let len = 1; len < MAXBITS; len++) offs[len + 1] = offs[len] + h.count[len];
  for (let s = 0; s < n; s++) if (length[s] !== 0) h.symbol[offs[length[s]]++] = s;
  return left;
}

const huffman = (symbols: number): Huffman => ({ count: new Uint16Array(MAXBITS + 1), symbol: new Uint16Array(symbols) });

class Inflater {
  private out: Uint8Array;
  private outcnt = 0;
  private incnt = 0;
  private bitbuf = 0;
  private bitcnt = 0;
  private readonly input: Uint8Array;
  private readonly limit: number;

  constructor(input: Uint8Array, limit: number) {
    this.input = input;
    this.limit = limit;
    this.out = new Uint8Array(Math.min(limit, Math.max(1024, input.length * 4)));
  }

  private bits(need: number): number {
    let val = this.bitbuf;
    while (this.bitcnt < need) {
      if (this.incnt >= this.input.length) throw new InflateError('the compressed data ends early');
      val |= this.input[this.incnt++] << this.bitcnt;
      this.bitcnt += 8;
    }
    this.bitbuf = val >>> need;
    this.bitcnt -= need;
    return val & ((1 << need) - 1);
  }

  private room(n: number): void {
    const need = this.outcnt + n;
    if (need > this.limit) throw new InflateError('the data unpacks to more than the limit');
    if (need <= this.out.length) return;
    let size = this.out.length;
    while (size < need) size *= 2;
    const bigger = new Uint8Array(Math.min(size, this.limit));
    bigger.set(this.out.subarray(0, this.outcnt));
    this.out = bigger;
  }

  private stored(): void {
    this.bitbuf = 0;
    this.bitcnt = 0;
    if (this.incnt + 4 > this.input.length) throw new InflateError('the compressed data ends early');
    const len = this.input[this.incnt] | (this.input[this.incnt + 1] << 8);
    const nlen = this.input[this.incnt + 2] | (this.input[this.incnt + 3] << 8);
    this.incnt += 4;
    if (len !== (~nlen & 0xffff)) throw new InflateError('a stored block has a bad length');
    if (this.incnt + len > this.input.length) throw new InflateError('the compressed data ends early');
    this.room(len);
    this.out.set(this.input.subarray(this.incnt, this.incnt + len), this.outcnt);
    this.outcnt += len;
    this.incnt += len;
  }

  private decode(h: Huffman): number {
    let code = 0;
    let first = 0;
    let index = 0;
    for (let len = 1; len <= MAXBITS; len++) {
      code |= this.bits(1);
      const count = h.count[len];
      if (code - count < first) return h.symbol[index + (code - first)];
      index += count;
      first += count;
      first <<= 1;
      code <<= 1;
    }
    throw new InflateError('a code is not in the table');
  }

  private codes(lencode: Huffman, distcode: Huffman): void {
    for (;;) {
      let symbol = this.decode(lencode);
      if (symbol < 256) {
        this.room(1);
        this.out[this.outcnt++] = symbol;
      } else if (symbol === 256) {
        return;
      } else {
        symbol -= 257;
        if (symbol >= 29) throw new InflateError('a bad length symbol');
        const len = LBASE[symbol] + this.bits(LEXT[symbol]);
        symbol = this.decode(distcode);
        if (symbol >= 30) throw new InflateError('a bad distance symbol');
        const dist = DBASE[symbol] + this.bits(DEXT[symbol]);
        if (dist > this.outcnt) throw new InflateError('a distance reaches before the start');
        this.room(len);
        for (let i = 0; i < len; i++, this.outcnt++) this.out[this.outcnt] = this.out[this.outcnt - dist];
      }
    }
  }

  private fixed(): void {
    const lengths = new Uint8Array(288);
    lengths.fill(8, 0, 144);
    lengths.fill(9, 144, 256);
    lengths.fill(7, 256, 280);
    lengths.fill(8, 280, 288);
    const lencode = huffman(288);
    construct(lencode, lengths, 288);
    const distcode = huffman(30);
    construct(distcode, new Uint8Array(30).fill(5), 30);
    this.codes(lencode, distcode);
  }

  private dynamic(): void {
    const nlen = this.bits(5) + 257;
    const ndist = this.bits(5) + 1;
    const ncode = this.bits(4) + 4;
    if (nlen > 286 || ndist > 30) throw new InflateError('bad counts in a dynamic block');
    const lengths = new Uint8Array(320);
    for (let i = 0; i < ncode; i++) lengths[ORDER[i]] = this.bits(3);
    const lencode = huffman(286);
    if (construct(lencode, lengths, 19) !== 0) throw new InflateError('an incomplete code-length code');
    lengths.fill(0);
    for (let index = 0; index < nlen + ndist; ) {
      let symbol = this.decode(lencode);
      if (symbol < 16) {
        lengths[index++] = symbol;
        continue;
      }
      let len = 0;
      if (symbol === 16) {
        if (index === 0) throw new InflateError('a repeat with nothing before it');
        len = lengths[index - 1];
        symbol = 3 + this.bits(2);
      } else if (symbol === 17) {
        symbol = 3 + this.bits(3);
      } else {
        symbol = 11 + this.bits(7);
      }
      if (index + symbol > nlen + ndist) throw new InflateError('too many lengths');
      while (symbol--) lengths[index++] = len;
    }
    if (lengths[256] === 0) throw new InflateError('no end-of-block code');
    let err = construct(lencode, lengths, nlen);
    if (err < 0 || (err > 0 && nlen - lencode.count[0] !== 1)) throw new InflateError('a bad literal/length code');
    const distcode = huffman(30);
    err = construct(distcode, lengths.subarray(nlen), ndist);
    if (err < 0 || (err > 0 && ndist - distcode.count[0] !== 1)) throw new InflateError('a bad distance code');
    this.codes(lencode, distcode);
  }

  /** Inflates the blocks; returns where the input ended (rounded up to a byte). */
  run(): { data: Uint8Array; end: number } {
    let last: number;
    do {
      last = this.bits(1);
      const type = this.bits(2);
      if (type === 0) this.stored();
      else if (type === 1) this.fixed();
      else if (type === 2) this.dynamic();
      else throw new InflateError('a block of type 3');
    } while (!last);
    return { data: this.out.slice(0, this.outcnt), end: this.incnt };
  }
}

/** Raw DEFLATE (RFC 1951) — OpenPGP's ZIP algorithm. */
export function inflateRaw(input: Uint8Array, limit: number): Uint8Array {
  return new Inflater(input, limit).run().data;
}

function adler32(data: Uint8Array): number {
  let a = 1;
  let b = 0;
  for (let i = 0; i < data.length; ) {
    const end = Math.min(data.length, i + 3800);
    for (; i < end; i++) {
      a += data[i];
      b += a;
    }
    a %= 65521;
    b %= 65521;
  }
  return ((b << 16) | a) >>> 0;
}

/** zlib (RFC 1950) — OpenPGP's ZLIB algorithm: a header, DEFLATE, then Adler-32. */
export function inflateZlib(input: Uint8Array, limit: number): Uint8Array {
  if (input.length < 6) throw new InflateError('the compressed data ends early');
  const cmf = input[0];
  const flg = input[1];
  if ((cmf & 0x0f) !== 8 || cmf >> 4 > 7 || (cmf * 256 + flg) % 31 !== 0) throw new InflateError('not a zlib stream');
  if (flg & 0x20) throw new InflateError('a zlib stream with a preset dictionary');
  const { data, end } = new Inflater(input.subarray(2), limit).run();
  const at = 2 + end;
  if (at + 4 > input.length) throw new InflateError('the zlib checksum is missing');
  const expected = ((input[at] << 24) | (input[at + 1] << 16) | (input[at + 2] << 8) | input[at + 3]) >>> 0;
  if (adler32(data) !== expected) throw new InflateError('the zlib checksum does not match');
  return data;
}
