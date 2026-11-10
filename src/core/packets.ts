// OpenPGP packet framing, RFC 4880 §4 (RFC 9580 §4): the header with its tag and length, and
// nothing about the contents. Both header formats are read — GnuPG 2.2 writes the old one —
// and only the new one is written, with definite lengths: everything is in memory.

import { Reader, Writer } from './bytes.ts';
import { concat } from './crypto/util.ts';
import { PgpError, malformed } from './errors.ts';

export const TAG = {
  PKESK: 1,
  SIGNATURE: 2,
  SKESK: 3,
  ONE_PASS: 4,
  SECRET_KEY: 5,
  PUBLIC_KEY: 6,
  SECRET_SUBKEY: 7,
  COMPRESSED: 8,
  SED: 9,
  MARKER: 10,
  LITERAL: 11,
  TRUST: 12,
  USER_ID: 13,
  PUBLIC_SUBKEY: 14,
  USER_ATTRIBUTE: 17,
  SEIPD: 18,
  MDC: 19,
  AEAD: 20,
  PADDING: 21,
} as const;

/** Packets that may carry partial body lengths (RFC 4880 §4.2.2.4): only those with data. */
const DATA_TAGS: ReadonlySet<number> = new Set([TAG.COMPRESSED, TAG.SED, TAG.LITERAL, TAG.SEIPD, TAG.AEAD]);

export interface Packet {
  tag: number;
  body: Uint8Array;
  /** The whole packet as it was read, header included: signatures over keys hash parts of it. */
  raw: Uint8Array;
}

/** The most packets one input may hold — a keyring of thousands of keys is far below it. */
export const MAX_PACKETS = 200_000;

/** The packets of `data`, in order. Anything after the last whole packet is an error. */
export function readPackets(data: Uint8Array): Packet[] {
  const r = new Reader(data);
  const packets: Packet[] = [];
  while (r.remaining > 0) {
    if (packets.length >= MAX_PACKETS) throw new PgpError('too-large', 'too many packets');
    packets.push(readPacket(r));
  }
  return packets;
}

function readPacket(r: Reader): Packet {
  const start = r.at;
  const first = r.byte('a packet header');
  if (!(first & 0x80)) throw malformed('this is not OpenPGP data (a packet header without its high bit)');
  let tag: number;
  let body: Uint8Array;
  if (first & 0x40) {
    tag = first & 0x3f;
    body = readNewBody(r, tag);
  } else {
    tag = (first >> 2) & 0x0f;
    const type = first & 3;
    if (type === 3) {
      // Indeterminate length: the rest of the data. Only data packets may do this.
      if (!DATA_TAGS.has(tag)) throw malformed(`packet ${tag} has an indeterminate length`);
      body = r.rest();
    } else {
      const length = type === 0 ? r.byte('a length') : type === 1 ? r.u16('a length') : r.u32('a length');
      body = r.bytes(length, `packet ${tag}`);
    }
  }
  if (tag === 0) throw malformed('a packet with the reserved tag 0');
  return { tag, body, raw: r.data.subarray(start, r.at) };
}

function readNewBody(r: Reader, tag: number): Uint8Array {
  const parts: Uint8Array[] = [];
  let firstPart = true;
  for (;;) {
    const b = r.byte('a length');
    if (b < 192) {
      parts.push(r.bytes(b, `packet ${tag}`));
      break;
    }
    if (b < 224) {
      const length = ((b - 192) << 8) + r.byte('a length') + 192;
      parts.push(r.bytes(length, `packet ${tag}`));
      break;
    }
    if (b === 255) {
      parts.push(r.bytes(r.u32('a length'), `packet ${tag}`));
      break;
    }
    // A partial body length: 2^(b & 31) bytes, and more parts follow.
    if (!DATA_TAGS.has(tag)) throw malformed(`packet ${tag} uses partial lengths`);
    const length = 1 << (b & 0x1f);
    if (firstPart && length < 512) throw malformed('the first partial length is under 512 bytes');
    firstPart = false;
    parts.push(r.bytes(length, `packet ${tag}`));
  }
  return parts.length === 1 ? parts[0] : concat(...parts);
}

/** A packet in the new format with a definite length. */
export function writePacket(tag: number, body: Uint8Array): Uint8Array {
  const w = new Writer().byte(0xc0 | tag);
  const n = body.length;
  if (n < 192) w.byte(n);
  else if (n < 8384) w.byte(((n - 192) >> 8) + 192).byte((n - 192) & 0xff);
  else w.byte(255).u32(n);
  return w.bytes(body).finish();
}
