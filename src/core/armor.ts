// ASCII armor, RFC 4880 §6: base64 between BEGIN and END lines, with the CRC-24 checksum line.
// We write it with lines of 64 characters and no headers, and read it strictly: a character
// outside base64 is an error, and so is a checksum that does not match.

import { crc24 } from './crypto/crc24.ts';
import { PgpError, malformed } from './errors.ts';

export type ArmorType = 'MESSAGE' | 'PUBLIC KEY BLOCK' | 'PRIVATE KEY BLOCK' | 'SIGNATURE';
const TYPES: readonly string[] = ['MESSAGE', 'PUBLIC KEY BLOCK', 'PRIVATE KEY BLOCK', 'SIGNATURE'];

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const INDEX = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < 64; i++) t[ALPHABET.charCodeAt(i)] = i;
  return t;
})();

export function toBase64(data: Uint8Array): string {
  let out = '';
  for (let i = 0; i < data.length; i += 3) {
    const n = (data[i] << 16) | ((data[i + 1] ?? 0) << 8) | (data[i + 2] ?? 0);
    out += ALPHABET[n >> 18] + ALPHABET[(n >> 12) & 63];
    out += i + 1 < data.length ? ALPHABET[(n >> 6) & 63] : '=';
    out += i + 2 < data.length ? ALPHABET[n & 63] : '=';
  }
  return out;
}

/** Strict base64: whitespace is skipped, anything else outside the alphabet is an error. */
export function fromBase64(text: string): Uint8Array {
  const clean = text.replace(/[ \t\r\n]/g, '');
  if (clean.length % 4 !== 0) throw malformed('the base64 text has a length that is not a multiple of 4');
  const pad = clean.endsWith('==') ? 2 : clean.endsWith('=') ? 1 : 0;
  const out = new Uint8Array((clean.length / 4) * 3 - pad);
  let o = 0;
  for (let i = 0; i < clean.length; i += 4) {
    let n = 0;
    for (let k = 0; k < 4; k++) {
      const c = clean.charCodeAt(i + k);
      let v: number;
      if (c === 61 && i + 4 === clean.length && k >= 4 - pad) v = 0;
      else v = c < 128 ? INDEX[c] : -1;
      if (v < 0) throw malformed('the text has a character that is not base64');
      n = (n << 6) | v;
    }
    out[o++] = n >> 16;
    if (o < out.length) out[o++] = (n >> 8) & 255;
    if (o < out.length) out[o++] = n & 255;
  }
  return out;
}

const crcLine = (data: Uint8Array): string => {
  const c = crc24(data);
  return '=' + toBase64(Uint8Array.of(c >> 16, (c >> 8) & 255, c & 255));
};

export function armor(type: ArmorType, data: Uint8Array): string {
  const body = toBase64(data).replace(/.{64}/g, '$&\n').replace(/\n$/, '');
  return `-----BEGIN PGP ${type}-----\n\n${body}\n${crcLine(data)}\n-----END PGP ${type}-----\n`;
}

export interface Armored {
  type: ArmorType;
  data: Uint8Array;
  /** Where the armor ended in the text: more blocks may follow. */
  end: number;
}

/** True when the text holds an armor block (BEGIN PGP …), as opposed to binary data. */
export const looksArmored = (text: string): boolean => /-----BEGIN PGP [A-Z ]+-----/.test(text);

/** Every armored block in `text`, in order. A clear-signed text is not one of them (cleartext.ts). */
export function dearmorAll(text: string): Armored[] {
  const out: Armored[] = [];
  const re = /^-----BEGIN PGP ([A-Z ]+)-----[ \t]*\r?$/gm;
  for (let m; (m = re.exec(text)); ) {
    if (m[1] === 'SIGNED MESSAGE') continue;
    const block = dearmorAt(text, m.index);
    out.push(block);
    re.lastIndex = block.end;
  }
  return out;
}

/** The first armored block in `text`. */
export function dearmor(text: string): Armored {
  const blocks = dearmorAll(text);
  if (!blocks.length) throw new PgpError('unexpected', 'no OpenPGP armor in the text');
  return blocks[0];
}

function dearmorAt(text: string, start: number): Armored {
  const head = /^-----BEGIN PGP ([A-Z ]+)-----[ \t]*\r?\n/.exec(text.slice(start));
  if (!head) throw malformed('the armor has no BEGIN line');
  const type = head[1];
  if (!TYPES.includes(type)) throw new PgpError('unsupported', `armor of type "${type}"`);
  const endLine = `-----END PGP ${type}-----`;
  const stop = text.indexOf(endLine, start + head[0].length);
  if (stop < 0) throw malformed('the armor has no END line');
  const lines = text.slice(start + head[0].length, stop).split(/\r?\n/);
  let i = 0;
  // Headers ("Key: value") until the first empty line; GnuPG's "Comment:", "Version:" and the
  // like say nothing that is checked, and are skipped.
  while (i < lines.length && /^[\x21-\x39\x3b-\x7e]+: /.test(lines[i])) i++;
  if (i < lines.length && lines[i].trim() === '') i++;
  const body: string[] = [];
  let checksum: string | null = null;
  for (; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === '') continue;
    if (line.startsWith('-----')) throw malformed('an armor line where the data should be');
    if (/^=[A-Za-z0-9+/]{4}$/.test(line)) {
      if (checksum !== null) throw malformed('two armor checksums');
      checksum = line.slice(1);
    } else if (checksum !== null) {
      throw malformed('text after the armor checksum');
    } else {
      body.push(line);
    }
  }
  const data = fromBase64(body.join(''));
  if (checksum !== null) {
    const expected = fromBase64(checksum);
    const c = crc24(data);
    if (expected[0] !== c >> 16 || expected[1] !== ((c >> 8) & 255) || expected[2] !== (c & 255)) {
      throw new PgpError('integrity', 'the armor checksum does not match: the text was damaged');
    }
  }
  return { type: type as ArmorType, data, end: stop + endLine.length };
}

/**
 * ASCII armor whose line breaks were turned into spaces — as a browser's context menu hands
 * over a selection — put back on its lines. The headers are dropped: they are optional and
 * not checked. Text that is not such armor is returned as it is; a clear-signed text cannot be
 * mended, its own lines being lost. (From html-pgp.)
 */
export function reflowArmor(text: string): string {
  if (/\n/.test(text.trim())) return text;
  const match = /-----BEGIN PGP (MESSAGE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK|SIGNATURE)-----(.*?)-----END PGP \1-----/s.exec(text);
  if (!match) return text;
  const tokens = (match[2] ?? '').trim().split(/\s+/).filter(Boolean);
  const checksum = tokens.length && /^=[A-Za-z0-9+/]{4}$/.test(tokens[tokens.length - 1]) ? tokens.pop()! : null;
  const body: string[] = [];
  while (tokens.length && /^[A-Za-z0-9+/=]+$/.test(tokens[tokens.length - 1])) body.unshift(tokens.pop()!);
  return [`-----BEGIN PGP ${match[1]}-----`, '', ...body, ...(checksum ? [checksum] : []), `-----END PGP ${match[1]}-----`, ''].join('\n');
}
