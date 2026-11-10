// The Cleartext Signature Framework, RFC 4880 §7: a text that stays readable, followed by its
// signature. The text is signed as a text signature (type 0x01): lines end in CR LF, spaces
// and tabs at the ends of lines are dropped, and the line break before the signature is not
// part of it. Lines starting with "-" are escaped as "- -" so they cannot be taken for armor.

import { armor, dearmorAll } from './armor.ts';
import { utf8 } from './bytes.ts';
import { PgpError, malformed } from './errors.ts';
import { readPackets, TAG } from './packets.ts';
import { readSignature } from './signature.ts';
import type { Signature } from './signature.ts';

const BEGIN_SIGNED = '-----BEGIN PGP SIGNED MESSAGE-----';
const BEGIN_SIGNATURE = '-----BEGIN PGP SIGNATURE-----';

const HASH_NAMES: Record<string, number> = { MD5: 1, SHA1: 2, RIPEMD160: 3, SHA256: 8, SHA384: 9, SHA512: 10, SHA224: 11 };

/** Spaces and tabs at a line's end are not signed — so they are neither written nor shown. */
const trimLine = (line: string): string => line.replace(/[ \t]+$/, '');

/** The bytes a text signature over these lines covers. */
export function signedBytes(lines: string[]): Uint8Array {
  return utf8(lines.map(trimLine).join('\r\n'));
}

/** The text's lines, with any line-ending convention, without the final line break. */
export function textLines(text: string): string[] {
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  if (lines.length > 1 && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

export function writeCleartext(text: string, signature: Uint8Array): string {
  const body = textLines(text).map(trimLine).map((line) => (line.startsWith('-') ? `- ${line}` : line));
  const sig = armor('SIGNATURE', signature);
  return `${BEGIN_SIGNED}\nHash: SHA512\n\n${body.join('\n')}\n${sig}`;
}

export interface Cleartext {
  /** The text as signed: unescaped, "\n" line breaks, no spaces at line ends. */
  text: string;
  /** What the signatures cover. */
  signed: Uint8Array;
  signatures: Signature[];
  /** Where the clear-signed block ended in the input. */
  end: number;
}

export const looksClearSigned = (text: string): boolean => /^-----BEGIN PGP SIGNED MESSAGE-----[ \t]*\r?$/m.test(text);

export function readCleartext(input: string): Cleartext {
  const start = input.search(/^-----BEGIN PGP SIGNED MESSAGE-----[ \t]*\r?$/m);
  if (start < 0) throw new PgpError('unexpected', 'this is not a clear-signed text');
  const lines = input.slice(start).replace(/\r\n?/g, '\n').split('\n');
  let i = 1;
  const hashes: number[] = [];
  for (; i < lines.length && lines[i].trim() !== ''; i++) {
    const m = /^Hash: (.+)$/.exec(lines[i].trim());
    if (!m) throw malformed('an unknown header in a clear-signed text');
    for (const name of m[1].split(',')) {
      const id = HASH_NAMES[name.trim().toUpperCase()];
      if (id === undefined) throw new PgpError('unsupported', `the hash ${name.trim()}`);
      hashes.push(id);
    }
  }
  i++;
  const textLinesOut: string[] = [];
  for (; i < lines.length; i++) {
    const line = lines[i];
    if (line.trimEnd() === BEGIN_SIGNATURE) break;
    textLinesOut.push(trimLine(line.startsWith('- ') ? line.slice(2) : line));
  }
  if (i >= lines.length) throw malformed('the clear-signed text has no signature');
  // Where the signature armor starts in the original input: a whole line, not the escaped
  // "- -----BEGIN PGP SIGNATURE-----" a text may hold.
  const sigAt = start + input.slice(start).search(/^-----BEGIN PGP SIGNATURE-----[ \t]*\r?$/m);
  const blocks = dearmorAll(input.slice(sigAt));
  if (!blocks.length || blocks[0].type !== 'SIGNATURE') throw malformed('the clear-signed text has no signature');
  const signatures = readPackets(blocks[0].data)
    .filter((p) => p.tag === TAG.SIGNATURE)
    .map((p) => readSignature(p.body));
  if (!signatures.length) throw malformed('the clear-signed text has no signature');
  // A Hash header must name the hash each signature uses: it keeps a weaker hash from being
  // swapped in under the same text.
  if (hashes.length) for (const s of signatures) if (s.version === 4 && !hashes.includes(s.hash)) throw malformed('a signature uses a hash its text does not announce');
  return { text: textLinesOut.join('\n'), signed: signedBytes(textLinesOut), signatures, end: sigAt + blocks[0].end };
}
