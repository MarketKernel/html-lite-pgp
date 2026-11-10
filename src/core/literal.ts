// Literal data packets, RFC 4880 §5.9: the plaintext with a format, a file name and a date.
// The name comes from whoever made the message: it is cleaned before anything uses it.

import { Reader, Writer, utf8 } from './bytes.ts';

export interface Literal {
  format: 'b' | 'u' | 't';
  filename: string;
  date: number;
  data: Uint8Array;
}

export function readLiteral(body: Uint8Array): Literal {
  const r = new Reader(body);
  const f = String.fromCharCode(r.byte('the literal format'));
  const format = f === 'u' || f === 't' ? f : 'b';
  const name = r.bytes(r.byte('the file name length'), 'the file name');
  const date = r.u32('the literal date');
  return { format, filename: safeFilename(new TextDecoder().decode(name)), date, data: r.rest() };
}

export function writeLiteral(literal: Omit<Literal, 'date'> & { date?: number }): Uint8Array {
  // At most 255 bytes, cut at a character boundary.
  let kept = '';
  for (const ch of literal.filename) {
    if (utf8(kept + ch).length > 255) break;
    kept += ch;
  }
  const name = utf8(kept);
  return new Writer()
    .byte(literal.format.charCodeAt(0))
    .byte(name.length)
    .bytes(name)
    .u32(literal.date ?? 0)
    .bytes(literal.data)
    .finish();
}

/**
 * A file name from a message, made safe to save under: no directories, no control or
 * direction-changing characters, no leading dots, not too long. GnuPG's "_CONSOLE" (show,
 * do not save) becomes no name.
 */
export function safeFilename(name: string): string {
  if (name === '_CONSOLE') return '';
  let s = name.replace(/^.*[\\/]/, '');
  s = s.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿<>:"|?*]/g, '');
  s = s.replace(/^[.\s]+/, '').replace(/[.\s]+$/, '');
  if (s.length > 200) s = s.slice(0, 200);
  return s;
}
