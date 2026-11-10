// Symmetric-key encrypted session keys, RFC 4880 §5.3 (version 4): a password instead of a
// recipient. The file container is one of these (Task.md §5.1), as `gpg -c` writes it.

import { SYM, aesKeySize } from './algorithms.ts';
import { Reader, Writer, utf8 } from './bytes.ts';
import { cfbDecrypt, cfbEncrypt } from './crypto/cfb.ts';
import { concat, wipe } from './crypto/util.ts';
import { HASH } from './algorithms.ts';
import { PgpError, unsupported } from './errors.ts';
import { deriveKey, readS2K, writeS2K } from './s2k.ts';
import type { S2K } from './s2k.ts';
import type { SessionKey } from './ecdh.ts';

export interface Skesk {
  cipher: number;
  s2k: S2K;
  /** The session key encrypted under the password's key, or empty: the password's key is it. */
  encrypted: Uint8Array;
}

export function readSkesk(body: Uint8Array): Skesk | null {
  const r = new Reader(body);
  if (r.byte('the SKESK version') !== 4) return null;
  const cipher = r.byte('the cipher');
  if (!aesKeySize(cipher)) throw unsupported(`a password-encrypted message with cipher ${cipher}`);
  const s2k = readS2K(r);
  return { cipher, s2k, encrypted: r.rest() };
}

/** The session key, or null when the password is not this one (we only know later, by the MDC). */
export async function openSkesk(skesk: Skesk, password: string, onProgress?: (done: number) => void): Promise<SessionKey | null> {
  const key = await deriveKey(skesk.s2k, utf8(password), aesKeySize(skesk.cipher)!, onProgress);
  if (!skesk.encrypted.length) return { cipher: skesk.cipher, key };
  const plain = cfbDecrypt(key, skesk.encrypted);
  wipe(key);
  const size = aesKeySize(plain[0]);
  if (!size || plain.length !== 1 + size) {
    wipe(plain);
    return null;
  }
  return { cipher: plain[0], key: plain.slice(1) };
}

/**
 * A SKESK for `password`. Without `sessionKey` the password's key is the session key (as
 * `gpg -c` does); with one (a message also for recipients), it carries that key encrypted.
 */
export async function makeSkesk(password: string, random: (n: number) => Uint8Array, sessionKey?: Uint8Array, countByte = 0xff): Promise<{ body: Uint8Array; sessionKey: Uint8Array }> {
  if (!password) throw new PgpError('unexpected', 'an empty password');
  const s2k: S2K = { type: 3, hash: HASH.SHA256, salt: random(8), countByte };
  const key = await deriveKey(s2k, utf8(password), 32);
  const w = new Writer().byte(4).byte(SYM.AES256);
  writeS2K(w, s2k);
  if (!sessionKey) return { body: w.finish(), sessionKey: key };
  w.bytes(cfbEncrypt(key, concat(Uint8Array.of(SYM.AES256), sessionKey)));
  wipe(key);
  return { body: w.finish(), sessionKey };
}
