// Symmetrically Encrypted Integrity Protected Data, version 1 (RFC 4880 §5.13): AES in CFB
// over a random prefix, the data, and a Modification Detection Code — SHA-1 of all of it. The
// one data format every GnuPG and Kleopatra reads.
//
// Decryption hands nothing back until the MDC has matched: a changed or truncated message is
// an error, with no part of its plaintext. The "quick check" bytes of the prefix are not used
// to tell a wrong key from a damaged message (that difference is what the Mister–Zuccherato
// attack feeds on): every failure is the same 'integrity' error.

import { aesKeySize } from './algorithms.ts';
import { cfbDecryptAsync, cfbEncryptAsync } from './crypto/cfb.ts';
import { SHA1 } from './crypto/sha1.ts';
import { concat, constantTimeEqual, wipe } from './crypto/util.ts';
import { PgpError } from './errors.ts';
import type { SessionKey } from './ecdh.ts';

const MDC_HEADER = Uint8Array.of(0xd3, 0x14);

export async function encryptSeipd(session: SessionKey, plaintext: Uint8Array, random: (n: number) => Uint8Array, onProgress?: (done: number) => void): Promise<Uint8Array> {
  const prefix = random(16);
  const head = concat(prefix, prefix.subarray(14, 16));
  const mdc = SHA1.create().update(head).update(plaintext).update(MDC_HEADER).digest();
  const plain = concat(head, plaintext, MDC_HEADER, mdc);
  const encrypted = await cfbEncryptAsync(session.key, plain, onProgress);
  wipe(plain, prefix, head);
  return concat(Uint8Array.of(1), encrypted);
}

/** The data inside, after the MDC matched; an 'integrity' PgpError otherwise. */
export async function decryptSeipd(session: SessionKey, body: Uint8Array, onProgress?: (done: number) => void): Promise<Uint8Array> {
  if (body.length < 1 || body[0] !== 1) throw new PgpError('unsupported', `encrypted data of version ${body[0]}`);
  const size = aesKeySize(session.cipher);
  if (!size || session.key.length !== size) throw new PgpError('unsupported', 'the session key is not for AES-128 or AES-256');
  const data = body.subarray(1);
  const fail = () => new PgpError('integrity', 'the message was changed or damaged, or it is not for this key');
  if (data.length < 18 + 22) throw fail();
  const plain = await cfbDecryptAsync(session.key, data, onProgress);
  const end = plain.length - 22;
  const mdc = SHA1.create().update(plain.subarray(0, end + 2)).digest();
  const ok = plain[end] === 0xd3 && plain[end + 1] === 0x14 && constantTimeEqual(mdc, plain.subarray(end + 2));
  if (!ok) {
    wipe(plain);
    throw fail();
  }
  const inner = plain.slice(18, end);
  wipe(plain);
  return inner;
}
