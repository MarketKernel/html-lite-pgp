// The file container (Task.md §5.1): the whole keyring in one file, encrypted with a password
// — an ordinary OpenPGP message (SKESK v4, AES-256, SEIPD v1) whose literal data is the keys
// one after another, secret parts still under their own passphrases. GnuPG opens it itself:
//
//   gpg -d keys.gpg | gpg --import --import-options import-local-sigs

import { SYM } from './algorithms.ts';
import { concat } from './crypto/util.ts';
import { PgpError } from './errors.ts';
import { equalBytes } from './bytes.ts';
import { readLiteral, writeLiteral } from './literal.ts';
import { TAG, readPackets, writePacket } from './packets.ts';
import { decryptSeipd, encryptSeipd } from './seipd.ts';
import { makeSkesk, openSkesk, readSkesk } from './skesk.ts';
import { parseCerts, writeCert } from './keys.ts';
import type { Cert } from './keys.ts';
import { encryptMessage, openMessage } from './message.ts';
import { phraseLongEnough } from './phrase.ts';

export const CONTAINER_NAME = 'html-simple-pgp-keys.gpg';

/** A password for a file that may be tried offline without limit: five different words, or 16 characters. */
export const containerPasswordStrong = (password: string): boolean => phraseLongEnough(password) || [...password].length >= 16;

export async function writeContainer(certs: Cert[], password: string, random: (n: number) => Uint8Array, now: number, onProgress?: (done: number) => void): Promise<Uint8Array> {
  if (!containerPasswordStrong(password)) throw new PgpError('unexpected', 'the container needs a stronger password: five different words, or 16 characters');
  const data = concat(...certs.map((c) => writeCert(c, { secret: true, local: true })));
  return encryptMessage({ data, format: 'b', filename: 'keyring.gpg', recipients: [], password, now, random, onProgress });
}

export async function readContainer(bytes: Uint8Array, password: string, now: number): Promise<Cert[]> {
  const opened = await openMessage(bytes, { keyring: [], password, now });
  if (!opened.data.length) return [];
  return parseCerts(opened.data);
}

/**
 * An open container: its SKESK and the key the password gave. Saving again uses them both, so
 * the password is asked once per session and never kept — only the key derived from it, in
 * memory, as the agent keeps unlocked keys. Each save still gets a fresh random prefix.
 */
export interface ContainerSession {
  skesk: Uint8Array;
  cipher: number;
  key: Uint8Array;
}

export async function newContainerSession(password: string, random: (n: number) => Uint8Array): Promise<ContainerSession> {
  if (!containerPasswordStrong(password)) throw new PgpError('unexpected', 'the container needs a stronger password: five different words, or 16 characters');
  const made = await makeSkesk(password, random);
  return { skesk: made.body, cipher: SYM.AES256, key: made.sessionKey };
}

/** Opens a container file: its keys, and the session to save it again with (null if it cannot be reused). */
export async function openContainer(bytes: Uint8Array, password: string, now: number): Promise<{ certs: Cert[]; session: ContainerSession | null }> {
  const certs = await readContainer(bytes, password, now);
  const packets = readPackets(bytes).filter((p) => p.tag !== TAG.MARKER);
  const skesk = packets[0]?.tag === TAG.SKESK ? readSkesk(packets[0].body) : null;
  // A container whose password's key is the session key (as ours and `gpg -c`) can be saved
  // again with the same key; one that carries an encrypted session key would need a new one.
  if (!skesk || skesk.encrypted.length) return { certs, session: null };
  const opened = await openSkesk(skesk, password);
  return { certs, session: opened ? { skesk: packets[0].body, cipher: opened.cipher, key: opened.key } : null };
}

/** The SKESK packet that opens a container file — what tells one container from another — or null. */
export function containerSkesk(bytes: Uint8Array): Uint8Array | null {
  try {
    const first = readPackets(bytes).find((p) => p.tag !== TAG.MARKER);
    return first?.tag === TAG.SKESK ? first.body : null;
  } catch {
    return null;
  }
}

/**
 * Opens a container with its session — the key its password gave, kept wrapped by a passkey
 * or a security key (Task.md §5.2) — instead of the password. The file must still be the one
 * the session belongs to: the same SKESK first, then the encrypted data, whose MDC decides.
 */
export async function openContainerWith(bytes: Uint8Array, session: ContainerSession): Promise<Cert[]> {
  const packets = readPackets(bytes).filter((p) => p.tag !== TAG.MARKER);
  if (packets.length !== 2 || packets[0].tag !== TAG.SKESK || packets[1].tag !== TAG.SEIPD) throw new PgpError('unexpected', 'this is not a container this program saved');
  if (!equalBytes(packets[0].body, session.skesk)) throw new PgpError('bad-passphrase', 'the container was saved with another password');
  const inner = readPackets(await decryptSeipd({ cipher: session.cipher, key: session.key }, packets[1].body));
  if (inner.length !== 1 || inner[0].tag !== TAG.LITERAL) throw new PgpError('unexpected', 'this is not a container this program saved');
  const data = readLiteral(inner[0].body).data;
  return data.length ? parseCerts(data) : [];
}

export async function saveContainer(session: ContainerSession, certs: Cert[], random: (n: number) => Uint8Array, now: number): Promise<Uint8Array> {
  const data = concat(...certs.map((c) => writeCert(c, { secret: true, local: true })));
  const literal = writePacket(TAG.LITERAL, writeLiteral({ format: 'b', filename: 'keyring.gpg', date: now, data }));
  const seipd = await encryptSeipd({ cipher: session.cipher, key: session.key }, literal, random);
  return concat(writePacket(TAG.SKESK, session.skesk), writePacket(TAG.SEIPD, seipd));
}
