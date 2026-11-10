// OpenPGP messages, RFC 4880 §11.3, as far as the profile goes (Task.md §7.5): made —
// literal data, signed or not, encrypted to recipients and/or a password — and opened.
//
// Opening reads this grammar and nothing else:
//
//   Message := (PKESK | SKESK)+ SEIPDv1  |  Signed  |  Compressed(Signed)
//   Signed  := OPS+ Literal Signature+  |  Signature+ Literal  |  Literal
//   inside SEIPDv1: Signed | Compressed(Signed); Marker and Padding packets are skipped.
//
// The plaintext comes back only when the whole message held together: MDC checked, every
// packet read. Signatures are reported, each with its own status; a bad one does not hide the
// text, it says so.

import { COMPRESSION, HASH, PUBKEY, SYM } from './algorithms.ts';
import { Reader, Writer, equalBytes } from './bytes.ts';
import { concat, wipe } from './crypto/util.ts';
import { addressedTo, makePkesk, openPkesk, readPkesk } from './ecdh.ts';
import type { Pkesk, SessionKey } from './ecdh.ts';
import { PgpError, malformed, unsupported } from './errors.ts';
import { InflateError, inflateRaw, inflateZlib } from './inflate.ts';
import type { Cert, KeyPacket } from './keys.ts';
import { readLiteral, writeLiteral } from './literal.ts';
import type { Literal } from './literal.ts';
import { TAG, readPackets, writePacket } from './packets.ts';
import type { Packet } from './packets.ts';
import { decryptSeipd, encryptSeipd } from './seipd.ts';
import { makeSkesk, openSkesk, readSkesk } from './skesk.ts';
import { SIG, intendedRecipients, makeSignature, readSignature } from './signature.ts';
import type { Signature } from './signature.ts';
import { canonicalLineEndings, checkSignature, intendedFor } from './verify.ts';
import type { SignatureCheck, SigningKey } from './verify.ts';

/** The most a message may unpack to: the same as the largest file we take. */
export const MAX_DATA = 256 * 1024 * 1024;

export interface NewMessage {
  data: Uint8Array;
  /** 'u' for text, 'b' for a file; the name goes with a file. */
  format: 'b' | 'u';
  filename?: string;
  /** The encryption subkeys of the recipients, with their certificates (for the intended-recipient subpackets). */
  recipients: { cert: Cert; key: KeyPacket }[];
  password?: string;
  signer?: SigningKey;
  now: number;
  random: (n: number) => Uint8Array;
  onProgress?: (done: number) => void;
}

/** One-Pass Signature packet, version 3. */
function onePass(signer: SigningKey): Uint8Array {
  return new Writer().byte(3).byte(SIG.BINARY).byte(HASH.SHA512).byte(PUBKEY.EDDSA).bytes(signer.key.keyId).byte(1).finish();
}

/** The inside of a message: the literal data, signed if there is a signer. */
function signedContent(m: NewMessage): Uint8Array {
  const literal = writePacket(TAG.LITERAL, writeLiteral({ format: m.format, filename: m.filename ?? '', date: m.now, data: m.data }));
  if (!m.signer) return literal;
  const extra = intendedFor(m.recipients.map((r) => r.cert.primary));
  const sig = makeSignature(SIG.BINARY, { seed: m.signer.seed, fingerprint: m.signer.key.fingerprint }, [m.data], m.now, extra);
  return concat(writePacket(TAG.ONE_PASS, onePass(m.signer)), literal, writePacket(TAG.SIGNATURE, sig));
}

/** A message signed but not encrypted (inline, as `gpg --sign` without compression). */
export function signMessage(m: Omit<NewMessage, 'recipients' | 'password' | 'random'> & { signer: SigningKey }): Uint8Array {
  return signedContent({ ...m, recipients: [], random: () => new Uint8Array(0) });
}

/** An encrypted message: to every recipient, and to the password if there is one. */
export async function encryptMessage(m: NewMessage): Promise<Uint8Array> {
  if (!m.recipients.length && !m.password) throw new PgpError('unexpected', 'a message needs a recipient or a password');
  const parts: Uint8Array[] = [];
  let sessionKey: Uint8Array;
  if (m.password && !m.recipients.length) {
    const skesk = await makeSkesk(m.password, m.random);
    parts.push(writePacket(TAG.SKESK, skesk.body));
    sessionKey = skesk.sessionKey;
  } else {
    sessionKey = m.random(32);
    for (const r of m.recipients) parts.push(writePacket(TAG.PKESK, makePkesk(r.key, sessionKey, m.random)));
    if (m.password) parts.push(writePacket(TAG.SKESK, (await makeSkesk(m.password, m.random, sessionKey)).body));
  }
  const inner = signedContent(m);
  const seipd = await encryptSeipd({ cipher: SYM.AES256, key: sessionKey }, inner, m.random, m.onProgress);
  wipe(sessionKey, inner);
  parts.push(writePacket(TAG.SEIPD, seipd));
  return concat(...parts);
}

// ---- Opening --------------------------------------------------------------------------------

const skippable = (p: Packet) => p.tag === TAG.MARKER || p.tag === TAG.PADDING;

export interface Recipients {
  /** Key IDs the message names (hidden ones are all zeros). */
  keyIds: Uint8Array[];
  hidden: boolean;
  /** The message can also be opened with a password. */
  password: boolean;
}

/** Who can open an encrypted message — to know which key to unlock before opening it. Null if it is not encrypted. */
export function recipientsOf(data: Uint8Array): Recipients | null {
  const packets = readPackets(data).filter((p) => !skippable(p));
  if (!packets.length || (packets[0].tag !== TAG.PKESK && packets[0].tag !== TAG.SKESK)) return null;
  const out: Recipients = { keyIds: [], hidden: false, password: false };
  for (const p of packets) {
    if (p.tag === TAG.PKESK) {
      const k = readPkesk(p.body);
      if (k.algorithm === PUBKEY.ECDH && k.keyId.every((b) => b === 0)) out.hidden = true;
      else out.keyIds.push(k.keyId);
    } else if (p.tag === TAG.SKESK) {
      out.password = true;
    } else break;
  }
  return out;
}

export interface Decryptor {
  /** Our certificate and its unlocked encryption subkey. */
  cert: Cert;
  key: KeyPacket;
  scalar: Uint8Array;
}

export interface OpenOptions {
  /** Every key whose signatures may be checked. */
  keyring: Cert[];
  /** Our unlocked encryption subkeys. */
  decryptors?: Decryptor[];
  password?: string;
  now: number;
  limit?: number;
  onProgress?: (done: number) => void;
}

export interface Opened {
  data: Uint8Array;
  format: Literal['format'];
  filename: string;
  date: number;
  encrypted: boolean;
  /** Whose key opened it (when it was encrypted to a key). */
  openedBy: Cert | null;
  signatures: SignatureCheck[];
}

/** Opens a binary message: decrypts if it is encrypted, checks its signatures, returns the data. */
export async function openMessage(data: Uint8Array, options: OpenOptions): Promise<Opened> {
  const limit = options.limit ?? MAX_DATA;
  const packets = readPackets(data).filter((p) => !skippable(p));
  if (!packets.length) throw malformed('an empty message');
  const first = packets[0].tag;
  if (first !== TAG.PKESK && first !== TAG.SKESK) {
    return { ...readSigned(packets, options, limit, null), encrypted: false, openedBy: null };
  }
  const esks: Packet[] = [];
  let i = 0;
  for (; i < packets.length && (packets[i].tag === TAG.PKESK || packets[i].tag === TAG.SKESK); i++) esks.push(packets[i]);
  const body = packets[i];
  if (!body) throw malformed('an encrypted message without its data');
  if (body.tag === TAG.AEAD) throw unsupported('a message in OCB (GnuPG writes this to keys that announce AEAD)');
  if (body.tag === TAG.SED) throw unsupported('a message without integrity protection');
  if (body.tag !== TAG.SEIPD) throw malformed('an encrypted message whose data is not where it should be');
  if (i + 1 !== packets.length) throw malformed('something after the encrypted data');

  let session: SessionKey | null = null;
  let openedBy: Cert | null = null;
  const pkesks: Pkesk[] = esks.filter((p) => p.tag === TAG.PKESK).map((p) => readPkesk(p.body));
  for (const d of options.decryptors ?? []) {
    for (const k of pkesks) {
      if (session || !addressedTo(k, d.key)) continue;
      const s = openPkesk(k, d.key, d.scalar);
      if (s) {
        session = s;
        openedBy = d.cert;
      }
    }
  }
  let passwordTried = false;
  if (!session && options.password) {
    for (const p of esks.filter((p) => p.tag === TAG.SKESK)) {
      const skesk = readSkesk(p.body);
      if (!skesk) continue;
      passwordTried = true;
      const s = await openSkesk(skesk, options.password);
      if (!s) continue;
      try {
        const inner = await decryptSeipd(s, body.body, options.onProgress);
        return finish(inner, s, null);
      } catch (error) {
        // The wrong password ends here too: its key does not pass the MDC.
        if (!(error instanceof PgpError && error.code === 'integrity')) throw error;
      } finally {
        wipe(s.key);
      }
    }
    if (passwordTried) throw new PgpError('bad-passphrase', 'the password does not open this message');
  }
  if (!session) throw new PgpError('no-key', 'none of your keys can open this message');
  const inner = await decryptSeipd(session, body.body, options.onProgress);
  wipe(session.key);
  return finish(inner, session, openedBy);

  function finish(inner: Uint8Array, _s: SessionKey, by: Cert | null): Opened {
    const innerPackets = readPackets(inner).filter((p) => !skippable(p));
    return { ...readSigned(innerPackets, options, limit, by), encrypted: true, openedBy: by };
  }
}

function decompress(body: Uint8Array, limit: number): Uint8Array {
  const r = new Reader(body);
  const algorithm = r.byte('the compression algorithm');
  const rest = r.rest();
  try {
    if (algorithm === COMPRESSION.NONE) return rest;
    if (algorithm === COMPRESSION.ZIP) return inflateRaw(rest, limit);
    if (algorithm === COMPRESSION.ZLIB) return inflateZlib(rest, limit);
  } catch (error) {
    if (error instanceof InflateError) throw new PgpError(/limit/.test(error.message) ? 'too-large' : 'malformed', `compressed data: ${error.message}`);
    throw error;
  }
  throw unsupported(algorithm === COMPRESSION.BZIP2 ? 'BZip2 compression' : `compression ${algorithm}`);
}

function readSigned(packets: Packet[], options: OpenOptions, limit: number, openedBy: Cert | null): Omit<Opened, 'encrypted' | 'openedBy'> {
  if (packets.length === 1 && packets[0].tag === TAG.COMPRESSED) {
    const inner = readPackets(decompress(packets[0].body, limit)).filter((p) => !skippable(p));
    if (inner.some((p) => p.tag === TAG.COMPRESSED)) throw malformed('compressed data inside compressed data');
    return readSigned(inner, options, limit, openedBy);
  }
  const literals = packets.filter((p) => p.tag === TAG.LITERAL);
  if (literals.length !== 1) throw new PgpError(literals.length ? 'malformed' : 'unexpected', literals.length ? 'more than one piece of literal data' : 'this is not a message');
  const at = packets.indexOf(literals[0]);
  const before = packets.slice(0, at);
  const after = packets.slice(at + 1);
  let sigs: Signature[];
  if (before.length && before.every((p) => p.tag === TAG.ONE_PASS)) {
    if (after.length !== before.length || !after.every((p) => p.tag === TAG.SIGNATURE)) throw malformed('one-pass signatures without their signatures');
    sigs = after.map((p) => readSignature(p.body));
  } else if (!after.length && before.every((p) => p.tag === TAG.SIGNATURE)) {
    sigs = before.map((p) => readSignature(p.body));
  } else {
    throw malformed('packets where a message does not have them');
  }
  const literal = readLiteral(literals[0].body);
  if (literal.data.length > limit) throw new PgpError('too-large', 'the message is larger than the limit');
  const signatures = sigs.map((sig) => {
    const signed = sig.type === SIG.TEXT ? canonicalLineEndings(literal.data) : literal.data;
    const check = checkSignature(sig, [signed], options.keyring, options.now);
    // A signature meant for other recipients was lifted from another message: not good here.
    if (check.status === 'good' && openedBy && sig.version === 4) {
      const intended = intendedRecipients(sig);
      if (intended.length && !intended.some((f) => equalBytes(f, openedBy.primary.fingerprint))) return { ...check, status: 'bad' as const };
    }
    return check;
  });
  return { data: literal.data, format: literal.format, filename: literal.filename, date: literal.date, signatures };
}
