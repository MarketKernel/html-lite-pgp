// The top of the core: what the interface calls. Telling what a piece of input is, opening
// it whatever its form (armored, binary, clear-signed), checking detached signatures, reading
// revocation certificates — over the modules below, which each do one part.

import { dearmor, dearmorAll, looksArmored } from './armor.ts';
import type { ArmorType } from './armor.ts';
import { readCleartext, looksClearSigned } from './cleartext.ts';
import { PgpError, malformed } from './errors.ts';
import { parseCerts } from './keys.ts';
import type { Cert } from './keys.ts';
import { openMessage } from './message.ts';
import type { OpenOptions, Opened } from './message.ts';
import { TAG, readPackets } from './packets.ts';
import { SIG, readSignature } from './signature.ts';
import type { Signature } from './signature.ts';
import { canonicalLineEndings, checkSignature } from './verify.ts';
import type { SignatureCheck } from './verify.ts';

export type Kind = 'public-keys' | 'secret-keys' | 'encrypted' | 'signed' | 'clear-signed' | 'signature' | 'revocation' | 'unknown';

const decoder = new TextDecoder('utf-8', { fatal: false });

/** Text, if the bytes are (mostly) text: armor and clear-signed texts arrive as files too. */
function asText(input: Uint8Array | string): string | null {
  if (typeof input === 'string') return input;
  const head = input.subarray(0, 4096);
  if (head.length && head[0] & 0x80) return null;
  return decoder.decode(input);
}

/**
 * GnuPG's revocation certificates (openpgp-revocs.d/*.rev) put a ":" before the BEGIN line, so
 * that importing the file by mistake does nothing. Importing it on purpose takes it off.
 */
export const unguardRevocation = (text: string): string => text.replace(/^:(-----BEGIN PGP PUBLIC KEY BLOCK-----)/m, '$1');

/** The binary packets of the input, armored or not, with the armor's type if it had one. */
export function binaryOf(input: Uint8Array | string): { data: Uint8Array; armor: ArmorType | null } {
  const text = asText(input);
  if (text !== null && looksArmored(unguardRevocation(text))) {
    const block = dearmor(unguardRevocation(text));
    return { data: block.data, armor: block.type };
  }
  if (typeof input === 'string') throw new PgpError('unexpected', 'there is no OpenPGP data in the text');
  return { data: input, armor: null };
}

/** What the input is, by its armor or its first packets — without decrypting anything. */
export function classify(input: Uint8Array | string): Kind {
  try {
    const text = asText(input);
    if (text !== null && looksClearSigned(text) && !/^-----BEGIN PGP (MESSAGE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK)-----/m.test(text.slice(0, text.search(/^-----BEGIN PGP SIGNED MESSAGE-----/m)))) return 'clear-signed';
    const { data } = binaryOf(input);
    const packets = readPackets(data).filter((p) => p.tag !== TAG.MARKER && p.tag !== TAG.PADDING);
    const first = packets[0]?.tag;
    if (first === TAG.PUBLIC_KEY) return 'public-keys';
    if (first === TAG.SECRET_KEY) return 'secret-keys';
    if (first === TAG.PKESK || first === TAG.SKESK) return 'encrypted';
    if (first === TAG.ONE_PASS || first === TAG.LITERAL || first === TAG.COMPRESSED) return 'signed';
    if (first === TAG.SIGNATURE) {
      if (packets.length === 1 && readSignature(packets[0].body).type === SIG.KEY_REVOCATION) return 'revocation';
      return packets.every((p) => p.tag === TAG.SIGNATURE) ? 'signature' : 'signed';
    }
    return 'unknown';
  } catch (error) {
    if (error instanceof PgpError) return 'unknown';
    throw error;
  }
}

/** Every key in the input — one armored block or several, or binary. */
export function readKeys(input: Uint8Array | string): Cert[] {
  const text = asText(input);
  if (text !== null && looksArmored(text)) {
    const certs: Cert[] = [];
    for (const block of dearmorAll(text)) {
      if (block.type !== 'PUBLIC KEY BLOCK' && block.type !== 'PRIVATE KEY BLOCK') continue;
      certs.push(...parseCerts(block.data));
    }
    if (!certs.length) throw new PgpError('unexpected', 'there is no key here');
    return certs;
  }
  return parseCerts(binaryOf(input).data);
}

/** A revocation certificate's signature (GnuPG's .rev or ours). */
export function readRevocation(input: Uint8Array | string): Signature {
  const { data } = binaryOf(input);
  const packets = readPackets(data);
  if (packets.length !== 1 || packets[0].tag !== TAG.SIGNATURE) throw new PgpError('unexpected', 'this is not a revocation certificate');
  const sig = readSignature(packets[0].body);
  if (sig.type !== SIG.KEY_REVOCATION) throw new PgpError('unexpected', 'this is not a revocation certificate');
  return sig;
}

export interface OpenedText extends Opened {
  /** A clear-signed text, as opposed to a message. */
  clearSigned: boolean;
}

/** Opens what a person pastes or drops: a message, armored or binary, or a clear-signed text. */
export async function open(input: Uint8Array | string, options: OpenOptions): Promise<OpenedText> {
  const text = asText(input);
  if (text !== null && classify(text) === 'clear-signed') {
    const clear = readCleartext(text);
    const signatures = clear.signatures.map((sig) => checkSignature(sig, [clear.signed], options.keyring, options.now));
    return { data: new TextEncoder().encode(clear.text), format: 'u', filename: '', date: 0, encrypted: false, openedBy: null, signatures, clearSigned: true };
  }
  const { data, armor } = binaryOf(input);
  if (armor && armor !== 'MESSAGE') throw new PgpError('unexpected', armor === 'SIGNATURE' ? 'a detached signature: it needs the file it signs' : 'keys, not a message');
  return { ...(await openMessage(data, options)), clearSigned: false };
}

/** Checks a detached signature (armored or binary) over a file's bytes. */
export function verifyDetached(signature: Uint8Array | string, data: Uint8Array, keyring: Cert[], now: number): SignatureCheck[] {
  const { data: bytes } = binaryOf(signature);
  const packets = readPackets(bytes);
  if (!packets.length || !packets.every((p) => p.tag === TAG.SIGNATURE)) throw malformed('this is not a detached signature');
  return packets.map((p) => {
    const sig = readSignature(p.body);
    return checkSignature(sig, [sig.type === SIG.TEXT ? canonicalLineEndings(data) : data], keyring, now);
  });
}
