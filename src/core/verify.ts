// Signatures over data — files, texts, messages — made and checked against a keyring.
//
// A check answers with one status: good, bad (the data or the signature was changed), made by
// a key we do not have, by a revoked key, by a key that had expired when it signed, or
// outside the profile (another algorithm, a weak hash). "Good" says the key signed it; whether
// the key is who it claims to be is the keyring's question (verified or not).

import { equalBytes } from './bytes.ts';
import { writeCleartext, textLines, signedBytes } from './cleartext.ts';
import { PgpError } from './errors.ts';
import { CLOCK_SKEW, keyState } from './keys.ts';
import type { Cert, KeyPacket } from './keys.ts';
import {
  SIG, SUB, created, issuerFingerprint, issuerKeyId, makeSignature, signatureExpires, subpacket, supported, verifySignature,
} from './signature.ts';
import type { Signature } from './signature.ts';
import { concat } from './crypto/util.ts';
import { TAG, writePacket } from './packets.ts';

export type SignatureStatus = 'good' | 'bad' | 'unknown-key' | 'key-revoked' | 'key-expired' | 'unsupported';

export interface SignatureCheck {
  status: SignatureStatus;
  /** When the signature says it was made. */
  created: number | null;
  /** The signer's key ID as the signature names it (hex shows it when the key is unknown). */
  keyId: Uint8Array | null;
  /** The certificate that made it, when we have it. */
  cert: Cert | null;
  /** The key (primary or subkey) that made it. */
  key: KeyPacket | null;
}

/** Text signatures (type 0x01) over data: every line break is CR LF. */
export function canonicalLineEndings(data: Uint8Array): Uint8Array {
  let extra = 0;
  for (let i = 0; i < data.length; i++) if (data[i] === 10 && (i === 0 || data[i - 1] !== 13)) extra++;
  if (!extra) return data;
  const out = new Uint8Array(data.length + extra);
  for (let i = 0, o = 0; i < data.length; i++) {
    if (data[i] === 10 && (i === 0 || data[i - 1] !== 13)) out[o++] = 13;
    out[o++] = data[i];
  }
  return out;
}

const matches = (sig: Signature, k: KeyPacket): boolean => {
  const fpr = issuerFingerprint(sig);
  if (fpr) return equalBytes(fpr, k.fingerprint);
  const id = issuerKeyId(sig);
  return !!id && equalBytes(id, k.keyId);
};

/**
 * Checks `sig` over `data` (already canonical for its type — the caller knows whether the data
 * is a cleartext, a literal packet's contents or a file).
 */
export function checkSignature(sig: Signature, data: Uint8Array[], keyring: Cert[], now: number): SignatureCheck {
  const keyId = sig.version === 4 ? issuerKeyId(sig) : null;
  const when = sig.version === 4 ? safeCreated(sig) : null;
  const result = (status: SignatureStatus, cert: Cert | null = null, key: KeyPacket | null = null): SignatureCheck => ({ status, created: when, keyId, cert, key });
  // Find the key first: "unknown key" says more than "unsupported" when we do not have it anyway.
  let found: { cert: Cert; key: KeyPacket } | null = null;
  if (sig.version === 4) {
    for (const cert of keyring) {
      const key = [cert.primary, ...cert.subkeys.map((s) => s.key)].find((k) => matches(sig, k));
      if (key) {
        found = { cert, key };
        break;
      }
    }
  }
  if (!supported(sig) || (sig.type !== SIG.BINARY && sig.type !== SIG.TEXT)) return result('unsupported', found?.cert ?? null, found?.key ?? null);
  if (!found) return result('unknown-key');
  const { cert, key } = found;
  const state = keyState(cert, now);
  if (!state.supported || !key.point || key.curve !== 'ed25519') return result('unsupported', cert, key);
  if (when === null || when > now + CLOCK_SKEW) return result('bad', cert, key);
  const expiresIn = signatureExpires(sig);
  if (expiresIn && when + expiresIn <= now) return result('bad', cert, key);
  if (!verifySignature(sig, key.point, data)) return result('bad', cert, key);
  // The signature is the key's. Was the key entitled to make it?
  if (!state.signing.includes(key)) return result('bad', cert, key);
  if (state.revoked) return result('key-revoked', cert, key);
  if (state.expires !== null && when >= state.expires) return result('key-expired', cert, key);
  const sub = state.subkeys.find((s) => s.key === key);
  if (sub && sub.expires !== null && when >= sub.expires) return result('key-expired', cert, key);
  if (when < key.created) return result('bad', cert, key);
  return result('good', cert, key);
}

function safeCreated(sig: Signature): number | null {
  try {
    return created(sig);
  } catch (error) {
    if (error instanceof PgpError) return null;
    throw error;
  }
}

export interface SigningKey {
  /** The certificate whose key signs. */
  cert: Cert;
  /** The key that signs — the primary key or a signing subkey — and its Ed25519 seed. */
  key: KeyPacket;
  seed: Uint8Array;
}

/** A detached binary signature (type 0x00) over a file's bytes: the signature packet's body. */
export function signData(data: Uint8Array, signer: SigningKey, now: number, extra: Uint8Array[] = []): Uint8Array {
  return makeSignature(SIG.BINARY, { seed: signer.seed, fingerprint: signer.key.fingerprint }, [data], now, extra);
}

/** A text clear-signed by `signer`. */
export function signCleartext(text: string, signer: SigningKey, now: number): string {
  const lines = textLines(text);
  const sig = makeSignature(SIG.TEXT, { seed: signer.seed, fingerprint: signer.key.fingerprint }, [signedBytes(lines)], now);
  return writeCleartext(text, wrapSignature(sig));
}

/** A signature packet around a signature body. */
export const wrapSignature = (body: Uint8Array): Uint8Array => writePacket(TAG.SIGNATURE, body);

/** Intended Recipient Fingerprint subpackets, for a signature inside an encrypted message. */
export const intendedFor = (recipients: KeyPacket[]): Uint8Array[] =>
  recipients.map((k) => subpacket(SUB.INTENDED_RECIPIENT, concat(Uint8Array.of(4), k.fingerprint)));

