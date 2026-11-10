// Making a key pair (Task.md §1, §4): the secrets from the chosen source of randomness or
// from a passphrase, the public key with its self-signatures, the secret parts protected,
// and the revocation certificate made at the same time.

import { armor } from './armor.ts';
import { equalBytes } from './bytes.ts';
import { ed25519PublicKey } from './crypto/ed25519.ts';
import { wipe } from './crypto/util.ts';
import { clamp, x25519Base } from './crypto/x25519.ts';
import { PgpError } from './errors.ts';
import { keyState, makeCert, revocationSignature, REASON } from './keys.ts';
import type { Cert, KeyPacket } from './keys.ts';
import { TAG, writePacket } from './packets.ts';
import { dayStart, secretsFromPhrase } from './phrase.ts';
import { protectAll } from './secret.ts';
import type { Secret } from './secret.ts';

export function userIdOf(name: string, email: string): string {
  const n = name.trim();
  const e = email.trim();
  if (n && e) return `${n} <${e}>`;
  if (e) return `<${e}>`;
  if (n) return n;
  throw new PgpError('unexpected', 'a key needs a name or an address');
}

export type KeySource = { kind: 'random'; random: (n: number) => Uint8Array } | { kind: 'phrase'; phrase: string; day: string };

export interface GenerateSpec {
  name: string;
  email: string;
  passphrase: string;
  /** Seconds the key is valid; 0: no expiry. */
  expiresIn: number;
  source: KeySource;
  /** Bytes for salts and IVs: the same source as the key's when it is random, the chosen one otherwise. */
  random: (n: number) => Uint8Array;
  now: number;
  onProgress?: (stage: 'derive' | 'protect', done: number) => void;
}

export interface Generated {
  cert: Cert;
  /** A revocation certificate to keep apart from the key: if the key is lost or stolen, import it. */
  revocation: string;
}

/** A revocation certificate as text, guarded as GnuPG guards its own: importing it by mistake does nothing. */
export function revocationText(cert: Cert, signature: Uint8Array, userId: string): string {
  const block = armor('PUBLIC KEY BLOCK', writePacket(TAG.SIGNATURE, signature)).replace(/^-----BEGIN/, ':-----BEGIN');
  const fpr = Array.from(cert.primary.fingerprint, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return [
    `This is a revocation certificate for the OpenPGP key ${fpr}`,
    `of ${userId}.`,
    '',
    'Keep it apart from the key. If the key is lost or stolen, import this file (Simple PGP',
    'asks to confirm; in GnuPG, remove the colon before -----BEGIN first) and share the revoked',
    'public key: everyone who updates it stops using it.',
    '',
    block,
  ].join('\n');
}

export async function generate(spec: GenerateSpec): Promise<Generated> {
  const userId = userIdOf(spec.name, spec.email);
  let seed: Uint8Array;
  let scalar: Uint8Array;
  let created: number;
  if (spec.source.kind === 'phrase') {
    created = dayStart(spec.source.day);
    if (created > spec.now) throw new PgpError('unexpected', 'the date of a key cannot be in the future');
    const s = await secretsFromPhrase(spec.source.phrase, spec.email, spec.onProgress && ((d) => spec.onProgress!('derive', d)));
    seed = s.seed;
    scalar = s.scalar;
  } else {
    created = spec.now;
    seed = spec.source.random(32);
    scalar = clamp(spec.source.random(32));
  }
  const pub = makeCert({ seed, subkeyPoint: x25519Base(scalar), userId, created, expiresIn: spec.expiresIn, signedAt: spec.now });
  const secrets = new Map<KeyPacket, Secret>([
    [pub.primary, { kind: 'ed25519', seed }],
    [pub.subkeys[0].key, { kind: 'cv25519', scalar }],
  ]);
  const cert = await protectAll(pub, secrets, spec.passphrase, { random: spec.random, onProgress: spec.onProgress && ((d) => spec.onProgress!('protect', d)) });
  const rev = revocationSignature(pub, seed, REASON.NONE, '', spec.now);
  wipe(scalar);
  wipe(seed);
  if (!keyState(cert, spec.now).valid) throw new Error('the new key does not check out');
  return { cert, revocation: revocationText(cert, rev.body, userId) };
}

/**
 * Restores a key from its phrase. With the public key (from a file, from someone who has it)
 * the secrets are checked against it and joined to it, signatures and all; without, the key
 * is made again from the e-mail address and the day.
 */
export async function restore(spec: { phrase: string; email: string; day?: string; publicKey?: Cert; name?: string; passphrase: string; expiresIn?: number; random: (n: number) => Uint8Array; now: number; onProgress?: GenerateSpec['onProgress'] }): Promise<Generated> {
  if (!spec.publicKey) {
    if (!spec.day) throw new PgpError('unexpected', 'restoring without the public key needs the day the key was made');
    return generate({ name: spec.name ?? '', email: spec.email, passphrase: spec.passphrase, expiresIn: spec.expiresIn ?? 0, source: { kind: 'phrase', phrase: spec.phrase, day: spec.day }, random: spec.random, now: spec.now, onProgress: spec.onProgress });
  }
  const pub = spec.publicKey;
  const { seed, scalar } = await secretsFromPhrase(spec.phrase, spec.email, spec.onProgress && ((d) => spec.onProgress!('derive', d)));
  const sub = pub.subkeys.find((s) => s.key.curve === 'cv25519' && s.key.point && equalBytes(s.key.point, x25519Base(scalar)));
  if (!pub.primary.point || !equalBytes(pub.primary.point, ed25519PublicKey(seed)) || !sub) {
    wipe(seed, scalar);
    throw new PgpError('bad-passphrase', 'the phrase or the e-mail address is not the one this key was made from');
  }
  const secrets = new Map<KeyPacket, Secret>([
    [pub.primary, { kind: 'ed25519', seed }],
    [sub.key, { kind: 'cv25519', scalar }],
  ]);
  const cert = await protectAll(pub, secrets, spec.passphrase, { random: spec.random, onProgress: spec.onProgress && ((d) => spec.onProgress!('protect', d)) });
  const rev = revocationSignature(pub, seed, REASON.NONE, '', spec.now);
  wipe(seed, scalar);
  return { cert, revocation: revocationText(cert, rev.body, keyState(pub, spec.now).primaryUserId ?? spec.email) };
}
