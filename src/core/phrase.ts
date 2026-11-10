// "Key from a passphrase" (Task.md §4.4): the same phrase, e-mail address and day give the
// same key, on any device, so it can be restored without a backup.
//
// Version 1 of the derivation, fixed for good — changing anything here changes every key
// made with it, and tests/vectors/phrase/ holds frozen examples that would fail:
//
//   phrase' = NFKC(phrase), lower-cased, runs of white space as one space, trimmed
//   email'  = NFKC(email), lower-cased, trimmed
//   seed    = scrypt(phrase', "html-simple-pgp/key/v1" ‖ 0x00 ‖ email', N=2^18, r=8, p=1, 64)
//   Ed25519 seed   = HMAC-SHA-512(seed, "ed25519")[0..32]
//   Cv25519 secret = clamp(HMAC-SHA-512(seed, "cv25519")[0..32])
//   both keys created at 00:00:00 UTC of the chosen day
//
// The public key is public: anyone can try phrases against it, as many as they like. Five
// words a person makes up are some 30–50 bits; scrypt makes each try cost 256 MiB of memory,
// and the e-mail in the salt makes each try good for one address only. The phrase is still
// the key's only protection.

import { utf8 } from './bytes.ts';
import { hmac } from './crypto/hmac.ts';
import { scrypt } from './crypto/scrypt.ts';
import { SHA512 } from './crypto/sha512.ts';
import { concat, wipe } from './crypto/util.ts';
import { clamp } from './crypto/x25519.ts';
import { PgpError } from './errors.ts';

export const PHRASE_PARAMS = { N: 2 ** 18, r: 8, p: 1, length: 64 } as const;
export const MIN_WORDS = 5;
const SALT_PREFIX = 'html-simple-pgp/key/v1';

export const normalizePhrase = (phrase: string): string => phrase.normalize('NFKC').toLowerCase().replace(/\s+/gu, ' ').trim();

export const normalizeEmail = (email: string): string => email.normalize('NFKC').toLowerCase().trim();

/**
 * The words of the phrase, each counted once, in any language — prepositions and the like
 * included. Intl.Segmenter splits languages written without spaces (Chinese, Japanese, Thai)
 * too. It is used only to count: the key comes from the normalized text, never from how a
 * browser's ICU happens to segment it.
 */
export function distinctWords(phrase: string): string[] {
  const text = normalizePhrase(phrase);
  const words = new Set<string>();
  const Segmenter = (Intl as { Segmenter?: typeof Intl.Segmenter }).Segmenter;
  if (Segmenter) {
    for (const s of new Segmenter(undefined, { granularity: 'word' }).segment(text)) if (s.isWordLike) words.add(s.segment);
  } else {
    for (const w of text.split(' ')) if (/[\p{L}\p{N}]/u.test(w)) words.add(w);
  }
  return [...words];
}

export const phraseLongEnough = (phrase: string): boolean => distinctWords(phrase).length >= MIN_WORDS;

/** The day, as "YYYY-MM-DD", at 00:00:00 UTC in seconds since 1970. */
export function dayStart(day: string): number {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day);
  if (!m) throw new PgpError('unexpected', 'the date is written YYYY-MM-DD');
  const t = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])) / 1000;
  if (new Date(t * 1000).toISOString().slice(0, 10) !== day) throw new PgpError('unexpected', 'there is no such date');
  return t;
}

export interface PhraseSecrets {
  seed: Uint8Array;
  scalar: Uint8Array;
}

export async function secretsFromPhrase(phrase: string, email: string, onProgress?: (done: number) => void): Promise<PhraseSecrets> {
  if (!phraseLongEnough(phrase)) throw new PgpError('unexpected', `the phrase needs at least ${MIN_WORDS} different words`);
  const address = normalizeEmail(email);
  if (!address) throw new PgpError('unexpected', 'a key from a phrase needs an e-mail address');
  const password = utf8(normalizePhrase(phrase));
  const salt = concat(utf8(SALT_PREFIX), Uint8Array.of(0), utf8(address));
  const seed = await scrypt(password, salt, PHRASE_PARAMS, onProgress);
  const ed = hmac(SHA512, seed, utf8('ed25519')).slice(0, 32);
  const cv = clamp(hmac(SHA512, seed, utf8('cv25519')).subarray(0, 32));
  wipe(seed, password);
  return { seed: ed, scalar: cv };
}
