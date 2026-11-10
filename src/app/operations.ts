// What the notepad and the files view share: finding and unlocking the keys a message needs,
// asking for a password, opening and making messages, and saying what went wrong in words.

import { equalBytes } from '../core/bytes.ts';
import { PgpError } from '../core/errors.ts';
import { t } from '../core/i18n.ts';
import { fingerprintHex } from '../core/keys.ts';
import { encryptMessage, recipientsOf } from '../core/message.ts';
import type { Decryptor } from '../core/message.ts';
import { binaryOf, classify, open } from '../core/pgp.ts';
import type { OpenedText } from '../core/pgp.ts';
import type { SigningKey } from '../core/verify.ts';
import { messageRandom } from './entropy.ts';
import { allViews, keyIdLabel, named, viewOf } from './model.ts';
import type { KeyView } from './model.ts';
import { app, now } from './state.ts';
import { dialog, field, h, secretInput } from './ui.ts';
import { scalarOf, seedOf, unlockKey } from './unlock.ts';

/** Thrown when the user closed a prompt: nothing to report. */
export class Cancelled extends Error {}

export function errorText(error: unknown): string | null {
  if (error instanceof Cancelled) return null;
  if (error instanceof PgpError) {
    switch (error.code) {
      case 'no-key':
        return t('errors', 'None of your keys can decrypt this message.');
      case 'bad-passphrase':
        return t('errors', 'The password does not open it.');
      case 'integrity':
        return t('errors', 'The message was changed or damaged on its way: it cannot be trusted, and nothing of it is shown.');
      case 'unsupported':
        return t('errors', 'Not supported: {what}.', { what: error.message });
      case 'too-large':
        return t('errors', 'Too large: {what}.', { what: error.message });
      case 'unexpected':
        return error.message;
      default:
        return t('errors', 'This is not valid OpenPGP data: {what}.', { what: error.message });
    }
  }
  return error instanceof Error ? error.message : String(error);
}

/** Asks for a password; null if the user closed the prompt. */
export async function askPassword(title: string, text: string, { twice = false } = {}): Promise<string | null> {
  const a = secretInput();
  const b = secretInput();
  let value = '';
  const ok = await dialog({
    title,
    body: [text, field(t('password', 'Password'), a.node), twice ? field(t('password', 'Repeat the password'), b.node) : null],
    confirm: t('password', 'OK'),
    focus: a.input,
    submit: () => {
      if (!a.input.value) return t('password', 'Enter a password.');
      if (twice && a.input.value !== b.input.value) return t('password', 'The passwords differ.');
      value = a.input.value;
      return null;
    },
  });
  return ok ? value : null;
}

/** Our signing key, unlocked: a signing subkey if the key has one with its secret, else the primary key. */
export async function signingKey(fingerprint: string): Promise<SigningKey> {
  const entry = app.keyring.get(fingerprint);
  if (!entry) throw new PgpError('unexpected', t('errors', 'The key to sign with is gone.'));
  const v = viewOf(entry);
  const secrets = await unlockKey(v, 'sign');
  if (!secrets) throw new Cancelled();
  const candidates = [...v.state.signing].filter((k) => k.secretBody).reverse();
  for (const key of candidates) {
    const seed = seedOf(secrets, key);
    if (seed) return { cert: entry.cert, key, seed };
  }
  throw new PgpError('unexpected', t('errors', 'This key cannot sign.'));
}

/** The keys of ours that can open the message, unlocked (asking as needed). */
async function decryptorsFor(data: Uint8Array): Promise<{ decryptors: Decryptor[]; password: string | undefined }> {
  const who = recipientsOf(data);
  if (!who) return { decryptors: [], password: undefined };
  const ours = allViews().filter((v) => v.secret);
  const candidates: { v: KeyView; keys: Decryptor['key'][] }[] = [];
  for (const v of ours) {
    const keys = v.entry.cert.subkeys.map((s) => s.key).filter((k) => k.curve === 'cv25519' && k.secretBody && (who.hidden || who.keyIds.some((id) => equalBytes(id, k.keyId))));
    if (keys.length) candidates.push({ v, keys });
  }
  const decryptors: Decryptor[] = [];
  for (const c of candidates) {
    const secrets = await unlockKey(c.v, 'decrypt');
    if (!secrets) throw new Cancelled();
    for (const key of c.keys) {
      const scalar = scalarOf(secrets, key);
      if (scalar) decryptors.push({ cert: c.v.entry.cert, key, scalar });
    }
    // One key that opens it is enough; a hidden recipient may need to try them all.
    if (!who.hidden) break;
  }
  let password: string | undefined;
  if (!decryptors.length && who.password) {
    const p = await askPassword(t('password', 'Decrypt with a password'), t('password', 'This message is encrypted with a password.'));
    if (p === null) throw new Cancelled();
    password = p;
  }
  if (!decryptors.length && password === undefined) {
    const named_ = who.keyIds.map((id) => keyIdLabel(fingerprintHex(id))).join(', ');
    throw new PgpError('no-key', named_);
  }
  return { decryptors, password };
}

/** Opens what was pasted or dropped: decrypts with what it needs, checks the signatures. */
export async function openAny(input: Uint8Array | string): Promise<OpenedText> {
  const kind = classify(input);
  const data = kind === 'encrypted' ? binaryOf(input).data : null;
  const { decryptors, password } = data ? await decryptorsFor(data) : { decryptors: [], password: undefined };
  return open(input, { keyring: app.keyring.certs(), decryptors, password, now: now() });
}

export interface Encrypt {
  data: Uint8Array;
  format: 'b' | 'u';
  filename?: string;
  recipients: KeyView[];
  password?: string;
  signer: string;
  onProgress?: (done: number) => void;
}

export async function encryptTo(e: Encrypt): Promise<Uint8Array> {
  const random = await messageRandom();
  if (!random) throw new Cancelled();
  const signer = e.signer ? await signingKey(e.signer) : undefined;
  const recipients = e.recipients.map((v) => ({ cert: v.entry.cert, key: v.state.encryption! }));
  return encryptMessage({ data: e.data, format: e.format, filename: e.filename, recipients, password: e.password, signer, now: now(), random: random.bytes, onProgress: e.onProgress });
}

export const nameOf = (fingerprint: string): string => {
  const entry = app.keyring.get(fingerprint);
  return entry ? named(viewOf(entry)) : keyIdLabel(fingerprint);
};
