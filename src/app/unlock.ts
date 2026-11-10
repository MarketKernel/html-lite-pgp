// Unlocking our keys: from the agent's cache, as they are when they have no passphrase, or
// after asking for it. A key GnuPG protected its own way (AES-128, SHA-1) is protected again
// in our profile (AES-256, SHA-256) with the same passphrase once it opens.

import { SYM, HASH } from '../core/algorithms.ts';
import { PgpError } from '../core/errors.ts';
import { t } from '../core/i18n.ts';
import { fingerprintHex } from '../core/keys.ts';
import type { KeyPacket } from '../core/keys.ts';
import { protectAll, readProtection, unlockAll } from '../core/secret.ts';
import type { Secret } from '../core/secret.ts';
import { messageRandom } from './entropy.ts';
import { keyIdLabel, label, fingerprintGroups } from './model.ts';
import type { KeyView } from './model.ts';
import { app, keyringChanged, now } from './state.ts';
import { dialog, h, secretInput, toast } from './ui.ts';
import { platform } from './platform.ts';

export type Purpose = 'decrypt' | 'sign' | 'change' | 'export' | 'verify';

function purposeText(purpose: Purpose): string {
  switch (purpose) {
    case 'decrypt':
      return t('passphrase', 'to decrypt the message');
    case 'sign':
      return t('passphrase', 'to sign');
    case 'change':
      return t('passphrase', 'to change the key');
    case 'export':
      return t('passphrase', 'to back up the key');
    case 'verify':
      return t('passphrase', 'to mark a key as verified');
  }
}

const byFingerprint = (m: Map<KeyPacket, Secret>): Map<string, Secret> => new Map([...m].map(([k, s]) => [fingerprintHex(k.fingerprint), s]));

/** True when the key's protection is not ours (AES-256, SHA-256, the full count). */
function foreignProtection(v: KeyView): boolean {
  try {
    for (const k of [v.entry.cert.primary, ...v.entry.cert.subkeys.map((s) => s.key)]) {
      if (!k.secretBody) continue;
      const p = readProtection(k);
      if (p.usage === 0) continue;
      if (p.cipher !== SYM.AES256 || p.s2k?.hash !== HASH.SHA256 || p.s2k?.countByte !== 0xff) return true;
    }
  } catch {
    return false;
  }
  return false;
}

async function reprotect(v: KeyView, passphrase: string, secrets: Map<KeyPacket, Secret>): Promise<void> {
  const random = await messageRandom();
  if (!random) return;
  const cert = await protectAll(v.entry.cert, secrets, passphrase, { random: random.bytes });
  await app.keyring.put(cert, v.entry.record.source, now());
  keyringChanged();
}

/** The secrets of our key by (sub)key fingerprint, or null when the user closed the prompt. */
export async function unlockKey(v: KeyView, purpose: Purpose, { fresh = false } = {}): Promise<Map<string, Secret> | null> {
  if (!v.secret) return null;
  if (!fresh) {
    const cached = app.agent.get(v.fingerprint, v.entry.record.data);
    if (cached) return cached;
  }
  // The PWA may hold the key on a device (a passkey, a security key): it asks for a touch. A
  // key whose secret lives only there has no passphrase to ask for, fresh or not.
  if (!fresh || !v.here) {
    const fromDevice = await platform.unlockWithDevice(v);
    if (fromDevice) {
      app.agent.put(v.fingerprint, v.entry.record.data, fromDevice);
      return fromDevice;
    }
  }
  if (!v.here) {
    toast(platform.pwa ? t('passphrase', 'The secret of this key is on a passkey or a security key, and it did not answer.') : t('passphrase', 'The secret of this key is not here: it is kept on a device, or was exported without it.'), 'error');
    return null;
  }
  if (v.unprotected) {
    const secrets = byFingerprint(await unlockAll(v.entry.cert, ''));
    app.agent.put(v.fingerprint, v.entry.record.data, secrets);
    return secrets;
  }
  const { input, node } = secretInput();
  const progress = h('div', { class: 'progress', hidden: '' }, h('span', { class: 'progress-fill' }));
  let result: Map<string, Secret> | null = null;
  const ok = await dialog({
    title: t('passphrase', 'Enter passphrase'),
    body: [
      h('p', { class: 'dialog-text', text: t('passphrase', 'The passphrase of your secret key is needed {purpose}:', { purpose: purposeText(purpose) }) }),
      h('div', { class: 'key-card' }, h('strong', { text: label(v) }), h('span', { class: 'mono', text: keyIdLabel(v.keyId) }), h('span', { class: 'mono key-card-fpr', text: fingerprintGroups(v.fingerprint) })),
      node,
      progress,
    ],
    confirm: t('passphrase', 'Unlock'),
    focus: input,
    submit: async () => {
      progress.hidden = false;
      const fill = progress.firstElementChild as HTMLElement;
      try {
        const opened = await unlockAll(v.entry.cert, input.value, (d) => (fill.style.width = `${Math.round(d * 100)}%`));
        result = byFingerprint(opened);
        if (foreignProtection(v)) {
          const passphrase = input.value;
          void reprotect(v, passphrase, opened).then(
            () => toast(t('passphrase', 'The key is now protected with AES-256 and SHA-256')),
            () => undefined,
          );
        }
        return null;
      } catch (error) {
        progress.hidden = true;
        if (error instanceof PgpError && error.code === 'bad-passphrase') return t('passphrase', 'Wrong passphrase. Try again.');
        if (error instanceof PgpError && error.code === 'integrity') return t('passphrase', 'This key was tampered with: its secret part does not match its public part. Do not use it.');
        throw error;
      }
    },
  });
  if (!ok || !result) return null;
  app.agent.put(v.fingerprint, v.entry.record.data, result);
  return result;
}

/** The Ed25519 seed of one of the key's packets. */
export function seedOf(secrets: Map<string, Secret>, key: KeyPacket): Uint8Array | null {
  const s = secrets.get(fingerprintHex(key.fingerprint));
  return s && s.kind === 'ed25519' ? s.seed : null;
}

export function scalarOf(secrets: Map<string, Secret>, key: KeyPacket): Uint8Array | null {
  const s = secrets.get(fingerprintHex(key.fingerprint));
  return s && s.kind === 'cv25519' ? s.scalar : null;
}
