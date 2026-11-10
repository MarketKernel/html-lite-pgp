// What decrypting and verifying found, in words: who opened it, whose signatures are on it and
// whether they hold. The notepad and the files view show the same lines. (After html-pgp.)

import { t } from '../core/i18n.ts';
import { fingerprintHex } from '../core/keys.ts';
import type { OpenedText } from '../core/pgp.ts';
import type { SignatureCheck } from '../core/verify.ts';
import { formatDateTime, keyIdLabel, named, viewOf } from './model.ts';
import { app } from './state.ts';
import { h, icon, ICONS } from './ui.ts';

export type Tone = 'ok' | 'warn' | 'bad' | 'neutral';

export interface Line {
  tone: Tone;
  text: string;
  detail?: string;
}

const ORDER: Tone[] = ['neutral', 'ok', 'warn', 'bad'];
export const worst = (tones: Tone[]): Tone => tones.reduce<Tone>((a, b) => (ORDER.indexOf(b) > ORDER.indexOf(a) ? b : a), 'neutral');

export function signatureLine(check: SignatureCheck): Line {
  const entry = check.cert ? app.keyring.get(fingerprintHex(check.cert.primary.fingerprint)) : undefined;
  const id = check.keyId ? keyIdLabel(fingerprintHex(check.keyId)) : '?';
  const when = check.created ? t('result', 'Signed {date}', { date: formatDateTime(check.created) }) : '';
  switch (check.status) {
    case 'unknown-key':
      return { tone: 'warn', text: t('result', 'Signed by an unknown key {key}', { key: id }), detail: t('result', 'Import its public key to check the signature.') };
    case 'unsupported':
      return { tone: 'warn', text: t('result', 'A signature this program cannot check ({key})', { key: id }), detail: t('result', 'It uses an algorithm outside Curve25519, or a weak hash.') };
    case 'bad':
      return { tone: 'bad', text: t('result', 'Bad signature from {signer}', { signer: entry ? named(viewOf(entry)) : id }), detail: t('result', 'The data was changed after it was signed, or the signature does not belong here.') };
    case 'key-revoked':
      return { tone: 'bad', text: t('result', 'Signed by a revoked key: {signer}', { signer: entry ? named(viewOf(entry)) : id }), detail: t('result', 'Its owner revoked it: the signature may have been made by someone who stole it.') };
    case 'key-expired':
      return { tone: 'warn', text: t('result', 'Signed by {signer} after the key expired', { signer: entry ? named(viewOf(entry)) : id }), detail: when };
    case 'good': {
      const v = entry ? viewOf(entry) : null;
      const notes = [when];
      let tone: Tone = 'ok';
      if (v?.secret) notes.push(t('result', 'Your own key.'));
      else if (v?.verified) notes.push(t('result', 'You verified this key.'));
      else {
        notes.push(t('result', 'The key is not verified: compare its fingerprint with its owner to be sure it is theirs.'));
        tone = 'warn';
      }
      return { tone, text: t('result', 'Good signature from {signer}', { signer: v ? named(v) : id }), detail: notes.filter(Boolean).join(' · ') };
    }
  }
}

export function outcomeLines(opened: OpenedText): Line[] {
  const lines: Line[] = [];
  if (opened.encrypted) {
    if (opened.openedBy) {
      const entry = app.keyring.get(fingerprintHex(opened.openedBy.primary.fingerprint));
      lines.push({ tone: 'ok', text: t('result', 'Decrypted with your key {key}', { key: entry ? named(viewOf(entry)) : '' }) });
    } else lines.push({ tone: 'ok', text: t('result', 'Decrypted with a password') });
  }
  for (const check of opened.signatures) lines.push(signatureLine(check));
  if (!opened.signatures.length) {
    lines.push({
      tone: opened.encrypted ? 'neutral' : 'warn',
      text: t('result', 'Not signed'),
      detail: opened.encrypted ? t('result', 'Anyone with your public key could have written it.') : undefined,
    });
  }
  return lines;
}

const TONE_ICONS: Record<Tone, string> = { ok: ICONS.check, warn: ICONS.warning, bad: ICONS.cross, neutral: ICONS.info };

export function renderLines(lines: Line[]): HTMLElement {
  const box = h('div', { class: `result result--${worst(lines.map((l) => l.tone))}`, role: 'status' });
  for (const line of lines) {
    box.append(
      h(
        'div',
        { class: `result-line result-line--${line.tone}` },
        icon(TONE_ICONS[line.tone]),
        h('div', {}, h('div', { class: 'result-text', text: line.text }), line.detail ? h('div', { class: 'result-detail', text: line.detail }) : null),
      ),
    );
  }
  return box;
}
