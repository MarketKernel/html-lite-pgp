// One key in full: its fingerprint, user IDs, keys, dates, where it came from, and every
// action that applies to it. (After html-pgp.)

import { armor } from '../core/armor.ts';
import { t } from '../core/i18n.ts';
import { algorithmName } from '../core/algorithms.ts';
import { fingerprintHex, writeCert } from '../core/keys.ts';
import { backupSecret, changeExpiry, changePassphrase, deleteKeys, exportPublic, markAsVerified, revokeKey, saveRevocationCertificate, unmarkVerified } from './keyactions.ts';
import { fingerprintGroups, formatDate, keyIdLabel, validity } from './model.ts';
import type { KeyView } from './model.ts';
import { copyText } from './save.ts';
import { back } from './screens.ts';
import { avatar, h, icon, ICONS, menuAt, toast } from './ui.ts';
import type { MenuItem } from './ui.ts';
import { KEY_FLAG } from '../core/signature.ts';
import { secretHere } from '../core/secret.ts';
import { platform } from './platform.ts';

function iconButton(paths: string, title: string, action: (button: HTMLButtonElement) => void): HTMLButtonElement {
  const button = h('button', { type: 'button', class: 'icon-button icon-button--small', title, 'aria-label': title }, icon(paths));
  button.addEventListener('click', () => action(button));
  return button;
}

function actionButton(paths: string, text: string, action: () => void, primary = false): HTMLButtonElement {
  const button = h('button', { type: 'button', class: `button button--small${primary ? ' button--primary' : ''}` }, icon(paths), h('span', { text }));
  button.addEventListener('click', action);
  return button;
}

function sourceText(v: KeyView): string {
  switch (v.entry.record.source) {
    case 'hardware':
      return t('details', 'made here from the hardware generator');
    case 'mouse':
      return t('details', 'made here from mouse movements');
    case 'phrase':
      return t('details', 'made from a phrase');
    default:
      return '';
  }
}

function usage(flags: number): string {
  const parts: string[] = [];
  if (flags & KEY_FLAG.CERTIFY) parts.push(t('details', 'certify'));
  if (flags & KEY_FLAG.SIGN) parts.push(t('details', 'sign'));
  if (flags & (KEY_FLAG.ENCRYPT_COMMS | KEY_FLAG.ENCRYPT_STORAGE)) parts.push(t('details', 'encrypt'));
  return parts.join(', ');
}

function keysList(v: KeyView): HTMLElement {
  const list = h('ul', { class: 'subkeys' });
  const rows = [
    { key: v.entry.cert.primary, flags: v.state.flags, expires: v.state.expires, note: t('details', 'primary'), bad: '' },
    ...v.state.subkeys.map((s) => ({ key: s.key, flags: s.flags, expires: s.expires, note: '', bad: s.revoked ? t('status', 'Revoked') : s.expired ? t('status', 'Expired') : !s.usable ? t('status', 'Not usable') : '' })),
  ];
  for (const r of rows) {
    const curve = r.key.curve === 'ed25519' ? 'Ed25519' : r.key.curve === 'cv25519' ? 'Cv25519' : algorithmName(r.key.algorithm);
    list.append(
      h(
        'li',
        { class: `subkey${r.bad ? ' subkey--dim' : ''}` },
        h(
          'div',
          { class: 'subkey-main' },
          h('span', { class: 'mono subkey-id', title: fingerprintHex(r.key.fingerprint), text: keyIdLabel(fingerprintHex(r.key.fingerprint)) }),
          h('span', { class: 'subkey-algorithm', text: curve }),
          h('span', { class: 'subkey-usage', text: usage(r.flags) }),
          r.bad ? h('span', { class: 'chip chip--bad', text: r.bad }) : null,
        ),
        h(
          'div',
          { class: 'subkey-dates' },
          h('span', { text: t('details', 'created {date}', { date: formatDate(r.key.created) }) }),
          h('span', { text: r.expires === null ? t('details', 'does not expire') : t('details', 'expires {date}', { date: formatDate(r.expires) }) }),
          r.note ? h('span', { class: 'subkey-note', text: r.note }) : null,
          secretHere(r.key) || !v.here ? null : v.secret ? h('span', { class: 'subkey-note', text: t('details', 'no secret key') }) : null,
        ),
      ),
    );
  }
  return list;
}

function publicKeyBlock(v: KeyView): HTMLElement {
  const pre = h('pre', { class: 'armor mono', hidden: '' });
  const toggle = h('button', { type: 'button', class: 'link-button', text: t('details', 'Show the public key as text') });
  const copy = h('button', { type: 'button', class: 'link-button', text: t('details', 'Copy'), hidden: '' });
  toggle.addEventListener('click', () => {
    pre.hidden = !pre.hidden;
    copy.hidden = pre.hidden;
    if (!pre.hidden && !pre.textContent) pre.textContent = armor('PUBLIC KEY BLOCK', writeCert(v.entry.cert));
    toggle.textContent = pre.hidden ? t('details', 'Show the public key as text') : t('details', 'Hide');
  });
  copy.addEventListener('click', () => void copyText(pre.textContent ?? '').then(() => toast(t('export', 'Public key copied'))));
  return h('section', { class: 'details-section' }, h('div', { class: 'armor-links' }, toggle, copy), pre);
}

export function renderDetails(v: KeyView, into: HTMLElement): void {
  const valid = validity(v);
  const chips = h('div', { class: 'chips' }, h('span', { class: `chip chip--${valid.tone}`, title: valid.hint, text: valid.label }));
  if (v.secret && !v.here) chips.append(h('span', { class: 'chip chip--neutral', title: t('details', 'The secret key is kept on a device, or was exported without it'), text: t('details', 'Secret not here') }));
  chips.append(...platform.keyChips(v));
  if (v.unprotected) chips.append(h('span', { class: 'chip chip--warn', title: t('details', 'Anyone who can use this browser can use this key'), text: t('details', 'No passphrase') }));
  if (v.entry.record.source === 'phrase') chips.append(h('span', { class: 'chip chip--neutral', title: t('details', 'Made from a phrase: it can be restored from it'), text: t('details', 'From a phrase') }));

  const backButton = h('button', { type: 'button', class: 'icon-button details-back', title: t('details', 'Back'), 'aria-label': t('details', 'Back') }, icon(ICONS.back));
  backButton.addEventListener('click', back);

  const actions = h('div', { class: 'details-actions' });
  actions.append(actionButton(ICONS.export, t('details', 'Export'), () => void exportPublic([v]), !v.secret && v.verified));
  if (!v.secret && v.status === 'valid' && !v.verified) actions.append(actionButton(ICONS.certify, t('details', 'Mark as verified'), () => void markAsVerified(v), true));
  if (v.secret) actions.append(actionButton(ICONS.save, t('details', 'Back up'), () => void backupSecret(v)));

  const more: MenuItem[] = [{ label: t('keys', 'Copy fingerprint'), action: () => void copyText(v.fingerprint).then(() => toast(t('keys', 'Fingerprint copied'))) }];
  if (!v.secret && v.verified) more.push({ label: t('details', 'Mark as not verified'), action: () => void unmarkVerified(v) });
  if (v.secret) {
    const revoked = v.status === 'revoked';
    more.push(
      { label: t('details', 'Change expiry…'), separated: true, disabled: revoked, action: () => void changeExpiry(v) },
      { label: v.here ? t('details', 'Change passphrase…') : t('details', 'Keep a copy in this browser…'), action: () => void changePassphrase(v) },
      { label: t('details', 'Back up secret key…'), action: () => void backupSecret(v) },
      { label: t('details', 'Revocation certificate…'), disabled: revoked, action: () => void saveRevocationCertificate(v) },
      { label: t('details', 'Revoke key…'), danger: true, separated: true, disabled: revoked, action: () => void revokeKey(v) },
    );
  }
  if (v.secret) {
    const extra = platform.keyActions(v);
    extra.forEach((item, i) => more.push({ ...item, separated: i === 0 }));
  }
  more.push({ label: t('details', 'Delete…'), danger: true, separated: !v.secret, action: () => void deleteKeys([v]) });
  actions.append(iconButton(ICONS.more, t('details', 'More actions'), (button) => menuAt(button, more)));

  const facts = h(
    'dl',
    { class: 'facts' },
    h('dt', { text: t('details', 'Created') }),
    h('dd', { text: formatDate(v.state.created) }),
    h('dt', { text: t('details', 'Expires') }),
    h('dd', { class: v.status === 'expired' ? 'fact--bad' : '', text: formatDate(v.state.expires) }),
    h('dt', { text: t('details', 'Algorithm') }),
    h('dd', { text: 'Curve25519 (Ed25519 + Cv25519)' }),
    h('dt', { text: t('details', 'Key ID') }),
    h('dd', { class: 'mono', text: keyIdLabel(v.keyId) }),
    // Known only for keys made here and kept in this browser: a container holds the keys alone.
    ...(v.secret && v.entry.record.source !== 'imported' ? [h('dt', { text: t('details', 'Origin') }), h('dd', { text: sourceText(v) })] : []),
  );

  const fingerprint = h(
    'section',
    { class: 'fingerprint' },
    h('span', { class: 'section-label', text: t('details', 'Fingerprint') }),
    h(
      'div',
      { class: 'fingerprint-row' },
      h('code', { class: 'fpr' }, ...fingerprintGroups(v.fingerprint).split('  ').map((half) => h('span', { class: 'fpr-half', text: half }))),
      iconButton(ICONS.copy, t('keys', 'Copy fingerprint'), () => void copyText(v.fingerprint).then(() => toast(t('keys', 'Fingerprint copied')))),
    ),
    !v.secret && !v.verified && v.status === 'valid'
      ? h('p', { class: 'fingerprint-hint', text: t('details', 'Before you trust this key, compare its fingerprint with its owner — in person, or on a call where you know their voice — and mark it as verified.') })
      : null,
  );

  const users = h(
    'ul',
    { class: 'uids' },
    ...v.state.userIds.map((u) =>
      h(
        'li',
        { class: `uid${!u.valid || u.revoked ? ' uid--dim' : ''}` },
        h(
          'div',
          { class: 'uid-main' },
          h('div', { class: 'uid-text' }, h('span', { text: u.text }), u.text === v.state.primaryUserId && v.state.userIds.length > 1 ? h('span', { class: 'chip chip--neutral', text: t('details', 'primary') }) : null),
          u.revoked ? h('span', { class: 'chip chip--bad', text: t('status', 'Revoked') }) : !u.valid ? h('span', { class: 'chip chip--bad', text: t('status', 'Invalid') }) : null,
        ),
      ),
    ),
  );

  into.replaceChildren(
    h(
      'article',
      { class: 'details', 'data-fpr': v.fingerprint },
      h(
        'header',
        { class: 'details-head' },
        backButton,
        avatar(v.name, v.email, v.fingerprint, 'large'),
        h('div', { class: 'details-title' }, h('h2', { text: v.name || v.email || keyIdLabel(v.keyId) }), v.name && v.email ? h('div', { class: 'details-email', text: v.email }) : null, chips),
      ),
      actions,
      fingerprint,
      facts,
      h('section', { class: 'details-section' }, h('h3', { text: t('details', 'User IDs') }), users),
      h('section', { class: 'details-section' }, h('h3', { text: t('details', 'Keys') }), keysList(v)),
      publicKeyBlock(v),
    ),
  );
}
