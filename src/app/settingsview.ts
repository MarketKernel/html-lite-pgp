// The settings view: language and theme, how passphrases are kept, where randomness comes
// from, where the keys are kept, defaults, and the keyring as a whole. (After html-pgp.)

import { armor } from '../core/armor.ts';
import { LANGUAGES, setLanguage, t } from '../core/i18n.ts';
import type { Language } from '../core/i18n.ts';
import { writeCert } from '../core/keys.ts';
import { deleteKeys } from './keyactions.ts';
import { allViews, label } from './model.ts';
import { saveFile } from './save.ts';
import { applyTheme, CACHE_CHOICES, resolveLanguage } from './settings.ts';
import type { MessageRandom, Theme } from './settings.ts';
import { app, onKeyringChange, saveState } from './state.ts';
import { backupToContainer, importContainer, moveToBrowser, moveToContainer, onContainerChange, saveNow } from './storage.ts';
import { hardwareReady } from './entropy.ts';
import { platform } from './platform.ts';
import { checkbox, confirmAsk, dialog, h, select, toast } from './ui.ts';

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

/** Set by main.ts: everything drawn by code, drawn again (after a language change). */
export const redraw = { all: (): void => undefined };

function row(title: string, control: HTMLElement, hint?: string): HTMLElement {
  return h('div', { class: 'settings-row' }, h('div', { class: 'settings-text' }, h('div', { class: 'settings-title', text: title }), hint ? h('div', { class: 'settings-hint', text: hint }) : null), control);
}

function cacheLabel(minutes: number): string {
  if (minutes === 0) return t('settings', 'Ask every time');
  if (minutes < 60) return t('settings', '{count} min', { count: minutes });
  return t('settings', '{count} h', { count: minutes / 60 });
}

function button(text: string, action: () => void, danger = false): HTMLButtonElement {
  const node = h('button', { type: 'button', class: `button button--small${danger ? ' button--danger-ghost' : ''}`, text });
  node.addEventListener('click', action);
  return node;
}

export function renderSettings(): void {
  const s = app.settings;
  const language = select<string>([{ value: 'auto', label: t('settings', 'As the system') }, ...Object.entries(LANGUAGES).map(([code, name]) => ({ value: code, label: name }))], s.language);
  language.addEventListener('change', () => {
    s.language = language.value as Language | 'auto';
    saveState();
    setLanguage(resolveLanguage(s.language));
    redraw.all();
  });
  const theme = select<Theme>(
    [
      { value: 'system', label: t('settings', 'As the system') },
      { value: 'light', label: t('settings', 'Light') },
      { value: 'dark', label: t('settings', 'Dark') },
    ],
    s.theme,
  );
  theme.addEventListener('change', () => {
    s.theme = theme.value as Theme;
    saveState();
    applyTheme(s.theme);
  });
  const cache = select<string>(CACHE_CHOICES.map((m) => ({ value: String(m), label: cacheLabel(m) })), String(s.cacheMinutes));
  cache.addEventListener('change', () => {
    s.cacheMinutes = Number(cache.value);
    saveState();
    app.agent.forgetAll();
  });
  const hw = hardwareReady();
  const random = select<MessageRandom>(
    [
      { value: 'hardware', label: hw ? t('settings', 'Hardware generator') : t('settings', 'Hardware generator (not available)') },
      { value: 'mouse', label: t('settings', 'Mouse movements') },
    ],
    hw ? s.messageRandom : 'mouse',
  );
  random.disabled = !hw;
  random.addEventListener('change', () => {
    s.messageRandom = random.value as MessageRandom;
    saveState();
  });

  const own = allViews().filter((v) => v.secret);
  const defaultKey = select<string>(
    own.length ? own.map((v) => ({ value: v.fingerprint, label: label(v) })) : [{ value: '', label: t('settings', 'No key pair yet') }],
    own.some((v) => v.fingerprint === s.defaultKey) ? s.defaultKey : (own[0]?.fingerprint ?? ''),
  );
  defaultKey.disabled = own.length < 2;
  defaultKey.addEventListener('change', () => {
    s.defaultKey = defaultKey.value;
    saveState();
    redraw.all();
  });
  const self = checkbox(t('settings', 'Encrypt to my own key too'), s.encryptToSelf);
  self.input.addEventListener('change', () => {
    s.encryptToSelf = self.input.checked;
    saveState();
    redraw.all();
  });
  const asText = checkbox(t('settings', 'Write files as text (ASCII armor)'), s.armorFiles);
  asText.input.addEventListener('change', () => {
    s.armorFiles = asText.input.checked;
    saveState();
  });

  const all = allViews();
  const secret = all.filter((v) => v.secret);
  const keyring = h(
    'div',
    { class: 'settings-buttons' },
    button(t('settings', 'Export all public keys'), () => void saveFile(armor('PUBLIC KEY BLOCK', new Uint8Array(all.flatMap((v) => [...writeCert(v.entry.cert)]))), `public-keys-${all.length}.asc`)),
    button(t('settings', 'Back up all key pairs'), () => void backupAll()),
    button(t('settings', 'Delete all keys…'), () => void deleteKeys(all), true),
  );
  for (const node of keyring.querySelectorAll('button')) node.disabled = !all.length;
  if (!secret.length) (keyring.children[1] as HTMLButtonElement).disabled = true;

  const inContainer = s.storage === 'container';
  const storage = h(
    'div',
    { class: 'settings-buttons' },
    ...(inContainer
      ? [button(t('settings', 'Save the container now'), () => void saveNow()), button(t('settings', 'Keep the keys in this browser instead'), () => void moveToBrowser())]
      : [
          button(t('settings', 'Save all keys to a container…'), () => void backupToContainer()),
          button(t('settings', 'Import keys from a container…'), () => void importContainer()),
          button(t('settings', 'Keep the keys in a container instead…'), () => void moveToContainer()),
        ]),
  );

  $('settings-body').replaceChildren(
    h('h2', { class: 'settings-group', text: t('settings', 'Appearance') }),
    row(t('settings', 'Language'), language),
    row(t('settings', 'Theme'), theme),
    h('h2', { class: 'settings-group', text: t('settings', 'Security') }),
    row(t('settings', 'Remember passphrases for'), cache, t('settings', 'An unlocked key stays unlocked in this page for this long. "Forget passphrases" locks them all at once.')),
    row(t('settings', 'Randomness for messages'), random, t('settings', 'Every message needs fresh random numbers. With the mouse, the page asks you to move it once per session.')),
    h('h2', { class: 'settings-group', text: t('settings', 'Where the keys are kept') }),
    h(
      'p',
      { class: 'settings-hint' },
      inContainer
        ? t('settings', 'In a container file: the keys are encrypted with its password and live in this page only while it is open. Keep the file on a USB stick or in an encrypted volume (VeraCrypt, BitLocker, FileVault).')
        : app.persistent
          ? t('settings', "In this browser, for this page only. Back them up: clearing the browser's data deletes them.")
          : t('settings', 'This browser does not let the page keep data: the keys are lost when the page closes.'),
    ),
    storage,
    h('h2', { class: 'settings-group', text: t('settings', 'Defaults') }),
    row(t('settings', 'My default key'), defaultKey, t('settings', 'Used to sign, and to encrypt to yourself.')),
    h('div', { class: 'settings-row settings-row--check' }, self.node),
    h('div', { class: 'settings-row settings-row--check' }, asText.node),
    h('h2', { class: 'settings-group', text: t('settings', 'Keyring') }),
    keyring,
    ...platform.settingsRows(),
    h('h2', { class: 'settings-group', text: t('settings', 'About') }),
    h(
      'div',
      { class: 'settings-about' },
      h('p', { text: t('settings', 'Curve25519 (Ed25519 + Cv25519) · AES-256 · OpenPGP v4: GnuPG and Kleopatra read what this page writes, and it reads theirs.') }),
      h('p', { text: t('settings', 'Every line of the cryptography is in this one file — no external libraries, no WebCrypto — and nothing leaves the page: it has no network access at all.') }),
      h('p', { text: t('settings', 'Check the file you have against SHA256SUMS.txt of its release.') }),
      h('p', { class: 'mono', text: `Simple PGP ${document.querySelector('meta[name="version"]')?.getAttribute('content') ?? ''}` }),
    ),
  );
}

async function backupAll(): Promise<void> {
  const secret = allViews().filter((v) => v.secret);
  const ok = await dialog({
    title: t('settings', 'Back up all key pairs'),
    body: [t('settings', 'The file holds every secret key, each protected by its own passphrase. Keep it somewhere safe and private.')],
    confirm: t('export', 'Save file'),
  });
  if (!ok) return;
  const unprotected = secret.filter((v) => v.unprotected);
  if (unprotected.length && !(await confirmAsk(t('settings', 'Unprotected keys'), t('settings', 'Some keys have no passphrase and will be readable by anyone who gets the file: {keys}', { keys: unprotected.map(label).join(', ') }), t('export', 'Save file')))) return;
  await saveFile(armor('PRIVATE KEY BLOCK', new Uint8Array(secret.flatMap((v) => [...writeCert(v.entry.cert, { secret: true })]))), `secret-keys-backup-${new Date().toISOString().slice(0, 10)}.asc`);
  toast(t('settings', 'Backup saved'));
}

export function bindSettings(): void {
  onKeyringChange(renderSettings);
  onContainerChange(renderSettings);
  renderSettings();
}
