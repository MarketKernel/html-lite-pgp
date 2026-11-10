// The notepad: text typed or pasted in, encrypted for the chosen recipients, clear-signed, or
// decrypted and verified, in place. The text before the last operation is kept, to go back
// to it. (After html-pgp.)

import { armor, reflowArmor } from '../core/armor.ts';
import { t } from '../core/i18n.ts';
import { classify } from '../core/pgp.ts';
import { signCleartext } from '../core/verify.ts';
import { importInputs } from './keyactions.ts';
import { label, named, ownEncryption } from './model.ts';
import { Cancelled, askPassword, encryptTo, errorText, openAny, signingKey } from './operations.ts';
import { outcomeLines, renderLines } from './outcome.ts';
import type { Line } from './outcome.ts';
import { RecipientPicker, defaultSigner, signerChoices } from './recipients.ts';
import { copyText, readClipboard, saveFile } from './save.ts';
import { app, now, onKeyringChange, saveState } from './state.ts';
import { h, select, toast } from './ui.ts';

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

let picker: RecipientPicker;
let signer: HTMLSelectElement;
let pickedSigner: string | null = null;
let previous: string | null = null;
let busy = false;

const area = (): HTMLTextAreaElement => $('np-text');

function showResult(lines: Line[], extra: HTMLElement[] = []): void {
  const box = $('np-result');
  const result = renderLines(lines);
  if (previous !== null) {
    const undo = h('button', { type: 'button', class: 'link-button', text: t('notepad', 'Show the original text') });
    undo.addEventListener('click', () => {
      if (previous === null) return;
      area().value = previous;
      previous = null;
      box.hidden = true;
      area().focus();
    });
    extra.push(undo);
  }
  if (extra.length) result.append(h('div', { class: 'result-actions' }, ...extra));
  box.replaceChildren(result);
  box.hidden = false;
}

const hideResult = (): void => void ($('np-result').hidden = true);

function replaceText(text: string): void {
  previous = area().value;
  area().value = text;
  area().scrollTop = 0;
}

async function run(work: () => Promise<void>): Promise<void> {
  if (busy) return;
  busy = true;
  for (const id of ['np-encrypt', 'np-sign', 'np-decrypt']) ($(id) as HTMLButtonElement).disabled = true;
  try {
    await work();
  } catch (error) {
    if (!(error instanceof Cancelled)) {
      const text = errorText(error);
      if (text) showResult([{ tone: 'bad', text }]);
    }
  } finally {
    busy = false;
    for (const id of ['np-encrypt', 'np-sign', 'np-decrypt']) ($(id) as HTMLButtonElement).disabled = false;
  }
}

function copyButton(): HTMLButtonElement {
  const button = h('button', { type: 'button', class: 'button button--small', text: t('notepad', 'Copy') });
  button.addEventListener('click', () => void copyText(area().value).then(() => toast(t('notepad', 'Copied'))));
  return button;
}

async function encryptText(): Promise<void> {
  const text = area().value;
  if (!text) return toast(t('notepad', 'Type or paste the text first'), 'error');
  if (picker.pending()) return toast(t('notepad', '"{text}" is not a recipient yet: pick a key from the list', { text: picker.pending() }), 'error');
  const recipients = picker.views();
  const self = ($('np-self') as HTMLInputElement).checked ? ownEncryption() : null;
  if (self && !recipients.some((r) => r.fingerprint === self.fingerprint)) recipients.push(self);
  let password: string | undefined;
  if (($('np-password') as HTMLInputElement).checked) {
    const p = await askPassword(t('notepad', 'Encrypt with a password'), t('notepad', 'Anyone who knows this password can decrypt the message. Tell it to the recipient another way than the message itself.'), { twice: true });
    if (p === null) return;
    password = p;
  }
  if (!recipients.length && !password) return toast(t('notepad', 'Add a recipient, or encrypt with a password'), 'error');
  const bytes = await encryptTo({ data: new TextEncoder().encode(text), format: 'u', recipients, password, signer: signer.value });
  replaceText(armor('MESSAGE', bytes));
  const names = recipients.map(named);
  if (password) names.push(t('notepad', 'a password'));
  const lines: Line[] = [{ tone: 'ok', text: t('notepad', 'Encrypted for: {names}', { names: names.join(', ') }) }];
  lines.push(signer.value ? { tone: 'ok', text: t('notepad', 'Signed as {key}', { key: recipientsLabel(signer.value) }) } : { tone: 'neutral', text: t('notepad', 'Not signed') });
  const unverified = recipients.filter((r) => !r.verified);
  if (unverified.length) lines.push({ tone: 'warn', text: t('notepad', 'Not verified: {names}', { names: unverified.map(named).join(', ') }), detail: t('notepad', 'Make sure these keys really belong to their owners.') });
  showResult(lines, [copyButton()]);
}

function recipientsLabel(fingerprint: string): string {
  return signerChoices().find((c) => c.value === fingerprint)?.label ?? fingerprint;
}

async function signText(): Promise<void> {
  const text = area().value;
  if (!text) return toast(t('notepad', 'Type or paste the text first'), 'error');
  if (!signer.value) return toast(t('notepad', 'Choose a key to sign with'), 'error');
  const key = await signingKey(signer.value);
  replaceText(signCleartext(text, key, now()));
  showResult([{ tone: 'ok', text: t('notepad', 'Signed as {key}', { key: recipientsLabel(signer.value) }), detail: t('notepad', 'The text stays readable; the signature below it shows it comes from you, unchanged.') }], [copyButton()]);
}

async function decryptText(): Promise<void> {
  const text = reflowArmor(area().value);
  if (!text.trim()) return toast(t('notepad', 'Paste an encrypted or signed message first'), 'error');
  const kind = classify(text);
  if (kind === 'public-keys' || kind === 'secret-keys' || kind === 'revocation') {
    const button = h('button', { type: 'button', class: 'button button--small button--primary', text: t('notepad', 'Import') });
    button.addEventListener('click', () => void importInputs([text]).then(hideResult));
    showResult([{ tone: 'neutral', text: kind === 'revocation' ? t('notepad', 'This is a revocation certificate.') : t('notepad', 'This is a key, not a message.') }], [button]);
    return;
  }
  if (kind === 'signature') {
    showResult([{ tone: 'warn', text: t('notepad', 'This is a detached signature: it is checked against the file it signs. Open both in Files.') }]);
    return;
  }
  const opened = await openAny(text);
  const lines = outcomeLines(opened);
  if (opened.format === 'b' && !opened.clearSigned) {
    const save = h('button', { type: 'button', class: 'button button--small', text: t('notepad', 'Save as a file') });
    save.addEventListener('click', () => void saveFile(opened.data, opened.filename || 'decrypted.bin'));
    let asText: string | null = null;
    try {
      asText = new TextDecoder('utf-8', { fatal: true }).decode(opened.data);
    } catch {
      asText = null;
    }
    if (asText === null) {
      lines.unshift({ tone: 'neutral', text: t('notepad', 'The content is a file, not text: {name}', { name: opened.filename || '—' }) });
      showResult(lines, [save]);
      return;
    }
    replaceText(asText);
    showResult(lines, [save]);
    return;
  }
  replaceText(new TextDecoder().decode(opened.data));
  showResult(lines);
}

const looksArmored = (text: string): boolean => /-----BEGIN PGP /.test(text);

export function primaryNotepadAction(): void {
  void run(looksArmored(area().value) ? decryptText : encryptText);
}

export const decryptNotepad = (): void => void run(decryptText);

export const notepadHasText = (): boolean => area().value.trim().length > 0;

export function loadNotepad(text: string): void {
  previous = null;
  area().value = text;
  hideResult();
}

function refreshSigners(): void {
  const choices = signerChoices();
  signer.replaceChildren(...choices.map((c) => h('option', { value: c.value, text: c.label })));
  signer.value = pickedSigner !== null && choices.some((c) => c.value === pickedSigner) ? pickedSigner : defaultSigner();
  const self = ownEncryption();
  const selfBox = $('np-self') as HTMLInputElement;
  selfBox.disabled = !self;
  $('np-self-name').textContent = self ? label(self) : t('notepad', 'you have no key pair yet');
  $('np-encrypt').querySelector('span')!.textContent = signer.value ? t('notepad', 'Sign and encrypt') : t('notepad', 'Encrypt');
}

export function bindNotepad(): void {
  picker = new RecipientPicker();
  $('np-recipients').replaceWith(picker.node);
  signer = select(signerChoices(), '');
  signer.id = 'np-signer';
  signer.className = 'side-select';
  $('np-signer-slot').replaceWith(signer);
  signer.addEventListener('change', () => {
    pickedSigner = signer.value;
    refreshSigners();
  });
  const selfBox = $('np-self') as HTMLInputElement;
  selfBox.checked = app.settings.encryptToSelf;
  selfBox.addEventListener('change', () => {
    app.settings.encryptToSelf = selfBox.checked;
    saveState();
  });
  refreshSigners();
  $('np-encrypt').addEventListener('click', () => void run(encryptText));
  $('np-sign').addEventListener('click', () => void run(signText));
  $('np-decrypt').addEventListener('click', () => void run(decryptText));
  area().addEventListener('input', () => {
    previous = null;
    hideResult();
  });
  area().addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
      event.preventDefault();
      primaryNotepadAction();
    }
  });
  $('np-paste').addEventListener('click', () => {
    readClipboard().then(
      (text) => {
        loadNotepad(text);
        area().focus();
      },
      (error: unknown) => toast(errorText(error) ?? '', 'error'),
    );
  });
  $('np-copy').addEventListener('click', () => {
    if (area().value) void copyText(area().value).then(() => toast(t('notepad', 'Copied')));
  });
  $('np-save').addEventListener('click', () => {
    const text = area().value;
    if (text) void saveFile(text, looksArmored(text) ? 'message.asc' : 'message.txt');
  });
  $('np-clear').addEventListener('click', () => {
    previous = null;
    area().value = '';
    hideResult();
    area().focus();
  });
  onKeyringChange(() => {
    picker.refresh();
    refreshSigners();
  });
}
