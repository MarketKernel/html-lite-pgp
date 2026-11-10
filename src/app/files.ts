// Files: added or dropped, each looked at to tell what it is; signing and encrypting the plain
// ones, decrypting and verifying the rest. A detached signature finds the file it signs by its
// name — report.pdf.sig goes with report.pdf — or asks for it. Files are read whole into
// memory. (After html-pgp.)

import { armor } from '../core/armor.ts';
import { t, tn } from '../core/i18n.ts';
import { classify, verifyDetached } from '../core/pgp.ts';
import type { Kind } from '../core/pgp.ts';
import { MAX_DATA } from '../core/message.ts';
import { signData, wrapSignature } from '../core/verify.ts';
import { importInputs } from './keyactions.ts';
import { named, ownEncryption } from './model.ts';
import { Cancelled, askPassword, encryptTo, errorText, openAny, signingKey } from './operations.ts';
import { outcomeLines, renderLines, signatureLine, worst } from './outcome.ts';
import type { Line } from './outcome.ts';
import { RecipientPicker, defaultSigner, signerChoices } from './recipients.ts';
import { saveFile } from './save.ts';
import { app, now, saveState } from './state.ts';
import { checkbox, dialog, h, icon, ICONS, select, toast } from './ui.ts';

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;

interface Output {
  name: string;
  data: Uint8Array | string;
}

interface Item {
  name: string;
  size: number;
  bytes: Uint8Array;
  kind: Kind;
  busy: boolean;
  lines: Line[];
  outputs: Output[];
  signed: Item | null;
}

let items: Item[] = [];
const PGP_EXT = /\.(gpg|pgp|asc|sig)$/i;
const OPENABLE: Kind[] = ['encrypted', 'signed', 'clear-signed', 'signature'];

function kindLabel(kind: Kind): string {
  switch (kind) {
    case 'encrypted':
      return t('files', 'Encrypted');
    case 'signed':
      return t('files', 'Signed');
    case 'clear-signed':
      return t('files', 'Signed text');
    case 'signature':
      return t('files', 'Detached signature');
    case 'public-keys':
    case 'secret-keys':
      return t('files', 'Keys');
    case 'revocation':
      return t('files', 'Revocation certificate');
    case 'unknown':
      return t('files', 'File');
  }
}

function kindIcon(kind: Kind): string {
  if (kind === 'encrypted') return ICONS.lock;
  if (kind === 'signed' || kind === 'clear-signed' || kind === 'signature') return ICONS.signature;
  if (kind === 'public-keys' || kind === 'secret-keys' || kind === 'revocation') return ICONS.key;
  return ICONS.file;
}

function size(bytes: number): string {
  if (bytes < 1024) return tn('files', '{count} byte', '{count} bytes', bytes);
  if (bytes < 1024 * 1024) return t('files', '{size} KB', { size: (bytes / 1024).toFixed(1) });
  return t('files', '{size} MB', { size: (bytes / 1024 / 1024).toFixed(1) });
}

const isKeys = (i: Item) => i.kind === 'public-keys' || i.kind === 'secret-keys' || i.kind === 'revocation';

function outputName(item: Item, embedded: string): string {
  if (PGP_EXT.test(item.name)) return item.name.replace(PGP_EXT, '');
  return embedded || `${item.name}.out`;
}

function pairOf(item: Item): Item | null {
  const base = item.name.replace(/\.(sig|asc)$/i, '');
  return items.find((other) => other !== item && other.kind === 'unknown' && other.name === base) ?? null;
}

function render(): void {
  $('files-list').replaceChildren(...items.map(row));
  const plain = items.filter((i) => i.kind === 'unknown');
  $('files-empty').hidden = items.length > 0;
  $('files-bar').hidden = items.length === 0;
  ($('files-protect') as HTMLButtonElement).disabled = !plain.length;
  ($('files-open') as HTMLButtonElement).disabled = !items.some((i) => OPENABLE.includes(i.kind)) || opening;
  $('files-import').hidden = !items.some(isKeys);
  $('files-save-all').hidden = items.flatMap((i) => i.outputs).length < 2;
}

function row(item: Item): HTMLElement {
  const remove = h('button', { type: 'button', class: 'icon-button icon-button--small', title: t('files', 'Remove from the list'), 'aria-label': t('files', 'Remove from the list') }, icon(ICONS.close));
  remove.addEventListener('click', () => {
    items = items.filter((i) => i !== item);
    for (const other of items) if (other.signed === item) other.signed = null;
    render();
  });
  const actions = h('div', { class: 'file-actions' });
  if (item.kind === 'signature' && !item.signed && !item.lines.length) {
    const choose = h('button', { type: 'button', class: 'button button--small', text: t('files', 'Choose the signed file…') });
    choose.addEventListener('click', () => chooseSigned(item));
    actions.append(choose);
  }
  for (const output of item.outputs) {
    const save = h('button', { type: 'button', class: 'button button--small button--primary' }, icon(ICONS.save), h('span', { text: t('files', 'Save {name}', { name: output.name }) }));
    save.addEventListener('click', () => void saveFile(output.data, output.name));
    actions.append(save);
  }
  return h(
    'li',
    { class: `file${item.busy ? ' file--busy' : ''}`, 'data-name': item.name },
    h(
      'div',
      { class: 'file-head' },
      h('span', { class: `file-icon file-icon--${item.kind}` }, icon(kindIcon(item.kind))),
      h(
        'div',
        { class: 'file-names' },
        h('span', { class: 'file-name', text: item.name }),
        h('span', { class: 'file-meta', text: `${kindLabel(item.kind)} · ${size(item.size)}${item.signed ? ` · ${t('files', 'signs {name}', { name: item.signed.name })}` : ''}` }),
      ),
      remove,
    ),
    item.lines.length ? renderLines(item.lines) : null,
    actions.childElementCount ? actions : null,
  );
}

export const filesListed = (): boolean => items.length > 0;

export async function addFiles(files: File[]): Promise<void> {
  for (const file of files) {
    if (file.size > MAX_DATA) {
      toast(t('files', '{name} is larger than 256 MB: too large for this page', { name: file.name }), 'error');
      continue;
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    items.push({ name: file.name, size: file.size, bytes, kind: classify(bytes), busy: false, lines: [], outputs: [], signed: null });
  }
  for (const item of items) if (item.kind === 'signature' && !item.signed) item.signed = pairOf(item);
  render();
}

function chooseSigned(item: Item): void {
  const picker = h('input', { type: 'file' });
  picker.addEventListener('change', async () => {
    const file = picker.files?.[0];
    if (!file) return;
    const signed: Item = { name: file.name, size: file.size, bytes: new Uint8Array(await file.arrayBuffer()), kind: 'unknown', busy: false, lines: [], outputs: [], signed: null };
    items.splice(items.indexOf(item), 0, signed);
    item.signed = signed;
    render();
    await openItem(item);
    render();
  });
  picker.click();
}

async function openItem(item: Item): Promise<void> {
  item.busy = true;
  render();
  try {
    if (item.kind === 'signature') {
      if (!item.signed) {
        item.lines = [{ tone: 'warn', text: t('files', 'This is a detached signature: the file it signs is needed to check it') }];
        return;
      }
      const checks = verifyDetached(item.bytes, item.signed.bytes, app.keyring.certs(), now());
      item.lines = [{ tone: 'neutral', text: t('files', 'Checked against {name}', { name: item.signed.name }) }, ...checks.map(signatureLine)];
      return;
    }
    const opened = await openAny(item.bytes);
    item.lines = outcomeLines(opened);
    const name = opened.clearSigned ? `${item.name.replace(/\.(asc|txt)$/i, '')}.txt` : outputName(item, opened.filename);
    item.outputs = [{ name, data: opened.data }];
  } catch (error) {
    const text = errorText(error);
    item.lines = text ? [{ tone: 'bad', text }] : [];
  } finally {
    item.busy = false;
  }
}

let opening = false;

async function openAll(): Promise<void> {
  if (opening) return;
  opening = true;
  render();
  try {
    for (const item of items) {
      if (!OPENABLE.includes(item.kind)) continue;
      await openItem(item);
      render();
    }
    const done = items.filter((i) => i.lines.length);
    if (done.length && worst(done.flatMap((i) => i.lines.map((l) => l.tone))) === 'bad') toast(t('files', 'Some files could not be processed: see below'), 'error');
  } finally {
    opening = false;
    render();
  }
}

async function importAll(): Promise<void> {
  const keys = items.filter(isKeys);
  items = items.filter((i) => !isKeys(i));
  render();
  await importInputs(keys.map((k) => k.bytes));
}

async function protectAll(): Promise<void> {
  const targets = items.filter((i) => i.kind === 'unknown');
  if (!targets.length) return;
  const choices = signerChoices().filter((c) => c.value);
  const signAs = checkbox(t('files', 'Sign as'), choices.length > 0);
  const signer = select(choices, defaultSigner());
  signAs.input.disabled = !choices.length;
  signer.disabled = !signAs.input.checked;
  signAs.input.addEventListener('change', () => (signer.disabled = !signAs.input.checked));
  const self = ownEncryption();
  const forMe = checkbox(self ? t('files', 'Encrypt for me ({key})', { key: named(self) }) : t('files', 'Encrypt for me'), !!self && app.settings.encryptToSelf);
  forMe.input.disabled = !self;
  const forOthers = checkbox(t('files', 'Encrypt for others'), true);
  const picker = new RecipientPicker(() => (forOthers.input.checked = true));
  const withPassword = checkbox(t('files', 'Encrypt with a password'), false, t('files', 'Anyone who knows the password can decrypt the files.'));
  const asText = checkbox(t('files', 'Text output (ASCII armor, .asc)'), app.settings.armorFiles, t('files', 'For mail and messengers; otherwise binary .gpg and .sig, smaller.'));
  let made = 0;
  await dialog({
    title: tn('files', 'Sign / encrypt {count} file', 'Sign / encrypt {count} files', targets.length),
    wide: true,
    body: [
      h('div', { class: 'protect-row' }, signAs.node, signer),
      forMe.node,
      forOthers.node,
      picker.node,
      withPassword.node,
      asText.node,
      h('p', { class: 'dialog-hint', text: t('files', 'Signing without encrypting makes a detached signature (.sig) beside each file.') }),
    ],
    confirm: t('files', 'Sign / encrypt'),
    submit: async () => {
      if (picker.pending()) return t('notepad', '"{text}" is not a recipient yet: pick a key from the list', { text: picker.pending() });
      const recipients = forOthers.input.checked ? picker.views() : [];
      if (forMe.input.checked && self && !recipients.some((r) => r.fingerprint === self.fingerprint)) recipients.push(self);
      const signing = signAs.input.checked && signer.value ? signer.value : '';
      if (!recipients.length && !withPassword.input.checked && !signing) return t('files', 'Choose to sign, to encrypt, or both');
      let password: string | undefined;
      if (withPassword.input.checked) {
        const p = await askPassword(t('notepad', 'Encrypt with a password'), t('notepad', 'Anyone who knows this password can decrypt the message. Tell it to the recipient another way than the message itself.'), { twice: true });
        if (p === null) return t('files', 'No password was chosen');
        password = p;
      }
      app.settings.armorFiles = asText.input.checked;
      app.settings.encryptToSelf = forMe.input.checked;
      saveState();
      const encrypting = recipients.length > 0 || !!password;
      const key = !encrypting && signing ? await signingKey(signing).catch((e) => (e instanceof Cancelled ? null : Promise.reject(e))) : null;
      if (!encrypting && signing && !key) return '';
      for (const item of targets) {
        item.busy = true;
        render();
        try {
          if (encrypting) {
            const data = await encryptTo({ data: item.bytes, format: 'b', filename: item.name, recipients, password, signer: signing });
            item.outputs = [{ name: `${item.name}.${asText.input.checked ? 'asc' : 'gpg'}`, data: asText.input.checked ? armor('MESSAGE', data) : data }];
            const names = recipients.map(named);
            if (password) names.push(t('notepad', 'a password'));
            item.lines = [{ tone: 'ok', text: t('notepad', 'Encrypted for: {names}', { names: names.join(', ') }) }];
          } else {
            const sig = wrapSignature(signData(item.bytes, key!, now()));
            item.outputs = [{ name: `${item.name}.${asText.input.checked ? 'asc' : 'sig'}`, data: asText.input.checked ? armor('SIGNATURE', sig) : sig }];
            item.lines = [];
          }
          if (signing) item.lines.push({ tone: 'ok', text: t('files', 'Signed') });
          made++;
        } catch (error) {
          if (error instanceof Cancelled) break;
          item.lines = [{ tone: 'bad', text: errorText(error) ?? '' }];
        } finally {
          item.busy = false;
        }
      }
      render();
      return null;
    },
  });
  if (made) toast(tn('files', '{count} file ready: save it below', '{count} files ready: save them below', made));
}

async function saveAll(): Promise<void> {
  for (const output of items.flatMap((i) => i.outputs)) await saveFile(output.data, output.name);
}

export function bindFiles(): void {
  const picker = $('files-picker') as HTMLInputElement;
  for (const id of ['files-add', 'files-choose']) $(id).addEventListener('click', () => picker.click());
  picker.addEventListener('change', () => {
    const files = [...(picker.files ?? [])];
    picker.value = '';
    if (files.length) void addFiles(files);
  });
  $('files-clear').addEventListener('click', () => {
    items = [];
    render();
  });
  $('files-protect').addEventListener('click', () => void protectAll());
  $('files-open').addEventListener('click', () => void openAll());
  $('files-import').addEventListener('click', () => void importAll());
  $('files-save-all').addEventListener('click', () => void saveAll());
  render();
}
