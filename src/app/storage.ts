// Where the keys are kept (Task.md §5.1): in this browser (IndexedDB), or in a container file
// — the whole keyring encrypted with a password, which GnuPG opens too. In container mode the
// keys live in the page's memory; every change is written back into the file — by itself in
// Chrome and Edge, which can write to a file the user opened; elsewhere with a Save button
// that downloads the new copy.

import { CONTAINER_NAME, containerPasswordStrong, newContainerSession, openContainer, openContainerWith, saveContainer } from '../core/container.ts';
import type { ContainerSession } from '../core/container.ts';
import { PgpError } from '../core/errors.ts';
import { t } from '../core/i18n.ts';
import { Keyring, MemoryStore } from '../core/keyring.ts';
import type { KeyRecord } from '../core/keyring.ts';
import type { Cert } from '../core/keys.ts';
import { messageRandom } from './entropy.ts';
import { platform } from './platform.ts';
import { askPassword } from './operations.ts';
import { saveFile } from './save.ts';
import { app, keyringChanged, now, saveState } from './state.ts';
import { keepStorage, openIdb } from './store.ts';
import { confirmAsk, dialog, field, h, secretInput, toast } from './ui.ts';

/** A memory store that tells when the keyring changed, so the container can be saved. */
class ContainerStore extends MemoryStore {
  async save(record: KeyRecord): Promise<void> {
    await super.save(record);
    markDirty();
  }

  async remove(fingerprint: string): Promise<void> {
    await super.remove(fingerprint);
    markDirty();
  }
}

const listeners = new Set<() => void>();
export const onContainerChange = (l: () => void): void => void listeners.add(l);
const changed = () => {
  for (const l of listeners) l();
};

type Picker = { showOpenFilePicker?: (o?: object) => Promise<FileSystemFileHandle[]>; showSaveFilePicker?: (o?: object) => Promise<FileSystemFileHandle> };
const fs = window as unknown as Picker;
const canWriteFiles = (): boolean => typeof fs.showOpenFilePicker === 'function' && typeof fs.showSaveFilePicker === 'function';
const PICKER_TYPES = { types: [{ description: 'OpenPGP', accept: { 'application/pgp-encrypted': ['.gpg', '.pgp'] } }] };

/** Starts the keyring where the settings say. */
export async function startStorage(): Promise<void> {
  const idb = await openIdb();
  app.idb = idb;
  if (app.settings.storage === 'container') {
    app.keyring = new Keyring(new ContainerStore());
    app.persistent = false;
    app.container = { name: '', handle: idb ? await idb.getHandle().catch(() => null) : null, session: null, dirty: false };
    return;
  }
  app.keyring = new Keyring(idb ?? new MemoryStore());
  app.persistent = !!idb;
  await app.keyring.load();
}

export const containerOpen = (): boolean => !!app.container?.session || !!app.container?.name;

let saving: Promise<void> = Promise.resolve();
let loading = false;

function markDirty(): void {
  const c = app.container;
  if (!c || loading) return;
  c.dirty = true;
  changed();
  if (c.handle && c.session) saving = saving.then(() => writeToHandle()).catch(() => undefined);
}

async function containerBytes(session: ContainerSession): Promise<Uint8Array> {
  const random = await messageRandom();
  if (!random) throw new PgpError('unexpected', t('container', 'No randomness: the container was not saved.'));
  return saveContainer(session, app.keyring.certs(), random.bytes, now());
}

async function writeToHandle(): Promise<void> {
  const c = app.container!;
  if (!c.handle || !c.session) return;
  const bytes = await containerBytes(c.session);
  const writable = await c.handle.createWritable();
  await writable.write(bytes as BlobPart);
  await writable.close();
  c.dirty = false;
  changed();
}

/** Saves the container: into its file where the browser can, as a download otherwise. */
export async function saveNow(): Promise<void> {
  const c = app.container;
  if (!c) return;
  if (!c.session) {
    const password = await askPassword(t('container', 'Container password'), t('container', 'The password of the container, to save it.'));
    if (password === null) return;
    const random = await messageRandom();
    if (!random) return;
    c.session = await newContainerSession(password, random.bytes);
  }
  if (c.handle) {
    await writeToHandle();
    toast(t('container', 'Container saved'));
    return;
  }
  await saveFile(await containerBytes(c.session), c.name || CONTAINER_NAME);
  c.dirty = false;
  changed();
}

/** The keys of the container into the page's keyring; the container becomes the open one. */
async function opened(certs: Cert[], name: string, handle: FileSystemFileHandle | null, session: ContainerSession | null): Promise<void> {
  loading = true;
  try {
    await app.keyring.importCerts(certs, now());
  } finally {
    loading = false;
  }
  app.container = { name, handle, session, dirty: false };
  if (handle) await app.idb?.setHandle(handle).catch(() => undefined);
  keyringChanged();
  changed();
}

async function loadInto(bytes: Uint8Array, name: string, handle: FileSystemFileHandle | null): Promise<boolean> {
  // The PWA may keep the container's key on a passkey or a security key: a touch opens it.
  const fromDevice = await platform.containerFromDevice(bytes).catch(() => null);
  if (fromDevice) {
    try {
      await opened(await openContainerWith(bytes, fromDevice), name, handle, fromDevice);
      return true;
    } catch {
      // The file was saved with another password since: the password opens it.
    }
  }
  const pass = secretInput();
  const ok = await dialog({
    title: t('container', 'Open the container'),
    body: [h('p', { class: 'dialog-text', text: name }), field(t('container', 'Container password'), pass.node)],
    confirm: t('container', 'Open'),
    focus: pass.input,
    submit: async () => {
      try {
        const container = await openContainer(bytes, pass.input.value, now());
        await opened(container.certs, name, handle, container.session);
        return null;
      } catch (error) {
        if (error instanceof PgpError && error.code === 'bad-passphrase') return t('container', 'Wrong password.');
        throw error;
      }
    },
  });
  return ok;
}

/** Opens a container file: the remembered one, one picked with the file system, or an upload. */
export async function openContainerFile(remembered = false): Promise<void> {
  const c = app.container;
  if (remembered && c?.handle) {
    const handle = c.handle as FileSystemFileHandle & { requestPermission?: (o: object) => Promise<string> };
    if ((await handle.requestPermission?.({ mode: 'readwrite' })) === 'denied') return;
    const file = await handle.getFile();
    await loadInto(new Uint8Array(await file.arrayBuffer()), file.name, handle);
    return;
  }
  if (canWriteFiles()) {
    try {
      const [handle] = await fs.showOpenFilePicker!(PICKER_TYPES);
      const file = await handle.getFile();
      await loadInto(new Uint8Array(await file.arrayBuffer()), file.name, handle);
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'AbortError')) throw error;
    }
    return;
  }
  const input = h('input', { type: 'file', accept: '.gpg,.pgp' });
  input.addEventListener('change', () => {
    const file = input.files?.[0];
    if (file) void file.arrayBuffer().then((b) => loadInto(new Uint8Array(b), file.name, null));
  });
  input.click();
}

/** A new container for the keys in the page now: a strong password, and a file to write. */
export async function createContainer(): Promise<boolean> {
  const a = secretInput();
  const b = secretInput();
  let session: ContainerSession | null = null;
  const ok = await dialog({
    title: t('container', 'New container'),
    body: [
      t('container', 'The file holds all your keys, encrypted with this password. It can be tried offline without limit if someone gets the file: take five or more different words, or at least 16 characters.'),
      field(t('container', 'Container password'), a.node),
      field(t('password', 'Repeat the password'), b.node),
    ],
    confirm: t('container', 'Create'),
    submit: async () => {
      if (!containerPasswordStrong(a.input.value)) return t('container', 'Take five or more different words, or at least 16 characters.');
      if (a.input.value !== b.input.value) return t('password', 'The passwords differ.');
      const random = await messageRandom();
      if (!random) return '';
      session = await newContainerSession(a.input.value, random.bytes);
      return null;
    },
  });
  if (!ok || !session) return false;
  let handle: FileSystemFileHandle | null = null;
  if (canWriteFiles()) {
    try {
      handle = await fs.showSaveFilePicker!({ suggestedName: CONTAINER_NAME, ...PICKER_TYPES });
    } catch (error) {
      if (!(error instanceof DOMException && error.name === 'AbortError')) throw error;
      return false;
    }
  }
  app.container = { name: handle?.name ?? CONTAINER_NAME, handle, session, dirty: true };
  if (handle) await app.idb?.setHandle(handle).catch(() => undefined);
  await saveNow();
  changed();
  return true;
}

/** Moves the keys from this browser into a container: afterwards the browser keeps none. */
export async function moveToContainer(): Promise<void> {
  const certs = app.keyring.certs();
  if (!(await confirmAsk(t('container', 'Keep the keys in a container?'), t('container', 'The keys are written into an encrypted file, then removed from this browser. From then on the page asks for the file each time it opens.'), t('container', 'Continue'), false))) return;
  const previous = app.keyring;
  app.keyring = new Keyring(new ContainerStore());
  loading = true;
  try {
    await app.keyring.importCerts(certs, now());
  } finally {
    loading = false;
  }
  if (!(await createContainer())) {
    app.keyring = previous;
    app.container = null;
    return;
  }
  await app.idb?.clear();
  app.settings.storage = 'container';
  app.persistent = false;
  saveState();
  keyringChanged();
  toast(t('container', 'The keys are in the container now'));
}

/** Back to keeping the keys in this browser. */
export async function moveToBrowser(): Promise<void> {
  if (!app.idb) {
    toast(t('container', 'This browser does not let the page keep data.'), 'error');
    return;
  }
  if (!(await confirmAsk(t('container', 'Keep the keys in this browser?'), t('container', 'The keys of the open container are stored in this browser. The container file stays as it is.'), t('container', 'Continue'), false))) return;
  const certs = app.keyring.certs();
  app.keyring = new Keyring(app.idb);
  await app.keyring.load();
  await app.keyring.importCerts(certs, now());
  await app.idb.setHandle(null).catch(() => undefined);
  app.container = null;
  app.settings.storage = 'browser';
  app.persistent = true;
  saveState();
  keepStorage();
  keyringChanged();
  changed();
}

/** In browser mode: all keys into a container file, as a backup. */
export async function backupToContainer(): Promise<void> {
  const a = secretInput();
  const b = secretInput();
  let bytes: Uint8Array | null = null;
  const ok = await dialog({
    title: t('container', 'Save all keys to a container'),
    body: [t('container', 'One encrypted file with all your keys. GnuPG opens it too: gpg -d file | gpg --import'), field(t('container', 'Container password'), a.node), field(t('password', 'Repeat the password'), b.node)],
    confirm: t('container', 'Save'),
    submit: async () => {
      if (!containerPasswordStrong(a.input.value)) return t('container', 'Take five or more different words, or at least 16 characters.');
      if (a.input.value !== b.input.value) return t('password', 'The passwords differ.');
      const random = await messageRandom();
      if (!random) return '';
      bytes = await saveContainer(await newContainerSession(a.input.value, random.bytes), app.keyring.certs(), random.bytes, now());
      return null;
    },
  });
  if (ok && bytes) await saveFile(bytes, CONTAINER_NAME);
}

/** In browser mode: the keys of a container merged into the keyring. */
export async function importContainer(): Promise<void> {
  const input = h('input', { type: 'file', accept: '.gpg,.pgp' });
  input.addEventListener('change', () => {
    const file = input.files?.[0];
    if (!file) return;
    void file.arrayBuffer().then(async (buffer) => {
      const pass = secretInput();
      await dialog({
        title: t('container', 'Open the container'),
        body: [h('p', { class: 'dialog-text', text: file.name }), field(t('container', 'Container password'), pass.node)],
        confirm: t('container', 'Import'),
        submit: async () => {
          try {
            const opened = await openContainer(new Uint8Array(buffer), pass.input.value, now());
            const results = await app.keyring.importCerts(opened.certs, now());
            keyringChanged();
            toast(t('container', '{count} keys read from the container', { count: results.length }));
            return null;
          } catch (error) {
            if (error instanceof PgpError && error.code === 'bad-passphrase') return t('container', 'Wrong password.');
            throw error;
          }
        },
      });
    });
  });
  input.click();
}
