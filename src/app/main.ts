// The page: settings and language first, then the keys (from this browser or a container),
// then the four views — keys, notepad, files, settings — and what ties them together: the
// navigation, shortcuts, files dropped on the window, other windows changing the keyring.

import { language, setLanguage, t } from '../core/i18n.ts';
import { classify } from '../core/pgp.ts';
import { addFiles, bindFiles } from './files.ts';
import { backupSecret, changePassphrase, importFiles, newKeyPair } from './keyactions.ts';
import { bindKeyList, focusSearch, importMenu, renderList } from './keylist.ts';
import { bindNotepad, loadNotepad } from './notepad.ts';
import { bindScreens, hideDetails, isTouch } from './screens.ts';
import { applyTheme, resolveLanguage } from './settings.ts';
import type { View } from './settings.ts';
import { bindSettings, redraw, renderSettings } from './settingsview.ts';
import { app, keyringChanged, saveState } from './state.ts';
import { backupToContainer, containerOpen, createContainer, moveToBrowser, onContainerChange, openContainerFile, saveNow, startStorage } from './storage.ts';
import { unlockKey } from './unlock.ts';
import { onStoreChanged } from './store.ts';
import { platform } from './platform.ts';
import { translatePage } from './translate.ts';
import { toast } from './ui.ts';

const $ = <T extends HTMLElement>(id: string): T => document.getElementById(id) as T;
const VIEWS: View[] = ['keys', 'notepad', 'files', 'settings'];

export function setView(view: View): void {
  app.settings.view = view;
  saveState();
  for (const name of VIEWS) {
    $(`view-${name}`).hidden = name !== view;
    document.querySelector(`.nav-item[data-view="${name}"]`)?.setAttribute('aria-current', name === view ? 'page' : 'false');
  }
  document.body.dataset['view'] = view;
  if (view !== 'keys') hideDetails();
  if (view === 'settings') renderSettings();
}

function bindNav(): void {
  for (const button of document.querySelectorAll<HTMLElement>('.nav-item[data-view]')) {
    button.addEventListener('click', () => setView(button.dataset['view'] as View));
  }
  const forget = $('forget');
  const update = (): void => {
    forget.hidden = app.agent.size === 0;
    forget.title = t('nav', 'Lock the unlocked secret keys again');
  };
  forget.addEventListener('click', () => {
    app.agent.forgetAll();
    toast(t('nav', 'Passphrases forgotten'));
  });
  app.agent.onChange(update);
  update();
}

const mod = (event: KeyboardEvent): boolean => (navigator.platform.startsWith('Mac') ? event.metaKey : event.ctrlKey);

function bindShortcuts(): void {
  document.addEventListener('keydown', (event) => {
    if (document.querySelector('.overlay, .context-menu')) return;
    if (!mod(event) || event.altKey) return;
    const key = event.key.toLowerCase();
    if (key === 'f' && app.settings.view === 'keys') {
      event.preventDefault();
      focusSearch();
    } else if (key === 'n' && event.shiftKey) {
      event.preventDefault();
      setView('keys');
      void newKeyPair();
    } else if (key === 'i' && event.shiftKey) {
      event.preventDefault();
      setView('keys');
      importMenu($('import'));
    }
  });
  if (isTouch()) document.body.classList.add('touch');
}

function bindDrop(): void {
  let depth = 0;
  const hasFiles = (event: DragEvent): boolean => [...(event.dataTransfer?.types ?? [])].includes('Files');
  document.addEventListener('dragenter', (event) => {
    if (!hasFiles(event)) return;
    depth += 1;
    document.body.classList.add('dropping');
  });
  document.addEventListener('dragleave', () => {
    depth = Math.max(0, depth - 1);
    if (!depth) document.body.classList.remove('dropping');
  });
  document.addEventListener('dragover', (event) => {
    if (hasFiles(event)) event.preventDefault();
  });
  document.addEventListener('drop', (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    depth = 0;
    document.body.classList.remove('dropping');
    const files = [...(event.dataTransfer?.files ?? [])];
    if (!files.length || document.querySelector('.overlay')) return;
    void (async () => {
      if (app.settings.view === 'notepad' && files.length === 1 && files[0].size < 1 << 20) {
        const text = await files[0].text();
        const kind = classify(text);
        if (kind !== 'unknown' && kind !== 'public-keys' && kind !== 'secret-keys') {
          loadNotepad(text);
          return;
        }
      }
      const kinds = await Promise.all(files.map(async (file) => classify(new Uint8Array(await file.arrayBuffer()))));
      if (app.settings.view === 'keys' && kinds.every((k) => k === 'public-keys' || k === 'secret-keys' || k === 'revocation')) {
        await importFiles(files);
        return;
      }
      setView('files');
      await addFiles(files);
    })();
  });
}

/** Container mode: the gate before the container is open, the bar with its state after. */
function bindContainer(): void {
  const update = () => {
    const c = app.container;
    const gated = app.settings.storage === 'container' && !containerOpen();
    $('container-gate').hidden = !gated;
    document.body.classList.toggle('container-gated', gated);
    if (gated) {
      $('keys-empty').hidden = true;
      $('keys-table').hidden = true;
      const remembered = $('gate-remembered') as HTMLButtonElement;
      remembered.hidden = !c?.handle;
      if (c?.handle) remembered.textContent = t('container', 'Open {name}', { name: c.handle.name });
    }
    $('container-bar').hidden = !c || gated;
    if (c && !gated) {
      $('container-name').textContent = c.name;
      $('container-state').textContent = c.dirty ? t('container', 'Not saved') : t('container', 'Saved');
      $('container-state').classList.toggle('container-state--dirty', c.dirty);
    }
  };
  $('gate-remembered').addEventListener('click', () => void openContainerFile(true).catch((e: Error) => toast(e.message, 'error')));
  $('gate-open').addEventListener('click', () => void openContainerFile(false).catch((e: Error) => toast(e.message, 'error')));
  $('gate-new').addEventListener('click', () => void createContainer().then(() => keyringChanged()));
  $('gate-browser').addEventListener('click', () => void moveToBrowser());
  $('container-save').addEventListener('click', () => void saveNow().catch((e: Error) => toast(e.message, 'error')));
  onContainerChange(update);
  const after = renderList;
  redraw.all = () => {
    document.documentElement.lang = language();
    translatePage();
    keyringChanged();
    after();
    renderSettings();
    update();
  };
  window.addEventListener('beforeunload', (event) => {
    // Unsaved keys in a container would be lost with the page.
    if (app.container?.dirty) event.preventDefault();
  });
  update();
}

async function start(): Promise<void> {
  setLanguage(resolveLanguage(app.settings.language));
  document.documentElement.lang = language();
  applyTheme(app.settings.theme);
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => applyTheme(app.settings.theme));
  translatePage();
  $('version').textContent = document.querySelector('meta[name="version"]')?.getAttribute('content') ?? '';
  await startStorage();
  bindScreens(() => document.body.classList.contains('details-open'));
  bindNav();
  bindKeyList();
  bindNotepad();
  bindFiles();
  bindSettings();
  bindShortcuts();
  bindDrop();
  bindContainer();
  // A container not yet open is asked for first, on the keys view, whatever view was last.
  setView(app.settings.storage === 'container' && !containerOpen() ? 'keys' : app.settings.view);
  platform.start({
    redraw: () => {
      if (app.settings.view === 'settings') renderSettings();
    },
    unlockWithPassphrase: (v) => unlockKey(v, 'change', { fresh: true }),
    backupSecret,
    backupToContainer,
    keepCopy: changePassphrase,
  });
  onStoreChanged(() => {
    if (app.settings.storage === 'browser') void app.keyring.load().then(keyringChanged);
  });
  if (!app.persistent && app.settings.storage === 'browser') toast(t('errors', 'This browser does not let the page keep data: the keys are lost when the page closes.'), 'error');
  document.body.classList.add('ready');
}

void start();
