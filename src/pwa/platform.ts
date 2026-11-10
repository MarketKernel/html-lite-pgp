// The PWA's additions to the page (see src/app/platform.ts, whose place this module takes in
// build/pages/): updates of the installed app by a button, and — devices.ts — unlocking or
// keeping keys with a passkey or a security key.

import { t } from '../core/i18n.ts';
import type { Platform } from '../app/platform.ts';
import { confirmAsk, h, toast } from '../app/ui.ts';
import { containerFromDevice, deviceActions, deviceChips, deviceSettings, keyDeleted, startDevices, unlockWithDevice } from './devices.ts';
import { applyUpdate, canUpdate, checkForUpdate, justUpdated, startUpdates, updateState } from './update.ts';

let redraw = (): void => undefined;

function updateRow(): HTMLElement | null {
  if (!canUpdate()) return null;
  const now = updateState();
  let note = '';
  let action = t('pwa', 'Check for updates');
  if (now.kind === 'checking') note = t('pwa', 'Checking…');
  else if (now.kind === 'latest') note = t('pwa', 'This is the latest version.');
  else if (now.kind === 'offline') note = t('pwa', 'No connection: could not check for updates.');
  else if (now.kind === 'ready') {
    note = now.version ? t('pwa', 'Version {version} is ready.', { version: now.version }) : t('pwa', 'A new version is ready.');
    action = t('pwa', 'Update');
  }
  const go = h('button', { type: 'button', class: `button button--small${now.kind === 'ready' ? ' button--primary' : ''}`, text: action });
  go.disabled = now.kind === 'checking';
  go.addEventListener('click', () => {
    if (now.kind !== 'ready') return void checkForUpdate();
    void confirmAsk(t('pwa', 'Update now?'), t('pwa', 'The page reloads: the text in the notepad and the list of files are cleared.'), t('pwa', 'Update'), false).then((ok) => ok && applyUpdate());
  });
  return h('div', { class: 'settings-row', 'data-setting': 'update' }, h('div', { class: 'settings-text' }, h('div', { class: 'settings-title', text: t('pwa', 'Updates') }), note ? h('div', { class: 'settings-hint', text: note }) : null), go);
}

export const platform: Platform = {
  pwa: true,
  start(context) {
    redraw = context.redraw;
    startUpdates(() => redraw());
    void startDevices(context);
    if (justUpdated()) toast(t('pwa', 'Updated to version {version}.', { version: document.querySelector('meta[name="version"]')?.getAttribute('content') ?? '' }));
  },
  settingsRows(): HTMLElement[] {
    const rows = deviceSettings();
    const update = updateRow();
    return update ? [update, ...rows] : rows;
  },
  keyActions: deviceActions,
  keyChips: deviceChips,
  unlockWithDevice,
  containerFromDevice,
  keyDeleted: (fingerprint) => void keyDeleted(fingerprint),
};
