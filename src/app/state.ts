// What the page holds while it runs: the keyring, the agent with unlocked keys, the settings,
// and the listeners that redraw what depends on the keyring when it changes.

import { Agent } from '../core/agent.ts';
import type { ContainerSession } from '../core/container.ts';
import { Keyring } from '../core/keyring.ts';
import type { KeyStore } from '../core/keyring.ts';
import { loadSettings, saveSettings } from './settings.ts';
import type { Settings } from './settings.ts';
import type { IdbStore } from './store.ts';

export interface ContainerState {
  /** The file's name, as shown. */
  name: string;
  /** Chrome and Edge: the file itself, to save into. */
  handle: FileSystemFileHandle | null;
  /** The container's key and its SKESK, to save again without asking for the password. */
  session: ContainerSession | null;
  /** Changes not yet written to the file. */
  dirty: boolean;
}

const settings = loadSettings();

export const app = {
  settings: settings as Settings,
  keyring: new Keyring(null as unknown as KeyStore),
  agent: new Agent(settings.cacheMinutes * 60_000),
  /** False when the keys last only as long as the page (no IndexedDB, or a container). */
  persistent: true,
  idb: null as IdbStore | null,
  container: null as ContainerState | null,
};

export const now = (): number => Math.floor(Date.now() / 1000);

const listeners = new Set<() => void>();

export const onKeyringChange = (listener: () => void): void => void listeners.add(listener);

export function keyringChanged(): void {
  for (const listener of listeners) listener();
}

export function saveState(): void {
  saveSettings(app.settings);
  app.agent.ttl = app.settings.cacheMinutes * 60_000;
}
