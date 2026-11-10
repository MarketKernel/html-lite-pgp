// What only the installed app (the PWA of build/pages/) adds to the page: updates of itself,
// and unlocking or keeping keys with a passkey or a security key (WebAuthn needs an https
// origin, which a file opened from disk has not). In the single file this module is all there
// is — it adds nothing; build.mjs puts src/pwa/platform.ts in its place for the PWA.

import type { ContainerSession } from '../core/container.ts';
import type { Secret } from '../core/secret.ts';
import type { KeyView } from './model.ts';

/**
 * What the page lends the PWA's code when it starts: actions of its own that the PWA offers
 * too. Passed in rather than imported, as those modules import this one.
 */
export interface PlatformContext {
  /** Draws the settings again. */
  redraw(): void;
  /** The secrets of our key after its passphrase (asked even if it is unlocked), or null. */
  unlockWithPassphrase(view: KeyView): Promise<Map<string, Secret> | null>;
  /** Saves a backup of our key's secret, under a passphrase. */
  backupSecret(view: KeyView): Promise<void>;
  /** Saves all keys into a new container file. */
  backupToContainer(): Promise<void>;
  /** Puts a copy of our key's secret back into the keyring, under a new passphrase. */
  keepCopy(view: KeyView): Promise<void>;
}

export interface Platform {
  /** True in the PWA. */
  readonly pwa: boolean;
  /** Called once the page is up. */
  start(context: PlatformContext): void;
  /** Rows the settings view shows in addition to its own. */
  settingsRows(): HTMLElement[];
  /** Menu items the details of our key show in addition (label, action). */
  keyActions(view: KeyView): { label: string; action: () => void }[];
  /** Chips the details of a key show in addition. */
  keyChips(view: KeyView): HTMLElement[];
  /** Secrets of our key from a device, if one holds them; null to ask for the passphrase. */
  unlockWithDevice(view: KeyView): Promise<Map<string, Secret> | null>;
  /** The session of a container file from a device, if one keeps it; null to ask for the password. */
  containerFromDevice(bytes: Uint8Array): Promise<ContainerSession | null>;
  /** A key left the keyring: what a device kept for it goes too. */
  keyDeleted(fingerprint: string): void;
}

export const platform: Platform = {
  pwa: false,
  start: () => undefined,
  settingsRows: () => [],
  keyActions: () => [],
  keyChips: () => [],
  unlockWithDevice: async () => null,
  containerFromDevice: async () => null,
  keyDeleted: () => undefined,
};
