// Preferences, remembered in localStorage between sessions. Every field is checked when read:
// an unknown or broken value is the default again. Nothing secret is ever kept here.

import { detectLanguage, isLanguage } from '../core/i18n.ts';
import type { Language } from '../core/i18n.ts';

export type Theme = 'system' | 'light' | 'dark';
export type View = 'keys' | 'notepad' | 'files' | 'settings';
export type KeyFilter = 'all' | 'mine' | 'verified' | 'unverified' | 'unusable';
/** Where the random bytes of messages come from (Task.md §4.5). */
export type MessageRandom = 'hardware' | 'mouse';
/** Where the keys are kept (Task.md §5.1). */
export type Storage = 'browser' | 'container';

export interface Settings {
  language: Language | 'auto';
  theme: Theme;
  view: View;
  filter: KeyFilter;
  /** Minutes an unlocked secret key stays unlocked; 0 — the passphrase is asked every time. */
  cacheMinutes: number;
  /** Files written as ASCII armor (.asc) rather than binary (.gpg, .sig). */
  armorFiles: boolean;
  encryptToSelf: boolean;
  /** The user's key to sign with and encrypt to by default; empty — the first one. */
  defaultKey: string;
  /** Years a new key is valid; 0 — no expiry. */
  validYears: number;
  messageRandom: MessageRandom;
  storage: Storage;
}

const KEY = 'html-simple-pgp';

export const CACHE_CHOICES = [0, 1, 5, 10, 30, 60, 240];
export const YEAR_CHOICES = [1, 2, 3, 5, 0];
const VIEWS: View[] = ['keys', 'notepad', 'files', 'settings'];
const FILTERS: KeyFilter[] = ['all', 'mine', 'verified', 'unverified', 'unusable'];

export const DEFAULTS: Settings = {
  language: 'auto',
  theme: 'system',
  view: 'keys',
  filter: 'all',
  cacheMinutes: 10,
  armorFiles: false,
  encryptToSelf: true,
  defaultKey: '',
  // GnuPG and Kleopatra give a new key three years.
  validYears: 3,
  messageRandom: 'hardware',
  storage: 'browser',
};

export function loadSettings(): Settings {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULTS };
    const s = JSON.parse(raw) as Partial<Record<keyof Settings, unknown>>;
    return {
      language: isLanguage(s.language) ? s.language : 'auto',
      theme: s.theme === 'light' || s.theme === 'dark' ? s.theme : 'system',
      view: VIEWS.includes(s.view as View) ? (s.view as View) : DEFAULTS.view,
      filter: FILTERS.includes(s.filter as KeyFilter) ? (s.filter as KeyFilter) : DEFAULTS.filter,
      cacheMinutes: CACHE_CHOICES.includes(Number(s.cacheMinutes)) ? Number(s.cacheMinutes) : DEFAULTS.cacheMinutes,
      armorFiles: typeof s.armorFiles === 'boolean' ? s.armorFiles : DEFAULTS.armorFiles,
      encryptToSelf: typeof s.encryptToSelf === 'boolean' ? s.encryptToSelf : DEFAULTS.encryptToSelf,
      defaultKey: typeof s.defaultKey === 'string' && /^[0-9A-F]{40}$/.test(s.defaultKey) ? s.defaultKey : '',
      validYears: YEAR_CHOICES.includes(Number(s.validYears)) ? Number(s.validYears) : DEFAULTS.validYears,
      messageRandom: s.messageRandom === 'mouse' ? 'mouse' : 'hardware',
      storage: s.storage === 'container' ? 'container' : 'browser',
    };
  } catch {
    return { ...DEFAULTS };
  }
}

export function saveSettings(settings: Settings): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(settings));
  } catch {
    /* private mode or a full quota — the app works either way */
  }
}

export const resolveLanguage = (choice: Settings['language']): Language => (choice === 'auto' ? detectLanguage() : choice);

export function applyTheme(theme: Theme): void {
  const dark = theme === 'dark' || (theme === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.dataset['theme'] = dark ? 'dark' : 'light';
}
