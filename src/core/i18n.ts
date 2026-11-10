// Interface languages: English in the code, Russian in a dictionary (src/locales/ru.ts), more
// can follow the same way.
//
// A string is looked up by its context — the part of the interface it belongs to — and its
// English text: t("keys", "New key pair"). Whatever a dictionary lacks is shown in English.
// {name} is a placeholder. A text with a number uses tn(), and the dictionary gives one text
// per plural category of the language (Intl.PluralRules), keyed by the English plural form.
// (Examples here use double quotes, so tests/i18n.test.ts does not take them for strings.)

import { ru } from '../locales/ru.ts';

export const LANGUAGES = { en: 'English', ru: 'Русский' } as const;
export type Language = keyof typeof LANGUAGES;

type Forms = Partial<Record<Intl.LDMLPluralRule, string>>;
export type Dictionary = Record<string, Record<string, string | Forms>>;

const DICTIONARIES: Partial<Record<Language, Dictionary>> = { ru };

let current: Language = 'en';
let rules = new Intl.PluralRules('en');

export const isLanguage = (value: unknown): value is Language => typeof value === 'string' && Object.hasOwn(LANGUAGES, value);

/** The first of the browser's languages that has a dictionary; English otherwise. */
export function detectLanguage(preferred: readonly string[] = typeof navigator === 'undefined' ? [] : navigator.languages): Language {
  for (const tag of preferred) {
    const base = tag.toLowerCase().split('-')[0];
    if (isLanguage(base)) return base;
  }
  return 'en';
}

export const language = (): Language => current;

export function setLanguage(next: Language): void {
  current = next;
  rules = new Intl.PluralRules(next);
  formats.clear();
}

type Values = Record<string, string | number>;

function fill(text: string, values?: Values): string {
  if (!values) return text;
  return text.replace(/\{(\w+)\}/g, (match, name: string) => (Object.hasOwn(values, name) ? String(values[name]) : match));
}

export function t(context: string, text: string, values?: Values): string {
  const found = DICTIONARIES[current]?.[context]?.[text];
  return fill(typeof found === 'string' && found ? found : text, values);
}

export function tn(context: string, one: string, other: string, count: number, values?: Values): string {
  const found = DICTIONARIES[current]?.[context]?.[other];
  const all = { count, ...values };
  if (typeof found === 'string' && found) return fill(found, all);
  if (found && typeof found === 'object') {
    const form = found[rules.select(count)] ?? found.other;
    if (form) return fill(form, all);
  }
  return fill(count === 1 ? one : other, all);
}

const formats = new Map<string, Intl.DateTimeFormat>();

export function dateFormat(options: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
  const key = JSON.stringify(options);
  let format = formats.get(key);
  if (!format) {
    format = new Intl.DateTimeFormat(current, options);
    formats.set(key, format);
  }
  return format;
}

/** The Russian dictionary, for the test that checks it against the strings in the code. */
export const DICTIONARY_FOR_TESTS = DICTIONARIES;
