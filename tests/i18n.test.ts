// The Russian dictionary against the strings in the code: every string translated, every
// translation used, placeholders kept, plural forms complete.
import { test } from 'node:test';
import assert from 'node:assert/strict';
// @ts-ignore -- tools/i18n.mjs is plain JavaScript.
import { extract } from '../tools/i18n.mjs';
import { ru } from '../src/locales/ru.ts';

const found: Map<string, Set<string>> = extract();
const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

test('every string of the interface has a Russian translation', () => {
  const missing: string[] = [];
  for (const [context, texts] of found) for (const text of texts) if (ru[context]?.[text] === undefined) missing.push(`${context}: ${text}`);
  assert.deepEqual(missing, []);
});

test('every translation is used', () => {
  const unused: string[] = [];
  for (const [context, texts] of Object.entries(ru)) for (const text of Object.keys(texts)) if (!found.get(context)?.has(text)) unused.push(`${context}: ${text}`);
  assert.deepEqual(unused, []);
});

test('translations keep the placeholders, and plural forms are complete', () => {
  const rules = new Intl.PluralRules('ru').resolvedOptions().pluralCategories;
  for (const [context, texts] of Object.entries(ru)) {
    for (const [english, translation] of Object.entries(texts)) {
      if (typeof translation === 'string') {
        assert.ok(translation, `${context}: ${english} is empty`);
        assert.deepEqual(placeholders(translation), placeholders(english), `${context}: ${english}`);
      } else {
        for (const category of rules) assert.ok(translation[category], `${context}: ${english} lacks the "${category}" form`);
        for (const form of Object.values(translation)) assert.deepEqual(placeholders(form!), placeholders(english), `${context}: ${english}`);
      }
    }
  }
});
