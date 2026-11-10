/**
 * The interface's strings, found in the code and the template: t('context', 'text'),
 * tn('context', 'one', 'other', n), data-i18n and data-i18n-attr. With no arguments it prints
 * what the Russian dictionary lacks, as an object to fill in; tests/i18n.test.ts uses the same
 * extraction to check the dictionary.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const STR = `('(?:[^'\\\\]|\\\\.)*'|"(?:[^"\\\\]|\\\\.)*")`;
const T = new RegExp(`(?<![\\w.])t\\(\\s*'([\\w-]+)'\\s*,\\s*${STR}`, 'g');
const TN = new RegExp(`(?<![\\w.])tn\\(\\s*'([\\w-]+)'\\s*,\\s*${STR}\\s*,\\s*${STR}`, 'g');

const unquote = (s) => s.slice(1, -1).replace(/\\(.)/g, '$1');

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : path.endsWith('.ts') && !path.includes('/locales/') ? [path] : [];
  });
}

/** Map of context → Set of English keys. */
export function extract() {
  const found = new Map();
  const add = (context, text) => {
    if (!found.has(context)) found.set(context, new Set());
    found.get(context).add(text);
  };
  for (const file of walk(join(root, 'src'))) {
    // Comments may show examples; they are written with double quotes inside t(...) and are skipped by this rule.
    const code = readFileSync(file, 'utf8').replace(/^\s*\/\/.*$/gm, '');
    for (const m of code.matchAll(T)) add(m[1], unquote(m[2]));
    for (const m of code.matchAll(TN)) add(m[1], unquote(m[3]));
  }
  const html = readFileSync(join(root, 'src/app/template.html'), 'utf8');
  for (const m of html.matchAll(/<(\w+)([^>]*?)\sdata-i18n="([\w-]+)"([^>]*)>([\s\S]*?)<\/\1>/g)) {
    const inner = m[5].replace(/<(\w+)[^>]*data-slot="(\w+)"[^>]*>[\s\S]*?<\/\1>/g, '{$2}').replace(/<[^>]+>/g, '');
    add(m[3], inner.replace(/\s+/g, ' ').trim());
  }
  for (const m of html.matchAll(/<\w+([^>]*)\sdata-i18n-attr="([\w-]+)"([^>]*)>/g)) {
    const attrs = m[1] + m[3];
    for (const a of attrs.matchAll(/\s(title|placeholder|aria-label)="([^"]*)"/g)) add(m[2], a[2]);
  }
  return found;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const { ru } = await import('../src/locales/ru.ts');
  const missing = {};
  for (const [context, texts] of extract()) {
    for (const text of texts) {
      if (ru[context]?.[text] === undefined) (missing[context] ??= {})[text] = '';
    }
  }
  console.log(JSON.stringify(missing, null, 2));
}
