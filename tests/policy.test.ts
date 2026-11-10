// What keeps the program free of anyone else's code: no packages, no imports from outside,
// no WebCrypto, and the few browser entry points that matter in one place each.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));

function files(dir: string, re: RegExp): string[] {
  const out: string[] = [];
  for (const name of readdirSync(join(root, dir))) {
    const path = join(dir, name);
    if (statSync(join(root, path)).isDirectory()) out.push(...files(path, re));
    else if (re.test(name)) out.push(path);
  }
  return out;
}

const code = (path: string) => readFileSync(join(root, path), 'utf8');
const sources = files('src', /\.ts$/);

test('package.json has no dependencies, and there is nothing installed', () => {
  const pkg = JSON.parse(code('package.json'));
  for (const key of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies']) {
    assert.equal(pkg[key], undefined, `package.json must not have ${key}`);
  }
  assert.ok(!existsSync(join(root, 'node_modules')), 'node_modules must not exist');
  assert.ok(!existsSync(join(root, 'package-lock.json')), 'package-lock.json must not exist');
});

test('every import is relative or a part of Node', () => {
  const all = [...sources, ...files('tests', /\.(ts|mjs)$/), ...files('tools', /\.(ts|mjs)$/), 'build.mjs'];
  for (const path of all) {
    for (const m of code(path).matchAll(/(?:^|\n)\s*(?:import|export)[^'"\n]*?from\s*['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]/g)) {
      const spec = m[1] ?? m[2];
      assert.ok(spec.startsWith('./') || spec.startsWith('../') || spec.startsWith('node:'), `${path} imports '${spec}'`);
    }
  }
});

test('the program uses none of what it must not', () => {
  const banned: [RegExp, string][] = [
    [/crypto\.subtle|\bsubtle\./, 'WebCrypto: the cryptography is ours'],
    [/\bfetch\s*\(|XMLHttpRequest|\bWebSocket\b|EventSource|sendBeacon/, 'the network'],
    [/\beval\s*\(|new\s+Function\b/, 'code from strings'],
    [/\.innerHTML\b|\.outerHTML\b|insertAdjacentHTML|document\.write/, 'HTML from strings'],
    [/Math\.random/, 'Math.random: randomness comes from random.ts'],
  ];
  for (const path of sources) {
    const text = code(path);
    for (const [re, why] of banned) assert.ok(!re.test(text), `${path}: ${why}`);
  }
});

test('the few sensitive entry points live in one file each', () => {
  for (const path of sources) {
    const text = code(path);
    const at = relative('src', path);
    if (/getRandomValues/.test(text)) assert.equal(at, 'core/crypto/random.ts', `${path} calls getRandomValues`);
    if (/navigator\.credentials|PublicKeyCredential/.test(text)) assert.equal(at, 'pwa/hardware.ts', `${path} uses WebAuthn`);
    if (at.startsWith('core/crypto/')) assert.ok(!/\bBigInt\b|(?<![\w.])\d+n\b/.test(text), `${path}: no BigInt in the primitives`);
    if (at.startsWith('core/')) assert.ok(!/\bdocument\.|\bwindow\./.test(text), `${path}: the core has no DOM`);
  }
});
