// The build: the bundler's rules, the page's policy, and the same bytes from the same sources.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
// @ts-ignore -- build.mjs is plain JavaScript without types.
import { bundle, buildPage, assertSelfContained } from '../build.mjs';

async function modules(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'hsp-build-'));
  for (const [name, text] of Object.entries(files)) await writeFile(join(dir, name), text);
  return dir;
}

test('two builds of the same sources are byte for byte the same', async () => {
  const a = await buildPage({ version: '1.2.3' });
  const b = await buildPage({ version: '1.2.3' });
  assert.equal(a, b);
});

test('the policy carries the hashes of exactly the inlined script and style', async () => {
  const html: string = await buildPage({ version: '1.2.3' });
  const csp = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)![1];
  const script = /<script>([\s\S]*)<\/script>/.exec(html)![1];
  const style = /<style>([\s\S]*)<\/style>/.exec(html)![1];
  const sha = (text: string) => `'sha256-${createHash('sha256').update(text).digest('base64')}'`;
  assert.ok(csp.includes(`script-src ${sha(script)}`));
  assert.ok(csp.includes(`style-src ${sha(style)}`));
  assert.ok(csp.includes("connect-src 'none'"));
  assert.ok(csp.includes("default-src 'none'"));
  assert.ok(!csp.includes('unsafe-inline'));
});

test('modules are joined with their imports and exports', async () => {
  const dir = await modules({
    'a.ts': "import { twice as double } from './b.ts';\nimport type { N } from './b.ts';\nexport const result: N = double(21);\n",
    'b.ts': 'export type N = number;\nexport function twice(n: number): number { return n * 2; }\n',
  });
  const code: string = await bundle(join(dir, 'a.ts'));
  assert.equal(new Function(`return ${code.replace(/\}\)\(\);\n$/, '')}return __m1.result; })();`)(), 42);
  await rm(dir, { recursive: true });
});

test('the bundler refuses what it does not understand', async () => {
  const cases: Record<string, string> = {
    'default export': 'export default 1;\n',
    'npm import': "import { x } from 'some-package';\n",
    'namespace import': "import * as b from './b.ts';\n",
    'dynamic import': "const b = import('./b.ts');\n",
    're-export': "export { y } from './b.ts';\n",
    'missing name': "import { nothing } from './b.ts';\n",
  };
  for (const [what, text] of Object.entries(cases)) {
    const dir = await modules({ 'a.ts': text, 'b.ts': 'export const y = 1;\n' });
    await assert.rejects(bundle(join(dir, 'a.ts')), undefined, what);
    await rm(dir, { recursive: true });
  }
  const dir = await modules({ 'a.ts': "import { y } from './b.ts';\nexport const x = y;\n", 'b.ts': "import { x } from './a.ts';\nexport const y = x;\n" });
  await assert.rejects(bundle(join(dir, 'a.ts')), /cycle/);
  await rm(dir, { recursive: true });
});

test('a page that refers outside itself is refused', () => {
  assert.throws(() => assertSelfContained('<script src="https://cdn.example/x.js"></script>'));
  assert.throws(() => assertSelfContained('<link rel="stylesheet" href="style.css">'));
  assertSelfContained('<link rel="icon" href="data:image/svg+xml;base64,AAAA"><a href="#top">');
});

test('every module keeps to the bundler’s rules', async () => {
  const { readdirSync, statSync } = await import('node:fs');
  const walk = (dir: string): string[] =>
    readdirSync(dir).flatMap((name) => {
      const path = join(dir, name);
      return statSync(path).isDirectory() ? walk(path) : path.endsWith('.ts') ? [path] : [];
    });
  const src = new URL('../src', import.meta.url).pathname;
  for (const file of walk(src)) await bundle(file);
});
