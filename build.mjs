/**
 * Builds build/html-simple-pgp.html: one self-contained page, opened from disk, with no
 * network access and nothing from npm.
 *
 * There is no bundler or compiler from npm here, on purpose: every byte of the page comes
 * from this repository. Node itself strips the TypeScript types (stripTypeScriptTypes in
 * 'strip' mode puts spaces where the types were, so lines and columns stay as written), and
 * the small bundler below joins the modules. It can stay small because the code keeps to a
 * few rules, and it checks them rather than trusting them:
 *
 *   - imports are `import { a, b as c } from './x.ts'` (and `import type`, which the
 *     stripping removes), nothing else — no default, no namespace, no dynamic import();
 *   - exports are `export function|async function|const|let|class name`, nothing else;
 *   - no import cycles.
 *
 * Each module becomes a function returning an object of its exports; an import becomes a
 * destructuring of that object. The result is inlined into src/app/template.html with the
 * styles and the icon, and the Content-Security-Policy gets the hashes of exactly that script
 * and that style, so nothing else can run or style the page.
 *
 * The build is reproducible: the same commit gives the same bytes (no dates, a fixed order).
 */
import { stripTypeScriptTypes } from 'node:module';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { copyFile, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const at = (...parts) => join(root, ...parts);

const IMPORT = /^import\s*\{([^}]*)\}\s*from\s*'([^']+)'\s*;?[ \t]*$/gm;
const EXPORT = /^export\s+(async\s+function\*?|function\*?|const|let|class)\s+([A-Za-z_$][\w$]*)/gm;
const NAME = /^[A-Za-z_$][\w$]*$/;

/** Reads, strips and checks one module: its code without import lines, what it imports, what it exports. */
async function parseModule(file) {
  const where = relative(root, file);
  const source = await readFile(file, 'utf8');
  let code = stripTypeScriptTypes(source, { mode: 'strip' });
  const imports = [];
  code = code.replace(IMPORT, (_line, names, spec) => {
    if (!spec.startsWith('./') && !spec.startsWith('../')) throw new Error(`${where}: only relative imports are allowed, not '${spec}'`);
    if (!spec.endsWith('.ts')) throw new Error(`${where}: import '${spec}' must name the .ts file`);
    const bindings = names
      .split(',')
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const [name, alias = name, ...rest] = part.split(/\s+as\s+/).map((s) => s.trim());
        if (rest.length || !NAME.test(name) || !NAME.test(alias)) throw new Error(`${where}: cannot read the import '${part}'`);
        return { name, alias };
      });
    imports.push({ file: resolve(dirname(file), spec), bindings });
    return '';
  });
  const exports = [];
  code = code.replace(EXPORT, (_line, kind, name) => {
    exports.push(name);
    return `${kind} ${name}`;
  });
  // A statement, not a property named import or export (an object key, an icon's name).
  const stray = /^[ \t]*(import|export)(?=[\s{*'"])(?!\s*:)/m.exec(code) ?? /(?<![.\w])import\s*\(/.exec(code);
  if (stray) {
    const line = code.slice(0, stray.index).split('\n').length;
    throw new Error(`${where}:${line}: this import or export is outside what build.mjs understands (see the comment at its top)`);
  }
  return { file, where, code, imports, exports };
}

/**
 * Joins the modules reachable from `entry` into one script. `replace` maps a module path
 * (relative to the repository) to another one that takes its place — the PWA's
 * hardware.ts instead of the page's stub.
 */
export async function bundle(entry, { replace = {} } = {}) {
  const swap = (file) => {
    const key = relative(root, file);
    return replace[key] ? at(replace[key]) : file;
  };
  const modules = new Map();
  const order = [];
  const visiting = new Set();
  async function visit(file) {
    file = swap(file);
    if (modules.has(file)) return modules.get(file);
    if (visiting.has(file)) throw new Error(`import cycle through ${relative(root, file)}`);
    visiting.add(file);
    const mod = await parseModule(file);
    for (const dep of mod.imports) {
      dep.module = await visit(dep.file);
      for (const { name } of dep.bindings) {
        if (!dep.module.exports.includes(name)) throw new Error(`${mod.where}: ${dep.module.where} does not export ${name}`);
      }
    }
    visiting.delete(file);
    mod.id = order.length;
    modules.set(file, mod);
    order.push(mod);
    return mod;
  }
  await visit(resolve(root, entry));
  const parts = order.map((mod) => {
    const head = mod.imports
      .map((dep) => `const { ${dep.bindings.map((b) => (b.name === b.alias ? b.name : `${b.name}: ${b.alias}`)).join(', ')} } = __m${dep.module.id};`)
      .join('\n');
    return `// ${mod.where}\nconst __m${mod.id} = (() => {\n${head}\n${mod.code}\nreturn { ${mod.exports.join(', ')} };\n})();\n`;
  });
  return `(() => {\n'use strict';\n${parts.join('\n')}})();\n`;
}

const hash = (text) => `'sha256-${createHash('sha256').update(text, 'utf8').digest('base64')}'`;

/** Things that would end or confuse an inline element: the parser would leave the script or the style early. */
function assertInlinable(text, tag) {
  const bad = tag === 'script' ? /<\/script|<!--|<script/i : /<\/style/i;
  const found = bad.exec(text);
  if (found) throw new Error(`the inlined ${tag} contains "${found[0]}", which would break the page`);
}

/**
 * Nothing on the page may load from elsewhere: every src and href is a data: URI or a fragment
 * — or, in the PWA, one of its own files named in `allowed`.
 */
export function assertSelfContained(html, allowed = []) {
  const re = /\s(src|href)\s*=\s*["']?([^"'\s>]*)/gi;
  for (let m; (m = re.exec(html)); ) {
    if (!/^(data:|#)/.test(m[2]) && !allowed.includes(m[2])) throw new Error(`the page refers to something outside itself: ${m[1]}="${m[2]}"`);
  }
}

/** package.json's version, and the commit when this is not the build of tag v<version>. */
export async function readVersion() {
  const { version } = JSON.parse(await readFile(at('package.json'), 'utf8'));
  try {
    const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    const tags = git('tag', '--points-at', 'HEAD').split('\n');
    if (tags.includes(`v${version}`)) return version;
    return `${version}+${git('rev-parse', '--short', 'HEAD')}`;
  } catch {
    return version;
  }
}

const fill = (template, values) => template.replace(/\{\{([A-Z]+)\}\}/g, (whole, key) => (key in values ? values[key] : whole));

/** Under assets/; each goes to build/pages/ under its own name. */
const PWA_ICONS = ['icon.svg', 'pwa/icon-192.png', 'pwa/icon-512.png', 'pwa/icon-maskable-512.png', 'pwa/apple-touch-icon.png'];

/** What the PWA's head adds: its manifest, its icon for iOS, the colours, and the worker's name. */
const PWA_HEAD = [
  '<link rel="manifest" href="manifest.webmanifest">',
  '<link rel="apple-touch-icon" href="apple-touch-icon.png">',
  '<meta name="theme-color" content="#fbfbfa" media="(prefers-color-scheme: light)">',
  '<meta name="theme-color" content="#16171b" media="(prefers-color-scheme: dark)">',
  '<meta name="apple-mobile-web-app-capable" content="yes">',
  // The page registers the worker itself (src/pwa/update.ts): this is how it knows it is the PWA.
  '<meta name="service-worker" content="sw.js">',
].join('\n');

/**
 * The page as a string: the single file, or (pwa) the page of build/pages/, which takes
 * src/pwa/platform.ts in place of the stub — updates and WebAuthn exist only there.
 */
export async function buildPage({ version, pwa = false } = {}) {
  version ??= await readVersion();
  const script = await bundle('src/app/main.ts', { replace: pwa ? { 'src/app/platform.ts': 'src/pwa/platform.ts' } : {} });
  const style = await readFile(at('src/app/styles.css'), 'utf8');
  assertInlinable(script, 'script');
  assertInlinable(style, 'style');
  const icon = `data:image/svg+xml;base64,${(await readFile(at('assets/icon.svg'))).toString('base64')}`;
  const csp = [
    "default-src 'none'",
    `script-src ${hash(script)}`,
    `style-src ${hash(style)}`,
    // The installed app needs its manifest, its worker and its icons, from its own origin;
    // connect-src stays 'none': the page itself still reaches nothing.
    pwa ? "img-src data: blob: 'self'" : 'img-src data: blob:',
    ...(pwa ? ["manifest-src 'self'", "worker-src 'self'"] : []),
    "connect-src 'none'",
    "form-action 'none'",
    "base-uri 'none'",
    "require-trusted-types-for 'script'",
    // The PWA registers its service worker through one policy that lets through sw.js and
    // nothing else (src/pwa/update.ts); the single file allows none at all.
    pwa ? 'trusted-types sw-url' : "trusted-types 'none'",
  ].join('; ');
  const html = fill(await readFile(at('src/app/template.html'), 'utf8'), { CSP: csp, VERSION: version, ICON: icon, STYLE: style, SCRIPT: script, PWAHEAD: pwa ? PWA_HEAD : '' });
  if (/\{\{[A-Z]+\}\}/.test(html)) throw new Error('template.html has a placeholder build.mjs does not fill');
  if (!pwa && /navigator\.credentials|PublicKeyCredential/.test(html)) throw new Error('WebAuthn belongs to the PWA only, and reached the single file');
  assertSelfContained(html, pwa ? ['manifest.webmanifest', 'apple-touch-icon.png'] : []);
  return html;
}

/** build/pages/: the page plus what makes it installable. Every path is relative: any host, any domain. */
async function buildPages(version) {
  const dir = at('build', 'pages');
  const page = await buildPage({ version, pwa: true });
  // A deploy between two releases changes the page, not the version: the hash tells them apart.
  const cache = `${version}-${createHash('sha256').update(page).digest('hex').slice(0, 12)}`;
  const manifest = {
    name: 'Simple PGP',
    short_name: 'Simple PGP',
    description: 'OpenPGP for GnuPG and Kleopatra: keys, encryption and signatures, offline',
    id: './',
    start_url: './',
    scope: './',
    display: 'standalone',
    background_color: '#fbfbfa',
    theme_color: '#3555d4',
    icons: [
      { src: 'icon.svg', sizes: 'any', type: 'image/svg+xml' },
      { src: 'icon-192.png', sizes: '192x192', type: 'image/png' },
      { src: 'icon-512.png', sizes: '512x512', type: 'image/png' },
      { src: 'icon-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
    ],
  };
  const worker = (await readFile(at('src/pwa/sw.js'), 'utf8')).replaceAll('__CACHE__', cache).replaceAll('__VERSION__', version);
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  await Promise.all([
    writeFile(join(dir, 'index.html'), page),
    writeFile(join(dir, 'sw.js'), worker),
    writeFile(join(dir, 'manifest.webmanifest'), `${JSON.stringify(manifest, null, 2)}\n`),
    // GitHub Pages would run the files through Jekyll otherwise: wasted time.
    writeFile(join(dir, '.nojekyll'), ''),
    ...PWA_ICONS.map((path) => copyFile(at('assets', path), join(dir, basename(path)))),
  ]);
  return cache;
}

async function main() {
  const version = await readVersion();
  const html = await buildPage({ version });
  await mkdir(at('build'), { recursive: true });
  await writeFile(at('build', 'html-simple-pgp.html'), html);
  console.log(`build/html-simple-pgp.html  ${(html.length / 1024).toFixed(0)} KiB`);
  console.log(`build/pages/                PWA (cache ${await buildPages(version)})`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
