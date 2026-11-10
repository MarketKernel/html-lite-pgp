/**
 * The built page in a real headless Chrome, opened from disk as a user opens it, driven as a
 * user drives it: making key pairs from each source of randomness (the mouse through real
 * pointer events of the DevTools protocol), the notepad both ways, GnuPG's keys and signatures
 * coming in, verifying a key, files signed, encrypted, saved and opened again, a key made
 * from a phrase and restored, and the keys moved into a container and opened from it. Then
 * the PWA from a local server: its worker, offline, and passkeys and security keys — virtual
 * authenticators of the DevTools protocol, with and without PRF and large blobs.
 *
 * Needs `node --run build` first and a local Chrome (or CHROME=/path/to/chrome); without one
 * it says so and passes. `--shots DIR` saves screenshots of the main screens.
 */
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { CHROME, sleep, startChrome } from '../tools/chrome.mjs';

if (!CHROME) {
  console.log('No Chrome found — set CHROME=/path/to/chrome. Skipping the browser tests.');
  process.exit(0);
}

const root = fileURLToPath(new URL('..', import.meta.url));
const PAGE = pathToFileURL(join(root, 'build', 'html-simple-pgp.html')).href;
const FIXTURES = join(root, 'tests', 'fixtures', 'gnupg');
const shotsAt = process.argv.indexOf('--shots');
const SHOTS = shotsAt > 0 ? process.argv[shotsAt + 1] : null;

let failed = 0;
function check(what, ok, detail = '') {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}${ok || !detail ? '' : ` — ${detail}`}`);
  if (!ok) failed++;
}

const downloads = await mkdtemp(join(tmpdir(), 'hsp-downloads-'));
const chrome = await startChrome();
const { targetId } = await chrome.send('Target.createTarget', { url: 'about:blank' });
// Every helper below drives this session: the single file first, the PWA later.
let session = await chrome.attach(targetId, 'page');
const send = (method, params = {}) => chrome.send(method, params, session);
const evaluate = (expression) => chrome.evaluate(session, expression);
const until = (expression, timeout = 20000) => chrome.until(session, expression, timeout);
const click = (selector) => chrome.click(session, selector);
const q = (s) => JSON.stringify(s);
const TOP = `[...document.querySelectorAll('.overlay')].at(-1)`;
const dialogTitle = () => evaluate(`${TOP}?.querySelector('h2')?.textContent ?? null`);
const waitDialog = (title, timeout = 30000) => until(`${TOP}?.querySelector('h2')?.textContent === ${q(title)}`, timeout);
const noDialog = (timeout = 30000) => until(`!document.querySelector('.overlay')`, timeout);
const text = (selector) => evaluate(`document.querySelector(${q(selector)})?.textContent ?? null`);

/** Sets a field's value as typing would, then tells the page. */
async function fill(selector, value) {
  await evaluate(`(() => { const n = ${selector}; n.value = ${q(value)}; n.dispatchEvent(new Event('input', { bubbles: true })); n.dispatchEvent(new Event('change', { bubbles: true })); })()`);
}
const inTop = (selector, index = 0) => `${TOP}.querySelectorAll(${q(selector)})[${index}]`;
const submitTop = () => click('.overlay:last-of-type button[type=submit]');

async function shot(name) {
  if (!SHOTS) return;
  const { data } = await send('Page.captureScreenshot', { format: 'png' });
  const { writeFile, mkdir } = await import('node:fs/promises');
  await mkdir(SHOTS, { recursive: true });
  await writeFile(join(SHOTS, `${name}.png`), Buffer.from(data, 'base64'));
}

/** Real pointer movements over an element, spread over `ms` milliseconds: isTrusted events. */
async function wiggle(selector, count, ms) {
  const box = await evaluate(`(() => { const r = document.querySelector(${q(selector)}).getBoundingClientRect(); return [r.left, r.top, r.width, r.height]; })()`);
  for (let i = 0; i < count; i++) {
    const x = box[0] + 10 + ((i * 37) % (box[2] - 20));
    const y = box[1] + 10 + ((i * 53) % (box[3] - 20));
    await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y });
    await sleep(ms / count);
  }
}

const PASSPHRASES = { 'Alice Test': 'пароль алисы', 'Mouse Test': 'мышь', 'Phrase Test': 'новый', 'Touch Test': 'касание' };

/** If the page asks for a key's passphrase within a moment, gives it. */
async function answerPassphrase() {
  if (!(await until(`${TOP}?.querySelector('h2')?.textContent === 'Enter passphrase'`, 3000))) return;
  const who = await evaluate(`${TOP}.querySelector('.key-card strong').textContent`);
  const name = Object.keys(PASSPHRASES).find((n) => who.startsWith(n));
  await fill(inTop('.secret-field input'), PASSPHRASES[name]);
  await submitTop();
}

async function newKey({ name, email, passphrase, source, phrase, day }) {
  await click('#new-key');
  await waitDialog('New key pair');
  await fill(inTop('.dialog-input'), name);
  await fill(inTop('.dialog-input', 1), email);
  await fill(inTop('.secret-field input'), passphrase);
  await fill(inTop('.secret-field input', 1), passphrase);
  await evaluate(`(() => { const r = ${TOP}.querySelector('input[value=${source}]'); r.checked = true; r.dispatchEvent(new Event('change', { bubbles: true })); })()`);
  if (phrase) {
    await fill(inTop('.phrase-input'), phrase);
    await fill(`${TOP}.querySelector('input[type=date]')`, day);
  }
  await submitTop();
}

try {
  await send('Page.enable');
  await send('DOM.enable');
  await send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: downloads, eventsEnabled: true });
  // Headless Chrome cannot answer the system's file pickers: the page falls back to downloads and <input type=file>.
  await send('Page.addScriptToEvaluateOnNewDocument', { source: 'delete window.showOpenFilePicker; delete window.showSaveFilePicker;' });
  await send('Page.setInterceptFileChooserDialog', { enabled: true });
  let chooserFiles = [];
  chrome.listeners.add((message) => {
    if (message.method === 'Page.fileChooserOpened' && message.sessionId === session) {
      void send('DOM.setFileInputFiles', { files: chooserFiles, backendNodeId: message.params.backendNodeId });
    }
  });
  const choose = async (selector, files) => {
    chooserFiles = files;
    await click(selector);
  };

  await send('Page.navigate', { url: PAGE });
  check('the page starts', await until(`document.body.classList.contains('ready')`));
  check('the keyring is empty at first', await evaluate(`!document.getElementById('keys-empty').hidden`));
  check('HTML from a string is refused (Trusted Types)', await evaluate(`(() => { try { document.body.innerHTML = '<b>x</b>'; return false; } catch (e) { return e instanceof TypeError; } })()`));
  check(
    'an injected inline script does not run',
    await evaluate(`new Promise((done) => { window.__ran = false; try { const s = document.createElement('script'); s.textContent = 'window.__ran = true'; document.body.append(s); } catch {} setTimeout(() => done(window.__ran === false), 100); })`),
  );
  check('no WebCrypto in the page', !(await evaluate(`document.documentElement.outerHTML.includes('crypto.subtle')`)));
  await click('.nav-item[data-view=settings]');
  check('the single file offers no passkeys', await evaluate(`!document.querySelector('[data-setting^=devices]')`));
  await click('.nav-item[data-view=keys]');
  await shot('01-empty');

  // A key from the hardware generator.
  await newKey({ name: 'Alice Test', email: 'alice@example.org', passphrase: 'пароль алисы', source: 'hardware' });
  check('a key from the hardware generator is made', await waitDialog('Your key pair is ready'));
  await shot('02-new-key-ready');
  await click('.overlay:last-of-type [data-cancel]');
  await noDialog();
  check('it shows as our key', await until(`[...document.querySelectorAll('.key-row .chip')].some((c) => c.textContent === 'Your key')`));
  check('its details are open', await until(`document.querySelector('.details h2')?.textContent === 'Alice Test'`));
  check('its origin is the hardware generator', (await text('.facts')).includes('hardware generator'));
  await shot('03-key-details');

  // A key from mouse movements.
  await newKey({ name: 'Mouse Test', email: 'mouse@example.org', passphrase: 'мышь', source: 'mouse' });
  check('the mouse window opens', await waitDialog('Randomness for your new key'));
  await shot('04-entropy');
  const before = await evaluate(`document.querySelector('.entropy-percent').textContent`);
  // Events a script makes do not count.
  await evaluate(`(() => { const a = document.querySelector('[data-entropy-area]'); for (let i = 0; i < 400; i++) a.dispatchEvent(new PointerEvent('pointermove', { clientX: i, clientY: i, bubbles: true })); })()`);
  check('synthetic events are not counted', (await evaluate(`document.querySelector('.entropy-percent').textContent`)) === before);
  await wiggle('[data-entropy-area]', 330, 2600);
  check('real movements fill the pool and the key is made', await waitDialog('Your key pair is ready', 40000));
  await click('.overlay:last-of-type [data-cancel]');
  await noDialog();
  check('its origin is the mouse', await until(`document.querySelector('.facts')?.textContent.includes('mouse movements')`));

  // The notepad: encrypt to ourselves, signed; then decrypt and check.
  await click('.nav-item[data-view=notepad]');
  await evaluate(`(() => { const s = document.getElementById('np-signer'); s.value = [...s.options].find((o) => o.textContent.startsWith('Alice')).value; s.dispatchEvent(new Event('change')); })()`);
  await fill(`document.getElementById('np-text')`, 'Секретное сообщение\nвторая строка');
  await click('#np-encrypt');
  check('signing asks for the passphrase', await waitDialog('Enter passphrase'));
  await fill(inTop('.secret-field input'), 'не тот');
  await submitTop();
  check('a wrong passphrase is refused', await until(`${TOP}?.querySelector('.dialog-error')?.textContent.includes('Wrong passphrase')`));
  await fill(inTop('.secret-field input'), 'пароль алисы');
  await submitTop();
  check('the text is encrypted', await until(`document.getElementById('np-text').value.startsWith('-----BEGIN PGP MESSAGE-----')`));
  await shot('05-notepad-encrypted');
  await click('#np-decrypt');
  check('it decrypts with the remembered key', await until(`document.getElementById('np-text').value === 'Секретное сообщение\\nвторая строка'`));
  check('and the signature is good', (await text('#np-result')).includes('Good signature from'));
  await shot('06-notepad-decrypted');

  // GnuPG's key and clear-signed text.
  await click('.nav-item[data-view=keys]');
  await click('#import');
  await click('.context-menu .context-item:nth-of-type(3)');
  await waitDialog('Paste a key');
  await fill(inTop('textarea'), await readFile(join(FIXTURES, 'carol-public.asc'), 'utf8'));
  await submitTop();
  check("GnuPG's key imports", await until(`!!document.querySelector('.key-row[data-fpr="3AE9D13A5FC82B8043738CFC2CC30ACC6EDD59F3"]')`));
  await click('.nav-item[data-view=notepad]');
  await fill(`document.getElementById('np-text')`, await readFile(join(FIXTURES, 'clearsigned-by-carol.asc'), 'utf8'));
  await click('#np-decrypt');
  check("GnuPG's clear-signed text: good, not verified", await until(`document.getElementById('np-result')?.textContent.includes('Good signature from') && document.getElementById('np-result').textContent.includes('not verified')`));
  // Mark Carol's key verified.
  await click('.nav-item[data-view=keys]');
  await click('.key-row[data-fpr="3AE9D13A5FC82B8043738CFC2CC30ACC6EDD59F3"]');
  await until(`[...document.querySelectorAll('.details-actions button')].some((b) => b.textContent.includes('Mark as verified'))`);
  await evaluate(`[...document.querySelectorAll('.details-actions button')].find((b) => b.textContent.includes('Mark as verified')).click()`);
  await waitDialog('Mark as verified');
  await shot('07-verify');
  await submitTop();
  check("Carol's key becomes verified", await until(`document.querySelector('.details .chip')?.textContent === 'Verified'`));
  await click('.nav-item[data-view=notepad]');
  await fill(`document.getElementById('np-text')`, await readFile(join(FIXTURES, 'clearsigned-by-carol.asc'), 'utf8'));
  await click('#np-decrypt');
  check('the signature now counts as verified', await until(`document.getElementById('np-result')?.textContent.includes('You verified this key')`));

  // Files: encrypt one for us, save it, open the saved file.
  await click('.nav-item[data-view=files]');
  const { root: doc } = await send('DOM.getDocument', { depth: 1 });
  const { nodeId } = await send('DOM.querySelector', { nodeId: doc.nodeId, selector: '#files-picker' });
  await send('DOM.setFileInputFiles', { files: [join(FIXTURES, 'message.txt')], nodeId });
  check('a file is listed', await until(`document.querySelector('.file-name')?.textContent === 'message.txt'`));
  await click('#files-protect');
  await waitDialog('Sign / encrypt 1 file');
  await submitTop();
  check('the file is encrypted', await until(`[...document.querySelectorAll('.file-actions button')].some((b) => b.textContent.includes('message.txt.gpg'))`));
  await evaluate(`[...document.querySelectorAll('.file-actions button')].find((b) => b.textContent.includes('message.txt.gpg')).click()`);
  const saved = join(downloads, 'message.txt.gpg');
  let got = false;
  for (let i = 0; i < 50 && !got; i++) {
    got = (await readdir(downloads)).includes('message.txt.gpg');
    if (!got) await sleep(100);
  }
  check('the encrypted file downloads', got);
  await click('#files-clear');
  const again = await send('DOM.querySelector', { nodeId: (await send('DOM.getDocument', { depth: 1 })).root.nodeId, selector: '#files-picker' });
  await send('DOM.setFileInputFiles', { files: [saved], nodeId: again.nodeId });
  await until(`document.querySelector('.file-meta')?.textContent.startsWith('Encrypted')`);
  await click('#files-open');
  await answerPassphrase();
  check('it decrypts back, signed by us', await until(`[...document.querySelectorAll('.file-actions button')].some((b) => b.textContent.includes('Save message.txt')) && document.querySelector('.result')?.textContent.includes('Good signature')`));
  await shot('08-files');

  // A key from a phrase, deleted, and restored.
  await click('.nav-item[data-view=keys]');
  await newKey({ name: 'Phrase Test', email: 'phrase@example.org', passphrase: 'p', source: 'phrase', phrase: 'зелёный слон тихо идёт по мосту', day: '2026-09-01' });
  check('a key from a phrase is made', await waitDialog('Your key pair is ready', 60000));
  await click('.overlay:last-of-type [data-cancel]');
  await noDialog();
  const phraseFpr = await evaluate(`document.querySelector('.details').dataset.fpr`);
  check('it says it was made from a phrase', (await text('.details .chips')).includes('From a phrase'));
  await evaluate(`document.querySelector('.details-actions .icon-button').click()`);
  await evaluate(`[...document.querySelectorAll('.context-item')].find((b) => b.textContent.startsWith('Delete')).click()`);
  await waitDialog('Delete');
  await submitTop();
  check('the phrase key is deleted', await until(`!document.querySelector('.key-row[data-fpr="${phraseFpr}"]')`));
  await click('#import');
  await click('.context-menu .context-item:nth-of-type(4)');
  await waitDialog('Restore a key from its phrase');
  await fill(inTop('textarea'), 'Зелёный  слон тихо идёт по мосту');
  await fill(inTop('.dialog-input', 1), 'phrase@example.org');
  await fill(inTop('.dialog-input', 2), 'Phrase Test');
  await fill(`${TOP}.querySelector('input[type=date]')`, '2026-09-01');
  await fill(inTop('.secret-field input'), 'новый');
  await submitTop();
  check('the same key comes back from the phrase', await until(`!!document.querySelector('.key-row[data-fpr="${phraseFpr}"]')`, 60000));
  await noDialog();

  // The keys into a container, the page reloaded, the container opened again.
  await click('.nav-item[data-view=settings]');
  await evaluate(`[...document.querySelectorAll('#settings-body button')].find((b) => b.textContent.includes('container instead')).click()`);
  await waitDialog('Keep the keys in a container?');
  await submitTop();
  await waitDialog('New container');
  await fill(inTop('.secret-field input'), 'пять разных слов для контейнера');
  await fill(inTop('.secret-field input', 1), 'пять разных слов для контейнера');
  await submitTop();
  let container = false;
  for (let i = 0; i < 100 && !container; i++) {
    container = (await readdir(downloads)).includes('html-simple-pgp-keys.gpg');
    if (!container) await sleep(100);
  }
  check('the container is saved', container);
  await sleep(300);
  await send('Page.reload');
  check('after a reload the page asks for the container', await until(`document.body.classList.contains('ready') && !document.getElementById('container-gate').hidden`));
  await shot('09-container-gate');
  await choose('#gate-open', [join(downloads, 'html-simple-pgp-keys.gpg')]);
  await waitDialog('Open the container');
  await fill(inTop('.secret-field input'), 'пять разных слов для контейнера');
  await submitTop();
  const opened = await until(`document.querySelectorAll('.key-row[data-fpr]').length === 4`);
  check('the container opens with all the keys', opened, String(await evaluate(`[...document.querySelectorAll('.key-name')].map((n) => n.textContent).join(', ')`)));
  check('and says it is saved', await until(`document.getElementById('container-state')?.textContent === 'Saved'`));
  await shot('10-container-open');

  // Russian, the dark theme, a phone's width.
  await click('.nav-item[data-view=settings]');
  await evaluate(`(() => { const s = document.querySelector('#settings-body select'); s.value = 'ru'; s.dispatchEvent(new Event('change')); })()`);
  check('the interface speaks Russian', await until(`document.querySelector('.nav-item[data-view=keys] .nav-label')?.textContent === 'Ключи' && document.documentElement.lang === 'ru'`));
  check('the settings are drawn again in Russian', await until(`document.getElementById('settings-body').textContent.includes('Где хранятся ключи')`));
  await evaluate(`(() => { const s = document.querySelectorAll('#settings-body select')[1]; s.value = 'dark'; s.dispatchEvent(new Event('change')); })()`);
  check('the dark theme applies', (await evaluate(`document.documentElement.dataset.theme`)) === 'dark');
  await click('.nav-item[data-view=keys]');
  await shot('11-ru-dark');
  await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
  await until(`matchMedia('(max-width: 900px)').matches`);
  await shot('12-phone-list');
  await click('.key-row[data-fpr]');
  check('on a phone the details take the screen', await until(`document.body.classList.contains('show-details')`));
  await shot('13-phone-details');
  await send('Emulation.clearDeviceMetricsOverride');

  check('no errors on the page', chrome.errors.length === 0, chrome.errors.join('\n'));

  // The PWA of build/pages/, from a local server (http://localhost is a secure context).
  const { createServer } = await import('node:http');
  const { extname } = await import('node:path');
  const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.svg': 'image/svg+xml' };
  let down = false;
  const server = createServer(async (req, res) => {
    if (down) return req.socket.destroy();
    // The same app under /sub/ too: not at the root of its origin.
    const path = new URL(req.url, 'http://localhost').pathname.replace(/^\/sub\//, '/');
    const name = path === '/' ? 'index.html' : path.slice(1);
    try {
      const body = await readFile(join(root, 'build', 'pages', name));
      res.setHeader('content-type', TYPES[extname(name)] ?? 'application/octet-stream');
      res.end(body);
    } catch {
      res.statusCode = 404;
      res.end();
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const pwaUrl = `http://localhost:${server.address().port}/`;
  const pwa = await chrome.send('Target.createTarget', { url: 'about:blank' });
  const ps = await chrome.attach(pwa.targetId, 'pwa');
  await chrome.send('Page.enable', {}, ps);
  await chrome.send('Page.navigate', { url: pwaUrl }, ps);
  check('the PWA starts', await chrome.until(ps, `document.body.classList.contains('ready')`, 20000));
  check('its service worker installs', await chrome.until(ps, `navigator.serviceWorker.getRegistration().then((r) => !!r?.active)`, 20000));
  check('the PWA page carries its manifest', await chrome.evaluate(ps, `!!document.querySelector('link[rel=manifest]')`));
  // A reload goes through the worker; the mark on the old document tells the new one apart.
  const reload = async () => {
    await chrome.evaluate(ps, `window.__old = true`);
    await chrome.send('Page.reload', {}, ps);
    return chrome.until(ps, `!window.__old && document.body.classList.contains('ready')`, 20000);
  };
  check('after a reload the worker serves the page', (await reload()) && (await chrome.evaluate(ps, `!!navigator.serviceWorker.controller`)));
  down = true;
  check('offline, the PWA still opens from its cache', await reload());
  await chrome.evaluate(ps, `document.querySelector('.nav-item[data-view=settings]').click()`);
  check('the settings offer updates', await chrome.until(ps, `!!document.querySelector('[data-setting=update]')`, 10000));
  down = false;

  // Passkeys and security keys: from here on the helpers drive the PWA.
  session = ps;
  await send('WebAuthn.enable', { enableUI: false });
  const AUTHENTICATOR = { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true };
  let authenticator = null;
  /** A new security key in place of the last one: what the last one held is gone with it. */
  const plugIn = async (features) => {
    if (authenticator) await send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: authenticator });
    authenticator = (await send('WebAuthn.addVirtualAuthenticator', { options: { ...AUTHENTICATOR, ...features } })).authenticatorId;
  };
  const menuItem = async (label) => {
    await evaluate(`document.querySelector('.details-actions .icon-button').click()`);
    await until(`!!document.querySelector('.context-menu')`);
    const found = await evaluate(`(() => { const b = [...document.querySelectorAll('.context-item')].find((b) => b.textContent.startsWith(${q(label)})); if (b) b.click(); else document.querySelector('.context-item--cancel, .sheet-backdrop')?.click(); return !!b; })()`);
    if (!found) await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape' });
    return found;
  };
  const toastText = () => evaluate(`document.querySelector('.toast')?.textContent ?? ''`);
  /** Locks every key, signs a text in the notepad: 'device' when no passphrase was asked, 'passphrase' when it was, 'failed'. */
  const signLocked = async () => {
    await evaluate(`document.getElementById('forget').click()`);
    await click('.nav-item[data-view=notepad]');
    await fill(`document.getElementById('np-text')`, 'подписано касанием');
    await click('#np-sign');
    const asked = await until(`${TOP}?.querySelector('h2')?.textContent === 'Enter passphrase'`, 4000);
    if (asked) await answerPassphrase();
    const signed = await until(`document.getElementById('np-text').value.startsWith('-----BEGIN PGP SIGNED MESSAGE-----')`);
    await click('.nav-item[data-view=keys]');
    await click('.key-row[data-fpr]');
    await until(`!!document.querySelector('.details')`);
    return !signed ? 'failed' : asked ? 'passphrase' : 'device';
  };

  await plugIn({ hasPrf: true, hasLargeBlob: true });
  await click('.nav-item[data-view=settings]');
  check('the PWA explains passkeys in its settings', await until(`!!document.querySelector('[data-setting=devices]')`));
  await click('.nav-item[data-view=keys]');
  await newKey({ name: 'Touch Test', email: 'touch@example.org', passphrase: 'касание', source: 'hardware' });
  await waitDialog('Your key pair is ready');
  await click('.overlay:last-of-type [data-cancel]');
  await noDialog();
  await until(`document.querySelector('.details h2')?.textContent === 'Touch Test'`);

  // Unlock with a touch: the passphrase once, then the device.
  check('the key offers to unlock with a touch', await menuItem('Unlock with a touch'));
  await waitDialog('Unlock with a touch');
  await submitTop();
  await answerPassphrase();
  check('a passkey now unlocks the key', await until(`!!document.querySelector('.details [data-device=prf]')`));
  check('locked, the key signs after a touch, without its passphrase', (await signLocked()) === 'device');

  // The security key unplugged: the passphrase still opens the key.
  await plugIn({ hasPrf: true, hasLargeBlob: true });
  check('without the device, the passphrase is asked', (await signLocked()) === 'passphrase');

  // A wrapped copy changed in the browser: the MDC refuses it, the passphrase is asked.
  check('the device can be forgotten', await menuItem('Forget the device that unlocks it'));
  await waitDialog('The device is forgotten');
  await click('.overlay:last-of-type [data-cancel]');
  check('and the key shows it', await until(`!document.querySelector('.details [data-device=prf]')`));
  await menuItem('Unlock with a touch');
  await waitDialog('Unlock with a touch');
  await submitTop();
  await answerPassphrase();
  await until(`!!document.querySelector('.details [data-device=prf]')`);
  check('a new device unlocks it again', (await signLocked()) === 'device');
  await evaluate(`new Promise((done) => { const r = indexedDB.open('html-simple-pgp-devices'); r.onsuccess = () => { const tx = r.result.transaction('devices', 'readwrite'); const s = tx.objectStore('devices'); s.getAll().onsuccess = (e) => { for (const x of e.target.result) if (x.kind === 'prf') { x.wrapped[40] ^= 1; s.put(x); } }; tx.oncomplete = () => done(true); }; })`);
  await reload();
  await click('.key-row[data-fpr]');
  await until(`!!document.querySelector('.details [data-device=prf]')`);
  check('a changed wrapped copy does not unlock: the passphrase is asked', (await signLocked()) === 'passphrase');
  check('and the page says why', (await toastText()).includes('does not open this key'));
  await menuItem('Forget the device that unlocks it');
  await waitDialog('The device is forgotten');
  await click('.overlay:last-of-type [data-cancel]');

  // A device without PRF: a plain refusal, not an error.
  await plugIn({ hasPrf: false, hasLargeBlob: false });
  await menuItem('Unlock with a touch');
  await waitDialog('Unlock with a touch');
  await submitTop();
  await answerPassphrase();
  check('a device without PRF is refused in words', await until(`${TOP}?.textContent.includes('it has no PRF')`));
  await click('.overlay:last-of-type [data-cancel]');
  await noDialog();
  check('and nothing is recorded', await evaluate(`!document.querySelector('.details [data-device]')`));

  // The key kept on the device itself, the copy in the browser removed.
  await plugIn({ hasPrf: true, hasLargeBlob: true });
  check('the key offers to be kept on a device', await menuItem('Keep on a device'));
  await waitDialog('Keep the key on a device');
  await submitTop();
  await answerPassphrase();
  check('the device holds the key and gave it back', await waitDialog('The key is on the device'));
  await submitTop();
  check('the copy is not removed without the tick', await until(`${TOP}?.querySelector('.dialog-error')?.textContent.includes('Tick the box')`));
  await evaluate(`${TOP}.querySelector('input[type=checkbox]').click()`);
  await submitTop();
  await noDialog();
  check('the key now says its secret is not here', await until(`document.querySelector('.details .chips')?.textContent.includes('Secret not here') && !!document.querySelector('.details [data-device=blob]')`));
  const stored = await evaluate(`new Promise((done) => { const r = indexedDB.open('html-simple-pgp'); r.onsuccess = () => { r.result.transaction('keys').objectStore('keys').getAll().onsuccess = (e) => { const data = e.target.result.find((k) => k.fingerprint === document.querySelector('.details').dataset.fpr).data; const hex = Array.from(data, (b) => b.toString(16).padStart(2, '0')).join(''); done(hex.split('ff006500474e5501').length - 1); }; }; })`);
  check("the browser keeps only GnuPG's mark, no secret", stored === 2, String(stored));
  check('the passphrase is not asked: the device signs', (await signLocked()) === 'device');

  // Not at the root of its origin: no passkeys, an explanation instead.
  await chrome.send('Page.navigate', { url: `${pwaUrl}sub/` }, ps);
  await until(`location.pathname === '/sub/' && document.body.classList.contains('ready')`);
  await click('.nav-item[data-view=settings]');
  check('in a subdirectory the settings explain why passkeys are off', await until(`!!document.querySelector('[data-setting=devices-off]') && !document.querySelector('[data-setting=devices]')`));
  await click('.nav-item[data-view=keys]');
  await click('.key-row[data-fpr]');
  await until(`!!document.querySelector('.details')`);
  check('and the key offers no device', !(await menuItem('Keep on a device')) && !(await menuItem('Unlock with a touch')));

  // The container opened with a touch; the key kept on the device signs from it.
  await send('Page.addScriptToEvaluateOnNewDocument', { source: 'delete window.showOpenFilePicker; delete window.showSaveFilePicker;' });
  await send('Page.setInterceptFileChooserDialog', { enabled: true });
  await rm(join(downloads, 'html-simple-pgp-keys.gpg'), { force: true });
  await send('Page.navigate', { url: pwaUrl });
  await until(`location.pathname === '/' && document.body.classList.contains('ready')`);
  await click('.nav-item[data-view=settings]');
  await evaluate(`[...document.querySelectorAll('#settings-body button')].find((b) => b.textContent.includes('container instead')).click()`);
  await waitDialog('Keep the keys in a container?');
  await submitTop();
  await waitDialog('New container');
  await fill(inTop('.secret-field input'), 'пять разных слов для контейнера');
  await fill(inTop('.secret-field input', 1), 'пять разных слов для контейнера');
  await submitTop();
  let pwaContainer = false;
  for (let i = 0; i < 100 && !pwaContainer; i++) {
    pwaContainer = (await readdir(downloads)).includes('html-simple-pgp-keys.gpg');
    if (!pwaContainer) await sleep(100);
  }
  check('the PWA saves its container', pwaContainer);
  await until(`!!document.querySelector('[data-device=container]')`);
  await evaluate(`document.querySelector('[data-device=container]').click()`);
  check('a device is set to open the container', await until(`document.querySelector('[data-device=container]')?.textContent === 'Forget the device'`));
  await sleep(300);
  await send('Page.reload');
  await until(`document.body.classList.contains('ready') && !document.getElementById('container-gate').hidden`);
  await choose('#gate-open', [join(downloads, 'html-simple-pgp-keys.gpg')]);
  check('a touch opens the container, no password asked', await until(`document.querySelectorAll('.key-row[data-fpr]').length === 1 && !document.querySelector('.overlay')`));
  await click('.key-row[data-fpr]');
  await until(`!!document.querySelector('.details')`);
  check('the key from the container still lives on the device', (await text('.details .chips')).includes('Secret not here'));
  check('and signs after a touch', (await signLocked()) === 'device');

  server.close();
  check('no errors in the PWA', !chrome.errors.some((e) => e.startsWith('pwa')), chrome.errors.join('\n'));
} catch (error) {
  failed++;
  console.log(`FAIL ${error.stack}`);
  console.log('dialog on top:', await dialogTitle().catch(() => null));
  console.log('page errors:', chrome.errors.join('\n'));
} finally {
  await chrome.close();
  await rm(downloads, { recursive: true, force: true });
}
if (failed) {
  console.log(`${failed} failed`);
  process.exit(1);
}
console.log('browser: all passed');
