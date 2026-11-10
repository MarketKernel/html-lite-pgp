// What can be done with keys, each as a dialog: making a key pair from the chosen source of
// randomness or from a phrase, restoring one from its phrase, importing, exporting, backing
// up, changing, revoking, marking as verified, deleting.

import { armor } from '../core/armor.ts';
import { PgpError } from '../core/errors.ts';
import { generate, restore } from '../core/generate.ts';
import type { Generated } from '../core/generate.ts';
import { t, tn } from '../core/i18n.ts';
import { applyRevocation, fingerprintHex, keyState, markVerified, revocationSignature, withExpiry, writeCert, REASON } from '../core/keys.ts';
import type { Cert, KeyPacket } from '../core/keys.ts';
import { MIN_WORDS, distinctWords, normalizeEmail } from '../core/phrase.ts';
import { classify, readKeys, readRevocation } from '../core/pgp.ts';
import { protectAll } from '../core/secret.ts';
import type { Secret } from '../core/secret.ts';
import type { ImportResult, KeySource } from '../core/keyring.ts';
import { revocationText } from '../core/generate.ts';
import { SIG, exportable, issuerFingerprint } from '../core/signature.ts';
import { hardwareReady, keyRandom, messageRandom } from './entropy.ts';
import { allViews, fingerprintGroups, keyIdLabel, label, named, ownSigning, viewOf } from './model.ts';
import type { KeyView } from './model.ts';
import { copyText, readClipboard, safeName, saveFile } from './save.ts';
import { YEAR_CHOICES } from './settings.ts';
import { app, keyringChanged, now, saveState } from './state.ts';
import { keepStorage } from './store.ts';
import { checkbox, confirmAsk, dialog, field, h, inform, secretInput, select, textInput, toast } from './ui.ts';
import { seedOf, unlockKey } from './unlock.ts';
import { platform } from './platform.ts';

/** Set by the key list: shows a key after it was made or imported. */
export const selection = { show: (_fingerprint: string): void => undefined };

const YEAR = 365 * 86400;

function yearsLabel(years: number): string {
  return years === 0 ? t('newkey', 'Does not expire') : tn('newkey', '{count} year', '{count} years', years);
}

function progressBar(): { node: HTMLElement; set: (done: number) => void } {
  const fill = h('span', { class: 'progress-fill' });
  const node = h('div', { class: 'progress', hidden: '' }, fill);
  return { node, set: (d) => ((node.hidden = false), (fill.style.width = `${Math.round(d * 100)}%`)) };
}

const today = (): string => new Date(now() * 1000).toISOString().slice(0, 10);

async function stored(generated: Generated, source: KeySource): Promise<void> {
  await app.keyring.put(generated.cert, source, now());
  keepStorage();
  keyringChanged();
  selection.show(fingerprintHex(generated.cert.primary.fingerprint));
}

/** After a key is made: its revocation certificate, and a backup, while it is fresh in mind. */
async function afterNewKey(generated: Generated): Promise<void> {
  const v = viewOf(app.keyring.get(fingerprintHex(generated.cert.primary.fingerprint))!);
  const saveRevocation = h('button', { type: 'button', class: 'button button--small', text: t('newkey', 'Save the revocation certificate') });
  saveRevocation.addEventListener('click', () => void saveFile(generated.revocation, `${safeName(label(v))}_${keyIdLabel(v.keyId)}_revocation.asc`));
  const backup = h('button', { type: 'button', class: 'button button--small', text: t('newkey', 'Back up the secret key') });
  backup.addEventListener('click', () => void saveFile(armor('PRIVATE KEY BLOCK', writeCert(v.entry.cert, { secret: true })), `${safeName(label(v))}_${keyIdLabel(v.keyId)}_SECRET.asc`));
  await inform(
    t('newkey', 'Your key pair is ready'),
    h('div', { class: 'key-card' }, h('strong', { text: label(v) }), h('span', { class: 'mono key-card-fpr', text: fingerprintGroups(v.fingerprint) })),
    app.persistent
      ? t('newkey', 'The key lives in this browser only. Back it up now, and keep the revocation certificate apart from it: if the key is ever lost or stolen, that file revokes it.')
      : t('newkey', 'The key lives only in this page and in your container: save the container. Keep the revocation certificate apart: if the key is ever lost or stolen, that file revokes it.'),
    h('div', { class: 'dialog-buttons' }, saveRevocation, backup),
  );
}

type SourceChoice = 'hardware' | 'mouse' | 'phrase';

function sourceCard(value: SourceChoice, title: string, text: string, checked: boolean, disabled = false, reason = ''): { input: HTMLInputElement; node: HTMLElement } {
  const input = h('input', { type: 'radio', name: 'key-source', value, class: 'source-radio' });
  input.checked = checked;
  input.disabled = disabled;
  const node = h(
    'label',
    { class: `source-card${disabled ? ' source-card--disabled' : ''}`, 'data-source': value },
    input,
    h('span', { class: 'source-text' }, h('strong', { text: title }), h('span', { text: disabled && reason ? reason : text })),
  );
  return { input, node };
}

export async function newKeyPair(): Promise<void> {
  const name = textInput('', { placeholder: t('newkey', 'Your name'), autocomplete: 'name' });
  const email = textInput('', { placeholder: 'you@example.org', autocomplete: 'email', type: 'email' });
  const pass = secretInput();
  const repeat = secretInput();
  const years = select(YEAR_CHOICES.map((y) => ({ value: String(y), label: yearsLabel(y) })), String(app.settings.validYears));
  const hw = hardwareReady();
  const cards = [
    sourceCard('hardware', t('newkey', 'Hardware generator'), t('newkey', "The system's random generator, fed by the hardware. The usual choice."), hw, !hw, t('newkey', 'Not available in this browser.')),
    sourceCard('mouse', t('newkey', 'Mouse movements'), t('newkey', 'You move the mouse or a finger until enough randomness is collected.'), !hw),
    sourceCard('phrase', t('newkey', 'Passphrase'), t('newkey', 'The key is made from a phrase, and can be made again from it on any device.'), false),
  ];
  const phrase = h('textarea', { class: 'dialog-input phrase-input', rows: '2', spellcheck: 'false', placeholder: t('newkey', 'At least five different words, in any language') });
  const counter = h('span', { class: 'phrase-counter' });
  const day = textInput(today(), { type: 'date', max: today() });
  const phraseBox = h(
    'div',
    { class: 'phrase-box', hidden: '' },
    field(t('newkey', 'Phrase'), h('div', { class: 'phrase-field' }, phrase, counter)),
    h(
      'p',
      { class: 'dialog-warning' },
      t('newkey', 'Your public key is public: anyone can try phrases against it, as many as they like. Five words someone makes up can be guessed; words from songs, books and sayings first. Take seven or more random words. The phrase is never stored.'),
    ),
    field(t('newkey', 'Date of the key'), day, t('newkey', 'Remember the phrase, the e-mail address and this date: together they make the same key again.')),
  );
  const updateCounter = () => {
    const n = distinctWords(phrase.value).length;
    counter.textContent = t('newkey', 'words: {count} of {min}', { count: n, min: MIN_WORDS });
    counter.classList.toggle('phrase-counter--ok', n >= MIN_WORDS);
  };
  phrase.addEventListener('input', updateCounter);
  updateCounter();
  const choice = (): SourceChoice => (cards.find((c) => c.input.checked)?.input.value as SourceChoice) ?? 'mouse';
  for (const c of cards) c.input.addEventListener('change', () => (phraseBox.hidden = choice() !== 'phrase'));
  const progress = progressBar();
  let made: Generated | null = null;
  let source: KeySource = 'hardware';

  const ok = await dialog({
    title: t('newkey', 'New key pair'),
    wide: true,
    body: [
      field(t('newkey', 'Name'), name),
      field(t('newkey', 'E-mail address'), email),
      field(t('newkey', 'Passphrase'), pass.node, t('newkey', 'Protects the secret key in this browser and in its backups.')),
      field(t('newkey', 'Repeat the passphrase'), repeat.node),
      field(t('newkey', 'Valid'), years),
      h('fieldset', { class: 'source-set' }, h('legend', { class: 'dialog-label-text', text: t('newkey', 'Source of randomness') }), ...cards.map((c) => c.node)),
      phraseBox,
      h('p', { class: 'dialog-hint', text: t('newkey', 'The key is Curve25519 (Ed25519 for signatures, Cv25519 for encryption), as GnuPG and Kleopatra make them by default.') }),
      progress.node,
    ],
    confirm: t('newkey', 'Create'),
    submit: async () => {
      if (!name.value.trim() && !email.value.trim()) return t('newkey', 'Give a name or an e-mail address.');
      if (pass.input.value !== repeat.input.value) return t('newkey', 'The passphrases differ.');
      const kind = choice();
      if (kind === 'phrase') {
        if (!email.value.trim()) return t('newkey', 'A key from a phrase needs an e-mail address.');
        if (distinctWords(phrase.value).length < MIN_WORDS) return t('newkey', 'The phrase needs at least {min} different words.', { min: MIN_WORDS });
        if (phrase.value.trim() === pass.input.value.trim()) return t('newkey', 'The phrase and the passphrase must differ.');
      }
      if (!pass.input.value && !(await confirmAsk(t('newkey', 'No passphrase?'), t('newkey', 'Without a passphrase anyone who can use this browser can use your key.'), t('newkey', 'Create without one')))) return '';
      app.settings.validYears = Number(years.value);
      saveState();
      const expiresIn = Number(years.value) * YEAR;
      const onProgress = (stage: 'derive' | 'protect', d: number) => progress.set(stage === 'derive' ? d * 0.6 : 0.6 + d * 0.4);
      if (kind === 'phrase') {
        const random = await messageRandom();
        if (!random) return '';
        source = 'phrase';
        made = await generate({ name: name.value, email: email.value, passphrase: pass.input.value, expiresIn, source: { kind: 'phrase', phrase: phrase.value, day: day.value }, random: random.bytes, now: now(), onProgress });
      } else {
        const random = await keyRandom(kind);
        if (!random) return '';
        source = kind;
        made = await generate({ name: name.value, email: email.value, passphrase: pass.input.value, expiresIn, source: { kind: 'random', random: random.bytes }, random: random.bytes, now: now(), onProgress: (_s, d) => progress.set(d) });
      }
      return null;
    },
  });
  if (!ok || !made) return;
  await stored(made, source);
  await afterNewKey(made);
}

/** A key made from a phrase, made again: with its public key if we have it, from the date otherwise. */
export async function restoreFromPhrase(): Promise<void> {
  const email = textInput('', { type: 'email', placeholder: 'you@example.org' });
  const name = textInput('', { placeholder: t('newkey', 'Your name') });
  const phrase = h('textarea', { class: 'dialog-input phrase-input', rows: '2', spellcheck: 'false' });
  const day = textInput(today(), { type: 'date', max: today() });
  const pass = secretInput();
  const progress = progressBar();
  let made: Generated | null = null;
  const ok = await dialog({
    title: t('restore', 'Restore a key from its phrase'),
    wide: true,
    body: [
      t('restore', 'If the public key is in your keyring (import it first, from a file or from someone who has it), it is checked against the phrase and keeps its signatures. Otherwise the key is made again from the name, the address and the date.'),
      field(t('newkey', 'Phrase'), phrase),
      field(t('newkey', 'E-mail address'), email),
      field(t('newkey', 'Name'), name, t('restore', 'Only needed without the public key: exactly as it was.')),
      field(t('newkey', 'Date of the key'), day, t('restore', 'Only needed without the public key.')),
      field(t('newkey', 'Passphrase'), pass.node, t('restore', 'A passphrase for the restored key in this browser.')),
      progress.node,
    ],
    confirm: t('restore', 'Restore'),
    submit: async () => {
      if (!email.value.trim()) return t('newkey', 'A key from a phrase needs an e-mail address.');
      const random = await messageRandom();
      if (!random) return '';
      const address = normalizeEmail(email.value);
      const publicKey = allViews().find((v) => !v.secret && normalizeEmail(v.email) === address)?.entry.cert;
      try {
        made = await restore({
          phrase: phrase.value, email: email.value, name: name.value, day: day.value, publicKey, passphrase: pass.input.value, expiresIn: app.settings.validYears * YEAR,
          random: random.bytes, now: now(), onProgress: (stage, d) => progress.set(stage === 'derive' ? d * 0.6 : 0.6 + d * 0.4),
        });
      } catch (error) {
        if (error instanceof PgpError && error.code === 'bad-passphrase') return t('restore', 'This phrase and address do not make the key in your keyring.');
        throw error;
      }
      return null;
    },
  });
  if (!ok || !made) return;
  const restored: Generated = made;
  const existing = app.keyring.get(fingerprintHex(restored.cert.primary.fingerprint));
  if (existing) await app.keyring.importCerts([restored.cert], now(), 'phrase');
  else await stored(restored, 'phrase');
  keyringChanged();
  selection.show(fingerprintHex(restored.cert.primary.fingerprint));
  toast(t('restore', 'The key is restored'));
}

// ---- Import -------------------------------------------------------------------------------

function resultLine(r: ImportResult): HTMLElement {
  const text =
    r.status === 'new' ? (r.secret ? t('import', 'new key pair') : t('import', 'new')) :
    r.status === 'updated' ? (r.secret ? t('import', 'secret key added or updated') : t('import', 'updated')) :
    r.status === 'unchanged' ? t('import', 'unchanged') : t('import', 'refused: {why}', { why: r.problem ?? '' });
  return h('li', { class: r.status === 'refused' ? 'import-refused' : '' }, h('span', { text: r.userId ?? keyIdLabel(r.fingerprint) }), h('span', { class: 'mono', text: text }));
}

/** Imports what the inputs hold: keys, or a revocation certificate after the user confirms it. */
export async function importInputs(inputs: (Uint8Array | string)[]): Promise<void> {
  const results: ImportResult[] = [];
  const problems: string[] = [];
  for (const input of inputs) {
    const kind = classify(input);
    try {
      if (kind === 'revocation') {
        await importRevocation(input);
        continue;
      }
      if (kind !== 'public-keys' && kind !== 'secret-keys') {
        problems.push(t('import', 'Not a key.'));
        continue;
      }
      results.push(...(await app.keyring.importCerts(readKeys(input), now())));
    } catch (error) {
      problems.push(error instanceof Error ? error.message : String(error));
    }
  }
  keyringChanged();
  if (results.some((r) => r.secret && r.status !== 'refused')) keepStorage();
  const first = results.find((r) => r.status === 'new' || r.status === 'updated');
  if (first) selection.show(first.fingerprint);
  if (!results.length && !problems.length) return;
  if (results.length === 1 && !problems.length && results[0].status !== 'refused') {
    toast(results[0].status === 'unchanged' ? t('import', 'The key is already in your keyring') : t('import', 'Key imported'));
    return;
  }
  await inform(t('import', 'Import'), ...(results.length ? [h('ul', { class: 'import-list' }, ...results.map(resultLine))] : []), ...problems.map((p) => h('p', { class: 'dialog-error', text: p })));
}

async function importRevocation(input: Uint8Array | string): Promise<void> {
  const sig = readRevocation(input);
  const id = issuerFingerprint(sig);
  const v = allViews().find((x) => (id ? x.fingerprint === fingerprintHex(id) : false));
  if (!v) throw new PgpError('unexpected', t('import', 'A revocation certificate for a key that is not in your keyring.'));
  if (!(await confirmAsk(t('import', 'Revoke this key?'), [t('import', 'This revocation certificate revokes {key} for good: it cannot be taken back.', { key: named(v) })], t('import', 'Revoke')))) return;
  await app.keyring.put(applyRevocation(v.entry.cert, sig, now()), v.entry.record.source, now());
  keyringChanged();
  toast(t('import', 'The key is revoked. Share the public key so others know.'));
}

export async function importFiles(files: File[]): Promise<void> {
  await importInputs(await Promise.all(files.map(async (f) => new Uint8Array(await f.arrayBuffer()))));
}

export async function importFromClipboard(): Promise<void> {
  try {
    await importInputs([await readClipboard()]);
  } catch (error) {
    toast(error instanceof Error ? error.message : String(error), 'error');
  }
}

export async function importPasted(): Promise<void> {
  const area = h('textarea', { class: 'dialog-input armor-input mono', rows: '10', spellcheck: 'false', placeholder: '-----BEGIN PGP PUBLIC KEY BLOCK-----' });
  let text = '';
  const ok = await dialog({ title: t('import', 'Paste a key'), wide: true, body: [area], confirm: t('import', 'Import'), submit: () => ((text = area.value).trim() ? null : t('import', 'Paste a key first.')) });
  if (ok) await importInputs([text]);
}

// ---- Export and backup ---------------------------------------------------------------------

export async function exportPublic(views: KeyView[]): Promise<void> {
  if (!views.length) return;
  const certs = views.map((v) => v.entry.cert);
  const text = armor('PUBLIC KEY BLOCK', new Uint8Array(certs.flatMap((c) => [...writeCert(c)])));
  const base = views.length === 1 ? `${safeName(label(views[0]))}_${keyIdLabel(views[0].keyId)}_public` : 'public_keys';
  const copy = h('button', { type: 'button', class: 'button button--small', text: t('export', 'Copy') });
  copy.addEventListener('click', () => void copyText(text).then(() => toast(t('export', 'Public key copied'))));
  const asc = h('button', { type: 'button', class: 'button button--small', text: t('export', 'Save as text (.asc)') });
  asc.addEventListener('click', () => void saveFile(text, `${base}.asc`));
  const gpg = h('button', { type: 'button', class: 'button button--small', text: t('export', 'Save as binary (.gpg)') });
  gpg.addEventListener('click', () => void saveFile(new Uint8Array(certs.flatMap((c) => [...writeCert(c)])), `${base}.gpg`));
  await inform(
    views.length === 1 ? t('export', 'Export public key') : t('export', 'Export {count} public keys', { count: views.length }),
    t('export', 'Give this to the people who will write to you or check your signatures. It holds nothing secret.'),
    h('pre', { class: 'armor mono' }, text),
    h('div', { class: 'dialog-buttons' }, copy, asc, gpg),
  );
}

export async function backupSecret(v: KeyView): Promise<void> {
  if (!v.here) {
    // The secret lives on a device only: unlocked there, it is saved under a passphrase of its own.
    const secrets = await unlockKey(v, 'export');
    if (!secrets) return;
    const saved = await withNewPassphrase(t('export', 'A passphrase for the backup'), t('export', 'Save file'), async (passphrase, random, onProgress) => {
      const cert = await protectAll(v.entry.cert, byPacket(v, secrets), passphrase, { random, onProgress });
      await saveFile(armor('PRIVATE KEY BLOCK', writeCert(cert, { secret: true })), `${safeName(label(v))}_${keyIdLabel(v.keyId)}_SECRET.asc`);
    });
    if (saved) toast(t('export', 'Keep the backup somewhere safe: it is your secret key, under its passphrase.'));
    return;
  }
  // Asked first, so the backup is known to open with the passphrase.
  if (!(await unlockKey(v, 'export', { fresh: true }))) return;
  await saveFile(armor('PRIVATE KEY BLOCK', writeCert(v.entry.cert, { secret: true })), `${safeName(label(v))}_${keyIdLabel(v.keyId)}_SECRET.asc`);
  toast(t('export', 'Keep the backup somewhere safe: it is your secret key, under its passphrase.'));
}

// ---- Changing our keys ------------------------------------------------------------------------

async function primarySeed(v: KeyView, purpose: 'change' | 'verify' | 'sign'): Promise<Uint8Array | null> {
  const secrets = await unlockKey(v, purpose);
  return secrets ? seedOf(secrets, v.entry.cert.primary) : null;
}

async function saveChanged(v: KeyView, cert: Cert): Promise<void> {
  await app.keyring.put(cert, v.entry.record.source, now());
  keyringChanged();
}

/** The unlocked secrets by the key packets of the key, as protectAll takes them. */
const byPacket = (v: KeyView, secrets: Map<string, Secret>): Map<KeyPacket, Secret> =>
  new Map([v.entry.cert.primary, ...v.entry.cert.subkeys.map((s) => s.key)].filter((k) => secrets.has(fingerprintHex(k.fingerprint))).map((k) => [k, secrets.get(fingerprintHex(k.fingerprint))!]));

/** Asks for a new passphrase (twice; none only after a warning), then does `work` with it while the dialog waits. */
async function withNewPassphrase(title: string, confirm: string, work: (passphrase: string, random: (n: number) => Uint8Array, onProgress: (done: number) => void) => Promise<void>): Promise<boolean> {
  const pass = secretInput();
  const repeat = secretInput();
  const progress = progressBar();
  return dialog({
    title,
    body: [field(t('details', 'New passphrase'), pass.node), field(t('newkey', 'Repeat the passphrase'), repeat.node), progress.node],
    confirm,
    submit: async () => {
      if (pass.input.value !== repeat.input.value) return t('newkey', 'The passphrases differ.');
      if (!pass.input.value && !(await confirmAsk(t('newkey', 'No passphrase?'), t('newkey', 'Without a passphrase anyone who can use this browser can use your key.'), t('details', 'Remove the passphrase')))) return '';
      const random = await messageRandom();
      if (!random) return '';
      await work(pass.input.value, random.bytes, progress.set);
      return null;
    },
  });
}

export async function changePassphrase(v: KeyView): Promise<void> {
  const secrets = await unlockKey(v, 'change', { fresh: true });
  if (!secrets) return;
  const here = v.here;
  const ok = await withNewPassphrase(here ? t('details', 'Change passphrase') : t('details', 'Keep a copy in this browser'), here ? t('details', 'Change') : t('details', 'Keep a copy'), async (passphrase, random, onProgress) => {
    const cert = await protectAll(v.entry.cert, byPacket(v, secrets), passphrase, { random, onProgress });
    await saveChanged(v, cert);
    app.agent.forget(v.fingerprint);
  });
  if (ok) toast(here ? t('details', 'Passphrase changed') : t('details', 'A copy of the key is in this browser again'));
}

export async function changeExpiry(v: KeyView): Promise<void> {
  const years = select(YEAR_CHOICES.map((y) => ({ value: String(y), label: yearsLabel(y) })), '3');
  const ok = await dialog({
    title: t('details', 'Change expiry'),
    body: [field(t('details', 'Valid from today for'), years), t('details', 'Share the public key again afterwards, so others see the new date.')],
    confirm: t('details', 'Change'),
  });
  if (!ok) return;
  const seed = await primarySeed(v, 'change');
  if (!seed) return;
  const y = Number(years.value);
  const expiresIn = y ? now() - v.entry.cert.primary.created + y * YEAR : 0;
  await saveChanged(v, withExpiry(v.entry.cert, seed, expiresIn, now()));
  toast(t('details', 'Expiry changed'));
}

export async function revokeKey(v: KeyView): Promise<void> {
  const reasons = select(
    [
      { value: String(REASON.COMPROMISED), label: t('details', 'The key was compromised') },
      { value: String(REASON.SUPERSEDED), label: t('details', 'Replaced by a new key') },
      { value: String(REASON.RETIRED), label: t('details', 'No longer used') },
      { value: String(REASON.NONE), label: t('details', 'No reason given') },
    ],
    String(REASON.SUPERSEDED),
  );
  const note = textInput('', { placeholder: t('details', 'A note (optional)') });
  const ok = await dialog({
    title: t('details', 'Revoke key'),
    body: [t('details', 'A revoked key cannot be used again: this cannot be undone. Share the public key afterwards, so others stop using it.'), field(t('details', 'Reason'), reasons), note],
    confirm: t('details', 'Revoke'),
    danger: true,
  });
  if (!ok) return;
  const seed = await primarySeed(v, 'change');
  if (!seed) return;
  const sig = revocationSignature(v.entry.cert, seed, Number(reasons.value), note.value, now());
  await saveChanged(v, applyRevocation(v.entry.cert, sig, now()));
  toast(t('details', 'Key revoked'));
}

export async function saveRevocationCertificate(v: KeyView): Promise<void> {
  const seed = await primarySeed(v, 'change');
  if (!seed) return;
  const sig = revocationSignature(v.entry.cert, seed, REASON.NONE, '', now());
  await saveFile(revocationText(v.entry.cert, sig.body, label(v)), `${safeName(label(v))}_${keyIdLabel(v.keyId)}_revocation.asc`);
}

/** "I checked the fingerprint": a local certification by one of our keys (gpg --lsign-key). */
export async function markAsVerified(v: KeyView): Promise<void> {
  const signers = ownSigning();
  if (!signers.length) {
    await inform(t('verify', 'Mark as verified'), t('verify', 'You need a key pair of your own to mark keys as verified.'));
    return;
  }
  const signer = select(signers.map((s) => ({ value: s.fingerprint, label: label(s) })), signers[0].fingerprint);
  const userIds = keyState(v.entry.cert, now()).userIds.filter((u) => u.valid && !u.revoked);
  const checks = userIds.map((u) => checkbox(u.text, true));
  const ok = await dialog({
    title: t('verify', 'Mark as verified'),
    wide: true,
    body: [
      t('verify', 'Compare this fingerprint with its owner — in person, or on a call where you know their voice. Only if every character matches:'),
      h('code', { class: 'fpr fpr--big', text: fingerprintGroups(v.fingerprint) }),
      ...(checks.length > 1 ? checks.map((c) => c.node) : []),
      signers.length > 1 ? field(t('verify', 'With your key'), signer) : null,
      t('verify', 'The mark stays in your keyring: it is not exported with the key.'),
    ],
    confirm: t('verify', 'The fingerprint matches'),
  });
  if (!ok) return;
  const own = signers.find((s) => s.fingerprint === signer.value)!;
  const seed = await primarySeed(own, 'verify');
  if (!seed) return;
  let cert = v.entry.cert;
  userIds.forEach((u, i) => {
    if (checks[i].input.checked) cert = markVerified(cert, u.text, own.entry.cert.primary, seed, now());
  });
  await saveChanged(v, cert);
  toast(t('verify', 'Marked as verified'));
}

/** Takes our local certifications off the key. */
export async function unmarkVerified(v: KeyView): Promise<void> {
  const ours = allViews().filter((x) => x.secret).map((x) => fingerprintHex(x.entry.cert.primary.fingerprint));
  const users = v.entry.cert.users.map((u) => ({
    ...u,
    sigs: u.sigs.filter((s) => !(s.version === 4 && s.type >= SIG.CERT_GENERIC && s.type <= SIG.CERT_POSITIVE && !exportable(s) && issuerFingerprint(s) && ours.includes(fingerprintHex(issuerFingerprint(s)!)))),
  }));
  await saveChanged(v, { ...v.entry.cert, users });
  toast(t('verify', 'No longer marked as verified'));
}

export async function deleteKeys(views: KeyView[]): Promise<void> {
  if (!views.length) return;
  const secret = views.filter((v) => v.secret);
  const message = [
    views.length === 1 ? t('delete', 'Delete {key} from this keyring?', { key: named(views[0]) }) : t('delete', 'Delete {count} keys from this keyring?', { count: views.length }),
    ...(secret.length ? [h('p', { class: 'dialog-warning', text: t('delete', 'This includes your secret key. Without a backup, messages to it can never be read again.') })] : []),
  ];
  if (!(await confirmAsk(t('delete', 'Delete'), message as (string | Node)[], t('delete', 'Delete')))) return;
  for (const v of views) {
    app.agent.forget(v.fingerprint);
    await app.keyring.remove(v.fingerprint);
    platform.keyDeleted(v.fingerprint);
  }
  keyringChanged();
  toast(tn('delete', '{count} key deleted', '{count} keys deleted', views.length));
}

/** Imports from bytes that are already known to be keys (the files view). */
export async function importBytes(list: Uint8Array[]): Promise<void> {
  await importInputs(list);
}

