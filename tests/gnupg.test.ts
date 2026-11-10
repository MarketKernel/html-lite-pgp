// What we write, read by GnuPG itself: our keys imported with the profile's preferences, our
// protected secret key used by gpg to sign, our expiry changes and revocations understood.
// Messages and signatures join in later stages. Skipped (and passing) without gpg.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { armor } from '../src/core/armor.ts';
import { x25519Base } from '../src/core/crypto/x25519.ts';
import { applyRevocation, fingerprintHex, makeCert, revocationSignature, withExpiry, writeCert } from '../src/core/keys.ts';
import type { Cert, KeyPacket } from '../src/core/keys.ts';
import { protectAll, secretsElsewhere } from '../src/core/secret.ts';
import type { Secret } from '../src/core/secret.ts';
import { GPG, ON_GITHUB, withGnupg } from './gpg.ts';
import { signCleartext, signData, wrapSignature } from '../src/core/verify.ts';
import { encryptMessage } from '../src/core/message.ts';
import { generate } from '../src/core/generate.ts';
import { readContainer, writeContainer } from '../src/core/container.ts';
import { writeFileSync } from 'node:fs';

const random = (n: number) => new Uint8Array(randomBytes(n));
const now = () => Math.floor(Date.now() / 1000);

async function ourKey(passphrase: string) {
  const seed = random(32);
  const scalar = random(32);
  const t = now() - 60;
  const pub = makeCert({ seed, subkeyPoint: x25519Base(scalar), userId: 'Наш Ключ <ours@example.org>', created: t, expiresIn: 3 * 365 * 86400, signedAt: t });
  const secrets = new Map<KeyPacket, Secret>([[pub.primary, { kind: 'ed25519', seed }], [pub.subkeys[0].key, { kind: 'cv25519', scalar }]]);
  const sec = await protectAll(pub, secrets, passphrase, { random });
  return { seed, pub, sec };
}

const colons = (out: Buffer) => out.toString().split('\n').map((l) => l.split(':'));

test('a key kept on a device: GnuPG imports it with our mark for a secret that is elsewhere', { skip: !GPG && 'no gpg' }, async () => {
  const { sec } = await ourKey('');
  const away = writeCert(secretsElsewhere(sec), { secret: true });
  withGnupg((g) => {
    // The mark is GnuPG's own gnu-dummy; the import goes through (a container holding such a
    // key still opens with gpg -d | gpg --import), and GnuPG has no secret it could use.
    assert.match(g.run(['--list-packets'], away).toString(), /gnu-dummy/);
    const imported = g.attempt(['--import'], armor('PRIVATE KEY BLOCK', away));
    assert.equal(imported.status, 0, imported.stderr);
    assert.match(imported.stderr, /secret keys read: 1/);
    const fpr = fingerprintHex(sec.primary.fingerprint);
    assert.ok(colons(g.run(['--with-colons', '--list-keys', fpr])).some((r) => r[0] === 'pub'));
    const secret = colons(g.attempt(['--with-colons', '--list-secret-keys', fpr]).stdout).find((r) => r[0] === 'sec');
    assert.ok(!secret || secret[14] === '#', 'GnuPG must not think it holds the secret');
  });
});

test('GnuPG imports our key: algorithms, usage, expiry, preferences', { skip: !GPG && 'no gpg' }, async () => {
  const { pub } = await ourKey('');
  withGnupg((g) => {
    g.run(['--import'], armor('PUBLIC KEY BLOCK', writeCert(pub)));
    const fpr = fingerprintHex(pub.primary.fingerprint);
    const rows = colons(g.run(['--with-colons', '--list-keys', fpr]));
    const pubRow = rows.find((r) => r[0] === 'pub')!;
    const subRow = rows.find((r) => r[0] === 'sub')!;
    assert.equal(pubRow[1], '-', 'the key is valid to GnuPG');
    assert.equal(pubRow[3], '22');
    assert.equal(pubRow[16], 'ed25519');
    assert.equal(subRow[3], '18');
    assert.equal(subRow[16], 'cv25519');
    assert.match(pubRow[11], /s/i);
    assert.match(subRow[11], /e/);
    assert.equal(Number(pubRow[6]), pub.primary.created + 3 * 365 * 86400);
    assert.ok(rows.some((r) => r[0] === 'uid' && r[9] === 'Наш Ключ <ours@example.org>'));
    const packets = g.run(['--list-packets'], g.run(['--export', fpr])).toString();
    assert.match(packets, /pref-sym-algos: 9\)/);
    assert.match(packets, /pref-hash-algos: 10 8\)/);
    assert.match(packets, /pref-zip-algos: 0\)/);
    assert.match(packets, /features: 01\)/);
    assert.doesNotMatch(packets, /pref-aead/);
  });
});

// Skipped on GitHub (ON_GITHUB): there gpg-agent does not unlock our Cv25519 subkey ("Bad
// passphrase", or asks for it again), though GnuPG 2.4.4 on the same Ubuntu 24.04 and 2.5 do.
test('GnuPG unlocks our protected secret key and signs with it', { skip: (!GPG && 'no gpg') || ON_GITHUB }, async () => {
  const { sec } = await ourKey('пароль ключа');
  withGnupg((g) => {
    g.run(['--import'], armor('PRIVATE KEY BLOCK', writeCert(sec, { secret: true })));
    const fpr = fingerprintHex(sec.primary.fingerprint);
    // The wrong passphrase first: once the right one is in, gpg-agent remembers it.
    const wrong = g.attempt(['--passphrase', 'not it', '-u', fpr, '--clearsign'], 'hello');
    assert.notEqual(wrong.status, 0);
    const signed = g.run(['--passphrase', 'пароль ключа', '-u', fpr, '--clearsign'], 'hello');
    assert.match(signed.toString(), /BEGIN PGP SIGNATURE/);
    // And GnuPG encrypts to our key the plain way: SEIPD v1, no compression.
    const encrypted = g.run(['-r', fpr, '--encrypt'], 'to us');
    const packets = g.run(['--list-packets'], encrypted).toString();
    assert.match(packets, /:pubkey enc packet: version 3, algo 18/);
    assert.match(packets, /:encrypted data packet:/);
    assert.doesNotMatch(packets, /ocb|aead|compressed/i);
  });
});

test('GnuPG sees our new expiry and our revocation', { skip: !GPG && 'no gpg' }, async () => {
  const { seed, pub } = await ourKey('');
  const fpr = fingerprintHex(pub.primary.fingerprint);
  const later: Cert = withExpiry(pub, seed, 0, now());
  const revoked = applyRevocation(pub, revocationSignature(pub, seed, 3, 'retired', now()), now());
  withGnupg((g) => {
    g.run(['--import'], armor('PUBLIC KEY BLOCK', writeCert(pub)));
    g.run(['--import'], armor('PUBLIC KEY BLOCK', writeCert(later)));
    const pubRow = colons(g.run(['--with-colons', '--list-keys', fpr])).find((r) => r[0] === 'pub')!;
    assert.equal(pubRow[6], '', 'no expiry any more');
    g.run(['--import'], armor('PUBLIC KEY BLOCK', writeCert(revoked)));
    const after = colons(g.run(['--with-colons', '--list-keys', fpr])).find((r) => r[0] === 'pub')!;
    assert.equal(after[1], 'r', 'revoked');
  });
});

test('GnuPG checks our clear-signed texts and detached signatures', { skip: !GPG && 'no gpg' }, async () => {
  const { seed, pub } = await ourKey('');
  const signer = { cert: pub, key: pub.primary, seed };
  const text = 'Проверка подписи\n- строка с дефисом\n-----BEGIN PGP SIGNATURE-----\nконец с пробелами   \n';
  const data = random(100_000);
  withGnupg((g) => {
    g.run(['--import'], armor('PUBLIC KEY BLOCK', writeCert(pub)));
    const clear = signCleartext(text, signer, now());
    const ok = g.attempt(['--status-fd', '1', '--verify'], clear);
    assert.equal(ok.status, 0, ok.stderr);
    assert.match(ok.stdout.toString(), /\[GNUPG:\] GOODSIG/);
    // What gpg says the text is: ours, without spaces at line ends (they are not signed).
    assert.equal(g.run(['--decrypt'], clear).toString(), text.replace(/[ \t]+$/gm, ''));
    const bad = g.attempt(['--verify'], clear.replace('Проверка', 'Подделка'));
    assert.notEqual(bad.status, 0);
    const dir = g.home;
    const sigFile = `${dir}/data.sig`;
    const dataFile = `${dir}/data.bin`;
    writeFileSync(dataFile, data);
    writeFileSync(sigFile, wrapSignature(signData(data, signer, now())));
    const detached = g.attempt(['--status-fd', '1', '--verify', sigFile, dataFile]);
    assert.equal(detached.status, 0, detached.stderr);
    assert.match(detached.stdout.toString(), /\[GNUPG:\] GOODSIG/);
  });
});

// Unlocks our Cv25519 subkey: skipped on GitHub, as above.
test('GnuPG decrypts our messages — to our key, signed, and by password — and checks the signature', { skip: (!GPG && 'no gpg') || ON_GITHUB }, async () => {
  const { seed, pub, sec } = await ourKey('пароль');
  const signer = { cert: pub, key: pub.primary, seed };
  const to = { cert: pub, key: pub.subkeys[0].key };
  const text = new TextEncoder().encode('Сообщение для GnuPG\n');
  const signedEncrypted = await encryptMessage({ data: text, format: 'u', recipients: [to], signer, now: now(), random });
  const byPassword = await encryptMessage({ data: text, format: 'b', filename: 'note.txt', recipients: [], password: 'общий пароль', now: now(), random });
  withGnupg((g) => {
    g.run(['--import'], armor('PRIVATE KEY BLOCK', writeCert(sec, { secret: true })));
    const out = g.attempt(['--passphrase', 'пароль', '--status-fd', '2', '--decrypt'], signedEncrypted);
    assert.equal(out.status, 0, out.stderr);
    assert.equal(out.stdout.toString(), 'Сообщение для GnuPG\n');
    assert.match(out.stderr, /\[GNUPG:\] GOODSIG/);
    assert.match(out.stderr, /\[GNUPG:\] DECRYPTION_OKAY/);
    assert.match(out.stderr, /\[GNUPG:\] GOODMDC/);
    const listed = g.run(['--passphrase', 'пароль', '--list-packets'], signedEncrypted).toString();
    assert.doesNotMatch(listed, /compressed/);
    const sym = g.attempt(['--passphrase', 'общий пароль', '--decrypt'], byPassword);
    assert.equal(sym.status, 0, sym.stderr);
    assert.equal(sym.stdout.toString(), 'Сообщение для GnuPG\n');
    const wrong = g.attempt(['--passphrase', 'не тот', '--decrypt'], byPassword);
    assert.notEqual(wrong.status, 0);
  });
});

test('GnuPG takes a key made from a phrase like any other', { skip: !GPG && 'no gpg' }, async () => {
  const made = await generate({
    name: 'Из фразы', email: 'phrase@example.org', passphrase: 'p', expiresIn: 0,
    source: { kind: 'phrase', phrase: 'зелёный слон тихо идёт по мосту', day: '2026-09-01' }, random, now: now(),
  });
  withGnupg((g) => {
    g.run(['--import'], armor('PRIVATE KEY BLOCK', writeCert(made.cert, { secret: true })));
    const fpr = fingerprintHex(made.cert.primary.fingerprint);
    const pubRow = colons(g.run(['--with-colons', '--list-keys', fpr])).find((r) => r[0] === 'pub')!;
    assert.equal(pubRow[1], '-');
    assert.equal(pubRow[5], String(Date.UTC(2026, 8, 1) / 1000));
    assert.match(g.run(['--passphrase', 'p', '-u', fpr, '--clearsign'], 'x').toString(), /BEGIN PGP SIGNATURE/);
  });
});

// Unlocks our Cv25519 subkey: skipped on GitHub, as above.
test('the container: GnuPG opens ours and imports the keys; we open what gpg -c made of an export', { skip: (!GPG && 'no gpg') || ON_GITHUB }, async () => {
  const { sec } = await ourKey('ключ');
  const password = 'пять разных слов для контейнера';
  const container = await writeContainer([sec], password, random, now());
  const fpr = fingerprintHex(sec.primary.fingerprint);
  const theirs = withGnupg((g) => {
    const keys = g.run(['--passphrase', password, '--decrypt'], container);
    g.run(['--import', '--import-options', 'import-local-sigs'], keys);
    assert.ok(colons(g.run(['--with-colons', '--list-secret-keys', fpr])).some((r) => r[0] === 'sec'));
    // And back: GnuPG's export of the key, encrypted with gpg -c, is a container we open.
    const exported = g.run(['--passphrase', 'ключ', '--export-secret-keys', fpr]);
    return g.run(['--passphrase', password, '--s2k-cipher-algo', 'AES256', '--s2k-digest-algo', 'SHA256', '--cipher-algo', 'AES256', '--compress-algo', 'none', '--symmetric'], exported);
  });
  const certs = await readContainer(new Uint8Array(theirs), password, now());
  assert.equal(fingerprintHex(certs[0].primary.fingerprint), fpr);
  assert.ok(certs[0].primary.secretBody);
});
