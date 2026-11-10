// The three sources of a key (Task.md §4): the system generator, the mouse pool, a phrase.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { toHex } from '../src/core/bytes.ts';
import { ed25519PublicKey } from '../src/core/crypto/ed25519.ts';
import { x25519Base } from '../src/core/crypto/x25519.ts';
import { EntropyPool, hardwareAvailable, hardwareRandom, mouseRandom, POOL_TARGET_BITS } from '../src/core/crypto/random.ts';
import { PgpError } from '../src/core/errors.ts';
import { generate, restore } from '../src/core/generate.ts';
import { applyRevocation, fingerprintHex, keyState, parseCerts, writeCert } from '../src/core/keys.ts';
import { readRevocation } from '../src/core/pgp.ts';
import { dayStart, distinctWords, normalizePhrase, phraseLongEnough, secretsFromPhrase } from '../src/core/phrase.ts';
import { unlockAll } from '../src/core/secret.ts';

const NOW = 1_800_000_000;

test('the system generator: there, and never twice the same', () => {
  assert.ok(hardwareAvailable());
  const r = hardwareRandom();
  assert.equal(r.kind, 'hardware');
  assert.notEqual(toHex(r.bytes(32)), toHex(r.bytes(32)));
  assert.equal(r.bytes(100_000).length, 100_000);
});

function fill(pool: EntropyPool, n: number, start = 0) {
  for (let i = 0; i < n; i++) pool.addPointer(100 + ((i * 37) % 500), 50 + ((i * 11) % 300), start + i * 10, [i % 3]);
}

test('the mouse pool credits only movement over time, and asks for 256 events over 2 seconds', () => {
  const pool = new EntropyPool();
  assert.ok(pool.addPointer(5, 5, 0));
  assert.ok(!pool.addPointer(5, 5, 10), 'no movement, no credit');
  assert.ok(!pool.addPointer(6, 5, 10), 'no time, no credit');
  assert.ok(pool.addPointer(7, 5, 20));
  assert.ok(pool.addKey(30));
  assert.ok(!pool.addKey(30));
  const quick = new EntropyPool();
  for (let i = 0; i < 400; i++) quick.addPointer(i, i, i);
  assert.ok(!quick.ready, '400 events in 0.4 s is not enough time');
  const full = new EntropyPool();
  fill(full, POOL_TARGET_BITS + 10);
  assert.ok(full.ready);
  assert.throws(() => mouseRandom(new EntropyPool()), /not collected enough/);
});

test('mouse randomness never touches the system generator, and follows only the movements', () => {
  const original = globalThis.crypto.getRandomValues;
  globalThis.crypto.getRandomValues = (() => {
    throw new Error('called the system generator');
  }) as typeof original;
  try {
    const a = new EntropyPool();
    const b = new EntropyPool();
    fill(a, 300);
    fill(b, 300);
    const ra = mouseRandom(a);
    const rb = mouseRandom(b);
    assert.equal(toHex(ra.bytes(64)), toHex(rb.bytes(64)), 'the same movements, the same bytes: nothing else goes in');
    fill(a, 5, 100_000);
    assert.notEqual(toHex(ra.bytes(64)), toHex(rb.bytes(64)), 'new movements change what follows');
    assert.ok(!hardwareAvailable(), 'a failing system generator is reported unavailable');
  } finally {
    globalThis.crypto.getRandomValues = original;
  }
});

test('phrases: words counted in any language, prepositions included, repeats once', () => {
  assert.equal(distinctWords('я иду в лес и').length, 5);
  assert.equal(distinctWords('лес лес лес лес лес').length, 1);
  assert.equal(distinctWords('Лес ЛЕС лес, лес!').length, 1);
  assert.ok(phraseLongEnough('أنا ذاهب إلى السوق اليوم'));
  assert.ok(phraseLongEnough('我今天去北京看朋友吃饭'));
  assert.ok(phraseLongEnough('私は今日東京で友達に会います'));
  assert.ok(!phraseLongEnough('one two three four'));
  assert.equal(normalizePhrase('  Ａ B\tc \n'), 'a b c');
  assert.equal(dayStart('2026-01-01'), 1767225600);
  assert.throws(() => dayStart('2026-02-30'), /no such date/);
});

test('version 1 of the phrase derivation gives exactly the frozen keys', async () => {
  const vectors = JSON.parse(readFileSync(new URL('./vectors/phrase/v1.json', import.meta.url), 'utf8'));
  for (const v of vectors) {
    assert.equal(normalizePhrase(v.phrase), v.normalized);
    const s = await secretsFromPhrase(v.phrase, v.email);
    assert.equal(toHex(ed25519PublicKey(s.seed)), v.ed25519, v.phrase);
    assert.equal(toHex(x25519Base(s.scalar)), v.cv25519, v.phrase);
  }
});

test('a key from a phrase: the same key again, restored from its public key, refused for the wrong phrase', async () => {
  const random = hardwareRandom().bytes;
  const phrase = 'мы пошли в лес за грибами и ягодами';
  const spec = { name: 'Фраза', email: 'phrase@example.org', passphrase: '', expiresIn: 0, random, now: NOW } as const;
  const a = await generate({ ...spec, source: { kind: 'phrase', phrase, day: '2026-10-01' } });
  const b = await generate({ ...spec, source: { kind: 'phrase', phrase: 'Мы  пошли в ЛЕС за грибами и ягодами', day: '2026-10-01' } });
  assert.equal(fingerprintHex(a.cert.primary.fingerprint), fingerprintHex(b.cert.primary.fingerprint));
  assert.equal(a.cert.primary.created, dayStart('2026-10-01'));
  const other = await generate({ ...spec, source: { kind: 'phrase', phrase, day: '2026-10-02' } });
  assert.notEqual(fingerprintHex(other.cert.primary.fingerprint), fingerprintHex(a.cert.primary.fingerprint));
  const publicOnly = parseCerts(writeCert(a.cert))[0];
  const back = await restore({ phrase, email: 'PHRASE@example.org', publicKey: publicOnly, passphrase: 'новый', random, now: NOW + 5 });
  assert.equal(fingerprintHex(back.cert.primary.fingerprint), fingerprintHex(a.cert.primary.fingerprint));
  assert.equal((await unlockAll(back.cert, 'новый')).size, 2);
  await assert.rejects(restore({ phrase: phrase + ' ещё', email: 'phrase@example.org', publicKey: publicOnly, passphrase: '', random, now: NOW }), (e: unknown) => e instanceof PgpError && e.code === 'bad-passphrase');
  await assert.rejects(generate({ ...spec, source: { kind: 'phrase', phrase: 'too few words here', day: '2026-10-01' } }), /at least 5/);
  await assert.rejects(generate({ ...spec, source: { kind: 'phrase', phrase, day: '2099-01-01' } }), /future/);
});

test('a random key, with its revocation certificate', async () => {
  const r = hardwareRandom();
  const made = await generate({ name: 'Случайный', email: 'r@example.org', passphrase: 'p', expiresIn: 3 * 365 * 86400, source: { kind: 'random', random: r.bytes }, random: r.bytes, now: NOW });
  const s = keyState(made.cert, NOW);
  assert.ok(s.valid);
  assert.equal(s.primaryUserId, 'Случайный <r@example.org>');
  assert.match(made.revocation, /^:-----BEGIN PGP PUBLIC KEY BLOCK-----$/m);
  const revoked = applyRevocation(made.cert, readRevocation(made.revocation), NOW + 1);
  assert.ok(keyState(revoked, NOW + 1).revoked);
});
