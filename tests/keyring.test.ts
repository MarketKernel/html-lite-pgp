// The keyring, the file container and the agent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Agent } from '../src/core/agent.ts';
import { containerPasswordStrong, readContainer, writeContainer } from '../src/core/container.ts';
import { PgpError } from '../src/core/errors.ts';
import { generate } from '../src/core/generate.ts';
import { fingerprintHex, keyState, markVerified, withExpiry } from '../src/core/keys.ts';
import { Keyring, MemoryStore, mergeCerts } from '../src/core/keyring.ts';
import { readKeys } from '../src/core/pgp.ts';
import { unlockAll } from '../src/core/secret.ts';

const NOW = 1_800_000_000;
const text = (name: string) => readFileSync(new URL(`./fixtures/gnupg/${name}`, import.meta.url), 'utf8');
const random = (n: number) => new Uint8Array(randomBytes(n));

test('import: new, unchanged, a secret part joining its public key, keys outside the profile refused', async () => {
  const ring = new Keyring(new MemoryStore());
  const [carolPub] = readKeys(text('carol-public.asc'));
  const [carolSec] = readKeys(text('carol-secret.asc'));
  assert.deepEqual((await ring.importCerts([carolPub], NOW)).map((r) => r.status), ['new']);
  assert.deepEqual((await ring.importCerts([carolPub], NOW)).map((r) => r.status), ['unchanged']);
  assert.ok(!ring.get('3AE9D13A5FC82B8043738CFC2CC30ACC6EDD59F3')!.secret);
  assert.deepEqual((await ring.importCerts([carolSec], NOW)).map((r) => r.status), ['updated']);
  assert.ok(ring.get('3ae9d13a5fc82b8043738cfc2cc30acc6edd59f3')!.secret);
  const refused = await ring.importCerts(readKeys(text('frank-public.asc')), NOW);
  assert.equal(refused[0].status, 'refused');
  assert.match(refused[0].problem!, /RSA.*Curve25519/);
  // What was stored reads back the same.
  const again = new Keyring(ring['store' as keyof Keyring] as unknown as MemoryStore);
  await again.load();
  assert.equal(again.size, 1);
  assert.ok(again.list()[0].secret);
});

test('merging takes in new signatures and never loses any', async () => {
  const made = await generate({ name: 'M', email: 'm@example.org', passphrase: '', expiresIn: 1000, source: { kind: 'random', random }, random, now: NOW });
  const [seed] = [...(await unlockAll(made.cert, '')).values()].filter((s) => s.kind === 'ed25519').map((s) => (s as { seed: Uint8Array }).seed);
  const longer = withExpiry(made.cert, seed, 0, NOW + 10);
  const merged = mergeCerts(made.cert, longer);
  assert.equal(keyState(merged, NOW + 20).expires, null);
  assert.equal(mergeCerts(longer, made.cert).users[0].sigs.length, 2);
  const ring = new Keyring(new MemoryStore());
  await ring.importCerts([made.cert], NOW);
  assert.deepEqual((await ring.importCerts([longer], NOW + 20)).map((r) => r.status), ['updated']);
  assert.equal(keyState(ring.list()[0].cert, NOW + 30).expires, null);
});

test('verified: our own keys, and keys we marked', async () => {
  const me = await generate({ name: 'Me', email: 'me@example.org', passphrase: '', expiresIn: 0, source: { kind: 'random', random }, random, now: NOW });
  const ring = new Keyring(new MemoryStore());
  await ring.importCerts([me.cert, ...readKeys(text('carol-public.asc'))], NOW);
  const mine = ring.get(fingerprintHex(me.cert.primary.fingerprint))!;
  const carol = ring.get('3AE9D13A5FC82B8043738CFC2CC30ACC6EDD59F3')!;
  assert.ok(ring.verified(mine, NOW));
  assert.ok(!ring.verified(carol, NOW));
  const seed = [...(await unlockAll(me.cert, '')).values()].find((s) => s.kind === 'ed25519') as { seed: Uint8Array };
  await ring.put(markVerified(carol.cert, 'Carol Example <carol@example.org>', me.cert.primary, seed.seed, NOW + 1), 'imported', NOW + 1);
  assert.ok(ring.verified(ring.get('3AE9D13A5FC82B8043738CFC2CC30ACC6EDD59F3')!, NOW + 2));
  await ring.remove(fingerprintHex(me.cert.primary.fingerprint), { secretOnly: true });
  assert.ok(!ring.get(fingerprintHex(me.cert.primary.fingerprint))!.secret);
});

test('the container: the whole keyring under a password, back again; weak passwords refused', async () => {
  const me = await generate({ name: 'Me', email: 'me@example.org', passphrase: 'ключ', expiresIn: 0, source: { kind: 'random', random }, random, now: NOW });
  const certs = [me.cert, ...readKeys(text('carol-public.asc')), ...readKeys(text('dave-public-lsigned-by-carol.asc'))];
  const password = 'зелёная лампа на старом столе';
  assert.ok(containerPasswordStrong(password));
  assert.ok(!containerPasswordStrong('short'));
  await assert.rejects(writeContainer(certs, 'short', random, NOW), /stronger password/);
  const bytes = await writeContainer(certs, password, random, NOW);
  const back = await readContainer(bytes, password, NOW);
  assert.deepEqual(back.map((c) => fingerprintHex(c.primary.fingerprint)), certs.map((c) => fingerprintHex(c.primary.fingerprint)));
  assert.ok(back[0].primary.secretBody);
  assert.equal((await unlockAll(back[0], 'ключ')).size, 2);
  // Carol's local certification of Dave travels with the container.
  assert.equal(back[2].users[0].sigs.length, certs[2].users[0].sigs.length);
  await assert.rejects(readContainer(bytes, 'не тот пароль совсем', NOW), (e: unknown) => e instanceof PgpError && e.code === 'bad-passphrase');
});

test('the agent forgets after its time, when asked, and when the key changes', async () => {
  const agent = new Agent(50);
  const secret = { kind: 'ed25519' as const, seed: new Uint8Array(32).fill(7) };
  agent.put('A', Uint8Array.of(1), new Map([['A', secret]]));
  assert.ok(agent.get('A', Uint8Array.of(1)));
  assert.equal(agent.get('A', Uint8Array.of(2)), null, 'a changed record drops the cache');
  assert.ok(secret.seed.every((b) => b === 0), 'and wipes the secret');
  agent.put('B', Uint8Array.of(1), new Map([['B', { kind: 'ed25519', seed: new Uint8Array(32).fill(1) }]]));
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(agent.size, 0);
  const never = new Agent(0);
  never.put('C', Uint8Array.of(1), new Map());
  assert.equal(never.size, 0);
});

test('a container session saves again without the password, and the file still opens with it', async () => {
  const { newContainerSession, openContainer, saveContainer } = await import('../src/core/container.ts');
  const password = 'пять разных слов для сессии';
  const session = await newContainerSession(password, random);
  const certs = readKeys(text('carol-public.asc'));
  const first = await saveContainer(session, certs, random, NOW);
  const opened = await openContainer(first, password, NOW);
  assert.equal(opened.certs.length, 1);
  assert.ok(opened.session);
  const second = await saveContainer(opened.session!, [...certs, ...readKeys(text('erin-public.asc'))], random, NOW + 1);
  assert.equal((await readContainer(second, password, NOW)).length, 2);
  assert.notDeepEqual(first.slice(-40), second.slice(-40));
});
