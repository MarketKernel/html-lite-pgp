// Secret keys: GnuPG's exports unlocked with their passphrases, ours protected and unlocked
// again, and the Key Overwriting check catching a swapped public part.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dearmor } from '../src/core/armor.ts';
import { PgpError } from '../src/core/errors.ts';
import { keyState, makeCert, parseCerts, writeCert } from '../src/core/keys.ts';
import type { Cert, KeyPacket } from '../src/core/keys.ts';
import { isUnprotected, protect, protectAll, unlock, unlockAll, withSecret } from '../src/core/secret.ts';
import { decodeCount } from '../src/core/s2k.ts';
import { ed25519PublicKey } from '../src/core/crypto/ed25519.ts';
import { x25519Base } from '../src/core/crypto/x25519.ts';
import { concat } from '../src/core/crypto/util.ts';

const NOW = 1_800_000_000;
const cert = (name: string): Cert => parseCerts(dearmor(readFileSync(new URL(`./fixtures/gnupg/${name}`, import.meta.url), 'utf8')).data)[0];
const random = (n: number) => new Uint8Array(randomBytes(n));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

test('the S2K count byte decodes as RFC 4880 says', () => {
  assert.equal(decodeCount(0), 1024);
  assert.equal(decodeCount(0xff), 65_011_712);
  assert.equal(decodeCount(253), 60_817_408);
});

test("GnuPG's exported secret keys open with their passphrases, and not without", async () => {
  const carol = cert('carol-secret.asc');
  const secrets = await unlockAll(carol, 'carol passphrase');
  assert.equal(secrets.size, 2);
  const primary = secrets.get(carol.primary)!;
  assert.equal(primary.kind, 'ed25519');
  assert.equal(hex(ed25519PublicKey((primary as { seed: Uint8Array }).seed)), hex(carol.primary.point!));
  const sub = secrets.get(carol.subkeys[0].key)!;
  assert.equal(sub.kind, 'cv25519');
  assert.equal(hex(x25519Base((sub as { scalar: Uint8Array }).scalar)), hex(carol.subkeys[0].key.point!));
  await assert.rejects(unlock(carol.primary, 'wrong passphrase'), (e: PgpError) => e.code === 'bad-passphrase');
  const dave = cert('dave-secret.asc');
  assert.ok(isUnprotected(dave.primary));
  assert.equal((await unlockAll(dave, '')).size, 2);
  const erin = cert('erin-secret.asc');
  assert.equal((await unlockAll(erin, 'erin passphrase')).size, 3);
});

test('a public part swapped beside the secret is caught (Key Overwriting)', async () => {
  const carol = cert('carol-secret.asc');
  const other = cert('dave-public.asc');
  // Carol's encrypted secret beside Dave's public subkey.
  const swappedPoint: KeyPacket = { ...carol.subkeys[0].key, point: other.subkeys[0].key.point };
  await assert.rejects(unlock(swappedPoint, 'carol passphrase'), (e: PgpError) => e.code === 'integrity');
  const weakKdf: KeyPacket = { ...carol.subkeys[0].key, kdf: { hash: 2, cipher: 7 } };
  await assert.rejects(unlock(weakKdf, 'carol passphrase'), (e: PgpError) => e.code === 'integrity');
  const swappedPrimary: KeyPacket = { ...carol.primary, point: other.primary.point };
  await assert.rejects(unlock(swappedPrimary, 'carol passphrase'), (e: PgpError) => e.code === 'integrity');
});

test('our protection round-trips, at the full count and a quick one, and with no passphrase', async () => {
  const seed = random(32);
  const scalar = random(32);
  const made = makeCert({ seed, subkeyPoint: x25519Base(scalar), userId: 'R <r@example.org>', created: NOW, expiresIn: 0, signedAt: NOW });
  const secrets = new Map<KeyPacket, import('../src/core/secret.ts').Secret>([
    [made.primary, { kind: 'ed25519', seed }],
    [made.subkeys[0].key, { kind: 'cv25519', scalar }],
  ]);
  const full = await protectAll(made, secrets, 'пароль — длинный', { random });
  const back = parseCerts(writeCert(full, { secret: true }))[0];
  assert.ok(keyState(back, NOW + 1).valid);
  const opened = await unlockAll(back, 'пароль — длинный');
  assert.equal(hex((opened.get(back.primary) as { seed: Uint8Array }).seed), hex(seed));
  // The scalar comes back clamped, which X25519 does anyway: the same public key.
  assert.equal(hex(x25519Base((opened.get(back.subkeys[0].key) as { scalar: Uint8Array }).scalar)), hex(x25519Base(scalar)));
  await assert.rejects(unlockAll(back, 'пароль — длинный!'), (e: PgpError) => e.code === 'bad-passphrase');
  const open = withSecret(made.primary, await protect({ kind: 'ed25519', seed }, '', { random }), true);
  assert.ok(isUnprotected(open));
  assert.equal(hex(((await unlock(open, '')) as { seed: Uint8Array }).seed), hex(seed));
  const quick = withSecret(made.primary, await protect({ kind: 'ed25519', seed }, 'x', { random, countByte: 0 }), true);
  assert.equal(hex(((await unlock(quick, 'x')) as { seed: Uint8Array }).seed), hex(seed));
  // Public export of a secret key has no secret in it.
  assert.ok(!parseCerts(writeCert(full))[0].primary.secretBody);
  void concat;
});
