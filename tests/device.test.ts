// A key kept by a passkey or a security key (Task.md §5.2–5.3), as far as it goes without a
// browser: the secrets packed and checked against the public key, wrapped under the PRF's key,
// GnuPG's mark for a secret that is elsewhere, and a container opened with its session.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { containerSkesk, newContainerSession, openContainerWith, saveContainer, writeContainer } from '../src/core/container.ts';
import { blobWrapped, openBlob, packSecrets, packedFingerprints, sealBlob, unpackSecrets, unwrap, wrap, wrapKey } from '../src/core/device.ts';
import { PgpError } from '../src/core/errors.ts';
import { generate } from '../src/core/generate.ts';
import { fingerprintHex, parseCerts, writeCert } from '../src/core/keys.ts';
import type { Cert } from '../src/core/keys.ts';
import { Keyring, MemoryStore } from '../src/core/keyring.ts';
import { readKeys } from '../src/core/pgp.ts';
import { GNU_DUMMY, isElsewhere, isUnprotected, readProtection, secretHere, secretsElsewhere, unlock, unlockAll } from '../src/core/secret.ts';
import type { Secret } from '../src/core/secret.ts';

const NOW = 1_800_000_000;
const random = (n: number) => new Uint8Array(randomBytes(n));
const text = (name: string) => readFileSync(new URL(`./fixtures/gnupg/${name}`, import.meta.url), 'utf8');
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

async function made(): Promise<{ cert: Cert; secrets: Map<string, Secret> }> {
  const g = await generate({ name: 'Device', email: 'device@example.org', passphrase: '', expiresIn: 0, source: { kind: 'random', random }, random, now: NOW });
  const secrets = new Map([...(await unlockAll(g.cert, ''))].map(([k, s]) => [fingerprintHex(k.fingerprint), s]));
  return { cert: g.cert, secrets };
}

const valueOf = (s: Secret) => hex(s.kind === 'ed25519' ? s.seed : s.scalar);

test('the wrapping key is HMAC-SHA-512 of the PRF output, cut to 32 bytes', () => {
  const prf = random(32);
  const expected = createHmac('sha512', prf).update('html-simple-pgp/prf/v1').digest().subarray(0, 32);
  assert.equal(hex(wrapKey(prf)), hex(expected));
});

test('secrets packed and unpacked are the same, checked against the public key', async () => {
  const { cert, secrets } = await made();
  const packed = packSecrets(cert, secrets);
  assert.equal(packed.length, 1 + 2 * 52);
  assert.deepEqual(packedFingerprints(packed), [cert.primary, cert.subkeys[0].key].map((k) => fingerprintHex(k.fingerprint)));
  const back = unpackSecrets(cert, packed);
  assert.deepEqual([...back.keys()], [...secrets.keys()]);
  for (const [fpr, s] of secrets) assert.equal(valueOf(back.get(fpr)!), valueOf(s));
});

test("a device's secret that is not this key's is refused (Key Overwriting)", async () => {
  const a = await made();
  const b = await made();
  // Another key's pack under this key: the fingerprints are not this key's.
  assert.throws(() => unpackSecrets(a.cert, packSecrets(b.cert, b.secrets)), (e: PgpError) => e.code === 'integrity');
  // This key's fingerprints with another key's secrets: they do not make its public keys.
  const swapped = packSecrets(a.cert, a.secrets);
  swapped.set(packSecrets(b.cert, b.secrets).subarray(21, 53), 21);
  assert.throws(() => unpackSecrets(a.cert, swapped), (e: PgpError) => e.code === 'integrity');
  // Cut short, or of another version.
  const packed = packSecrets(a.cert, a.secrets);
  assert.throws(() => unpackSecrets(a.cert, packed.subarray(0, 60)), PgpError);
  assert.throws(() => unpackSecrets(a.cert, Uint8Array.of(2, ...packed.subarray(1))), PgpError);
  assert.throws(() => unpackSecrets(a.cert, Uint8Array.of(1)), PgpError);
});

test('wrapped under the PRF key: opens with it; a wrong key or a changed byte gives nothing', async () => {
  const { cert, secrets } = await made();
  const k = wrapKey(random(32));
  const packed = packSecrets(cert, secrets);
  const wrapped = await wrap(k, packed, random);
  assert.equal(hex(await unwrap(k, wrapped)), hex(packed));
  await assert.rejects(unwrap(wrapKey(random(32)), wrapped), (e: PgpError) => e.code === 'integrity');
  for (const at of [0, 5, 20, wrapped.length - 1]) {
    const bad = wrapped.slice();
    bad[at] ^= 1;
    await assert.rejects(unwrap(k, bad), PgpError);
  }
});

test('a largeBlob: plain without a PRF, wrapped with one', async () => {
  const { cert, secrets } = await made();
  const packed = packSecrets(cert, secrets);
  const plain = await sealBlob(packed, null, random);
  assert.ok(!blobWrapped(plain));
  assert.equal(hex(await openBlob(plain, null)), hex(packed));
  const k = wrapKey(random(32));
  const sealed = await sealBlob(packed, k, random);
  assert.ok(blobWrapped(sealed));
  assert.ok(sealed.length < 200, `${sealed.length} bytes`);
  assert.equal(hex(await openBlob(sealed, k)), hex(packed));
  await assert.rejects(openBlob(sealed, null), (e: PgpError) => e.code === 'integrity');
  await assert.rejects(openBlob(Uint8Array.of(7, 1, 2), k), PgpError);
});

test("GnuPG's mark for a secret elsewhere: written as GnuPG writes it, read, never unlocked", async () => {
  const { cert } = await made();
  const away = secretsElsewhere(cert);
  for (const k of [away.primary, away.subkeys[0].key]) {
    assert.equal(hex(k.secretBody!), hex(GNU_DUMMY));
    assert.ok(isElsewhere(k) && !secretHere(k) && !isUnprotected(k));
    assert.ok(readProtection(k).elsewhere);
    await assert.rejects(unlock(k, ''), (e: PgpError) => e.code === 'unexpected');
  }
  assert.equal((await unlockAll(away, '')).size, 0);
  // It survives writing and reading, and the keyring takes it as our key.
  const again = parseCerts(writeCert(away, { secret: true }))[0];
  assert.ok(isElsewhere(again.primary));
  const ring = new Keyring(new MemoryStore());
  assert.equal((await ring.importCerts([again], NOW))[0].status, 'new');
  assert.ok(ring.list()[0].secret);
  // The secret imported again replaces the mark; the mark never replaces a secret.
  assert.equal((await ring.importCerts([cert], NOW))[0].status, 'updated');
  assert.ok(secretHere(ring.list()[0].cert.primary));
  assert.equal((await ring.importCerts([away], NOW))[0].status, 'unchanged');
});

test("GnuPG's own export without the primary secret (--export-secret-subkeys) is read", async () => {
  const [carol] = readKeys(text('carol-secret.asc'));
  const subkeysOnly = { ...secretsElsewhere(carol), subkeys: carol.subkeys };
  const opened = await unlockAll(subkeysOnly, 'carol passphrase');
  assert.equal(opened.size, 1);
  assert.equal([...opened.values()][0].kind, 'cv25519');
});

test('a container opens with its session, and only the container of that session', async () => {
  const { cert } = await made();
  const session = await newContainerSession('пять разных слов для контейнера', random);
  const bytes = await saveContainer(session, [cert], random, NOW);
  assert.equal(hex(containerSkesk(bytes)!), hex(session.skesk));
  const certs = await openContainerWith(bytes, session);
  assert.equal(fingerprintHex(certs[0].primary.fingerprint), fingerprintHex(cert.primary.fingerprint));
  // Another container: another SKESK.
  const other = await writeContainer([cert], 'другие пять слов для файла', random, NOW);
  await assert.rejects(openContainerWith(other, session), (e: PgpError) => e.code === 'bad-passphrase');
  // The right SKESK with a wrong key: the MDC decides.
  await assert.rejects(openContainerWith(bytes, { ...session, key: random(32) }), (e: PgpError) => e.code === 'integrity');
  assert.equal(containerSkesk(new Uint8Array([1, 2, 3])), null);
});
