// Messages: GnuPG's opened here — plain, signed, compressed, to several recipients, to hidden
// ones, with a password — and ours opened here; every kind of damage refused without a byte of
// plaintext.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dearmor } from '../src/core/armor.ts';
import { x25519Base } from '../src/core/crypto/x25519.ts';
import { PgpError } from '../src/core/errors.ts';
import { keyState, makeCert, parseCerts } from '../src/core/keys.ts';
import type { Cert } from '../src/core/keys.ts';
import { encryptMessage, openMessage, recipientsOf, signMessage } from '../src/core/message.ts';
import type { Decryptor } from '../src/core/message.ts';
import { unlockAll } from '../src/core/secret.ts';

const NOW = 1_800_000_000;
const file = (dir: string, name: string) => readFileSync(new URL(`./fixtures/${dir}/${name}`, import.meta.url));
const binary = (dir: string, name: string): Uint8Array => (name.endsWith('.asc') ? dearmor(file(dir, name).toString()).data : new Uint8Array(file(dir, name)));
const cert = (name: string): Cert => parseCerts(binary('gnupg', name))[0];
const message = file('gnupg', 'message.txt');
const random = (n: number) => new Uint8Array(randomBytes(n));
const isCode = (code: string) => (e: unknown) => e instanceof PgpError && e.code === code;

let carolDecryptor: Decryptor | null = null;
async function carol(): Promise<Decryptor> {
  if (carolDecryptor) return carolDecryptor;
  const c = cert('carol-secret.asc');
  const secrets = await unlockAll(c, 'carol passphrase');
  const key = c.subkeys[0].key;
  const s = secrets.get(key)!;
  carolDecryptor = { cert: c, key, scalar: (s as { scalar: Uint8Array }).scalar };
  return carolDecryptor;
}

test("GnuPG's message to Carol, opened with her key", async () => {
  const d = await carol();
  const data = binary('gnupg', 'to-carol.gpg');
  assert.deepEqual(recipientsOf(data)!.keyIds.map((k) => Buffer.from(k).toString('hex')), ['fa9b19ca4562ce30']);
  const opened = await openMessage(data, { keyring: [], decryptors: [d], now: NOW });
  assert.ok(Buffer.from(opened.data).equals(message));
  assert.equal(opened.filename, 'message.txt');
  assert.ok(opened.encrypted);
  assert.equal(opened.openedBy, d.cert);
  assert.deepEqual(opened.signatures, []);
  await assert.rejects(openMessage(data, { keyring: [], decryptors: [], now: NOW }), isCode('no-key'));
});

test('signed and encrypted, to several recipients, to a hidden one', async () => {
  const d = await carol();
  const keyring = [cert('carol-public.asc'), cert('erin-public.asc')];
  const byCarol = await openMessage(binary('gnupg', 'to-carol-signed-by-carol.asc'), { keyring, decryptors: [d], now: NOW });
  assert.deepEqual(byCarol.signatures.map((s) => s.status), ['good']);
  const byErin = await openMessage(binary('gnupg', 'to-carol-signed-by-erin.asc'), { keyring, decryptors: [d], now: NOW });
  assert.deepEqual(byErin.signatures.map((s) => s.status), ['good']);
  const unknown = await openMessage(binary('gnupg', 'to-carol-signed-by-erin.asc'), { keyring: [], decryptors: [d], now: NOW });
  assert.deepEqual(unknown.signatures.map((s) => s.status), ['unknown-key']);
  const many = await openMessage(binary('gnupg', 'to-carol-dave-frank.asc'), { keyring, decryptors: [d], now: NOW });
  assert.ok(Buffer.from(many.data).equals(message));
  const hidden = binary('gnupg', 'to-carol-hidden.gpg');
  assert.ok(recipientsOf(hidden)!.hidden);
  assert.ok(Buffer.from((await openMessage(hidden, { keyring, decryptors: [d], now: NOW })).data).equals(message));
});

test("GnuPG's compressed signed message and its password-encrypted one", async () => {
  const signed = await openMessage(binary('gnupg', 'signed-by-carol.gpg'), { keyring: [cert('carol-public.asc')], now: NOW });
  assert.ok(Buffer.from(signed.data).equals(message));
  assert.ok(!signed.encrypted);
  assert.deepEqual(signed.signatures.map((s) => s.status), ['good']);
  const sym = binary('gnupg', 'symmetric.gpg');
  assert.ok(recipientsOf(sym)!.password);
  assert.ok(Buffer.from((await openMessage(sym, { keyring: [], password: 'correct horse battery staple', now: NOW })).data).equals(message));
  await assert.rejects(openMessage(sym, { keyring: [], password: 'wrong horse', now: NOW }), isCode('bad-passphrase'));
});

test('what is outside the profile says so', async () => {
  const d = await carol();
  await assert.rejects(openMessage(binary('gnupg', 'to-dave.asc'), { keyring: [], decryptors: [d], now: NOW }), (e: unknown) => isCode('unsupported')(e) && /OCB/.test((e as Error).message));
  await assert.rejects(openMessage(binary('gnupg-hp', 'to-alice-signed-by-bob.asc'), { keyring: [], decryptors: [d], now: NOW }), isCode('unsupported'));
  // GnuPG 2.5 wrote this one in OCB as well (Bob's key announces AEAD): the format is the first thing said.
  await assert.rejects(openMessage(binary('gnupg-hp', 'to-bob.gpg'), { keyring: [], decryptors: [d], now: NOW }), isCode('unsupported'));
});

async function me(name: string) {
  const seed = random(32);
  const scalar = random(32);
  const c = makeCert({ seed, subkeyPoint: x25519Base(scalar), userId: `${name} <${name}@example.org>`, created: NOW, expiresIn: 0, signedAt: NOW });
  return { cert: c, seed, signer: { cert: c, key: c.primary, seed }, decryptor: { cert: c, key: c.subkeys[0].key, scalar } as Decryptor, to: { cert: c, key: keyState(c, NOW).encryption! } };
}

test('our messages: signed and encrypted to two recipients and a password; text and files', async () => {
  const a = await me('a');
  const b = await me('b');
  const data = new TextEncoder().encode('Секретное сообщение\n');
  const bytes = await encryptMessage({ data, format: 'u', recipients: [a.to, b.to], password: 'общий пароль', signer: a.signer, now: NOW + 1, random });
  for (const d of [a.decryptor, b.decryptor]) {
    const o = await openMessage(bytes, { keyring: [a.cert, b.cert], decryptors: [d], now: NOW + 2 });
    assert.ok(Buffer.from(o.data).equals(Buffer.from(data)));
    assert.equal(o.format, 'u');
    assert.deepEqual(o.signatures.map((s) => s.status), ['good']);
  }
  const byPassword = await openMessage(bytes, { keyring: [a.cert], password: 'общий пароль', now: NOW + 2 });
  assert.ok(Buffer.from(byPassword.data).equals(Buffer.from(data)));
  const fileData = random(300_000);
  const encryptedFile = await encryptMessage({ data: fileData, format: 'b', filename: '../../etc/отчёт.pdf', recipients: [a.to], now: NOW + 1, random });
  const openedFile = await openMessage(encryptedFile, { keyring: [], decryptors: [a.decryptor], now: NOW + 2 });
  assert.ok(Buffer.from(openedFile.data).equals(Buffer.from(fileData)));
  assert.equal(openedFile.filename, 'отчёт.pdf');
  const onlyPassword = await encryptMessage({ data, format: 'u', recipients: [], password: 'p', now: NOW, random });
  assert.ok(Buffer.from((await openMessage(onlyPassword, { keyring: [], password: 'p', now: NOW })).data).equals(Buffer.from(data)));
  const signedOnly = signMessage({ data, format: 'u', signer: b.signer, now: NOW + 1 });
  assert.deepEqual((await openMessage(signedOnly, { keyring: [b.cert], now: NOW + 2 })).signatures.map((s) => s.status), ['good']);
});

test('any change to an encrypted message is refused, without plaintext', async () => {
  const a = await me('a');
  const bytes = await encryptMessage({ data: random(5000), format: 'b', recipients: [a.to], signer: a.signer, now: NOW, random });
  const tried = new Set<string>();
  for (let i = 0; i < 400; i++) {
    const changed = new Uint8Array(bytes);
    const at = (i * 7919) % changed.length;
    changed[at] ^= 1 << (i % 8);
    try {
      await openMessage(changed, { keyring: [a.cert], decryptors: [a.decryptor], now: NOW });
      assert.fail(`a change at byte ${at} went unnoticed`);
    } catch (error) {
      assert.ok(error instanceof PgpError, `byte ${at}: ${(error as Error).stack}`);
      tried.add(error.code);
    }
  }
  assert.ok(tried.has('integrity'));
  for (const cut of [10, bytes.length - 1, bytes.length - 21, bytes.length - 23]) {
    await assert.rejects(openMessage(bytes.subarray(0, cut), { keyring: [a.cert], decryptors: [a.decryptor], now: NOW }), (e: unknown) => e instanceof PgpError);
  }
});

test('a signature meant for someone else does not count', async () => {
  const a = await me('a');
  const b = await me('b');
  const c = await me('c');
  // Signed by A for B, then the inside re-encrypted to C (as a forwarder would).
  const forB = await encryptMessage({ data: Uint8Array.of(1, 2, 3), format: 'b', recipients: [b.to], signer: a.signer, now: NOW, random });
  const inner = await openMessage(forB, { keyring: [a.cert], decryptors: [b.decryptor], now: NOW });
  assert.deepEqual(inner.signatures.map((s) => s.status), ['good']);
  const { encryptSeipd } = await import('../src/core/seipd.ts');
  const { readPackets, writePacket, TAG } = await import('../src/core/packets.ts');
  const { makePkesk } = await import('../src/core/ecdh.ts');
  const { decryptSeipd } = await import('../src/core/seipd.ts');
  const { openPkesk, readPkesk } = await import('../src/core/ecdh.ts');
  const packets = readPackets(forB);
  const session = openPkesk(readPkesk(packets[0].body), b.decryptor.key, b.decryptor.scalar)!;
  const plain = await decryptSeipd(session, packets[1].body);
  const key = random(32);
  const forwarded = new Uint8Array([...writePacket(TAG.PKESK, makePkesk(c.to.key, key, random)), ...writePacket(TAG.SEIPD, await encryptSeipd({ cipher: 9, key }, plain, random))]);
  const atC = await openMessage(forwarded, { keyring: [a.cert], decryptors: [c.decryptor], now: NOW });
  assert.deepEqual(atC.signatures.map((s) => s.status), ['bad']);
});
