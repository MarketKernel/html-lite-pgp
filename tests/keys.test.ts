// Keys GnuPG made, read as GnuPG reads them: fingerprints, user IDs, expiry, usable subkeys,
// local certifications; keys outside the profile told apart; and keys we make, read back.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dearmor } from '../src/core/armor.ts';
import { x25519Base } from '../src/core/crypto/x25519.ts';
import { readPackets, TAG } from '../src/core/packets.ts';
import { readSignature, SIG, SUB, KEY_FLAG, exportable, makeSignature, subpacket } from '../src/core/signature.ts';
import { ed25519PublicKey } from '../src/core/crypto/ed25519.ts';
import {
  applyRevocation, fingerprintHex, keyData, publicKeyBody, readKeyPacket, formatFingerprint, keyState, makeCert, markVerified, parseCerts, revocationSignature, verifiedBy, withExpiry, writeCert,
} from '../src/core/keys.ts';
import type { Cert } from '../src/core/keys.ts';

const NOW = 1_800_000_000;
const text = (name: string) => readFileSync(new URL(`./fixtures/gnupg/${name}`, import.meta.url), 'utf8');
const cert = (name: string): Cert => parseCerts(dearmor(text(name)).data)[0];
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

test("GnuPG's Carol: fingerprint, user ID, encryption subkey, signing by the primary key", () => {
  const s = keyState(cert('carol-public.asc'), NOW);
  assert.equal(fingerprintHex(s.fingerprint), '3AE9D13A5FC82B8043738CFC2CC30ACC6EDD59F3');
  assert.equal(formatFingerprint(s.fingerprint), '3AE9 D13A 5FC8 2B80 4373  8CFC 2CC3 0ACC 6EDD 59F3');
  assert.ok(s.supported && s.valid);
  assert.equal(s.primaryUserId, 'Carol Example <carol@example.org>');
  assert.equal(s.expires, null);
  assert.equal(fingerprintHex(s.encryption!.fingerprint), '7625395DBA2696DD34034FB6FA9B19CA4562CE30');
  assert.deepEqual(s.signing.map((k) => fingerprintHex(k.fingerprint)), ['3AE9D13A5FC82B8043738CFC2CC30ACC6EDD59F3']);
  // The binary export is the same key.
  assert.equal(fingerprintHex(keyState(parseCerts(new Uint8Array(readFileSync(new URL('./fixtures/gnupg/carol-public.gpg', import.meta.url))))[0], NOW).fingerprint), fingerprintHex(s.fingerprint));
});

test("Erin's signing subkey signs for her, her certify-only primary key does not", () => {
  const c = cert('erin-public.asc');
  const s = keyState(c, NOW);
  assert.ok(s.valid);
  assert.deepEqual(s.signing.map((k) => fingerprintHex(k.fingerprint)), ['ABD31E1C169DBF117EAEA31C9F6D71046DAFE15C']);
  assert.equal(fingerprintHex(s.encryption!.fingerprint), '3BC36E2387F31F8A75E20BC54126539328F7E05D');
});

test('a signing subkey counts only with a good back-signature', () => {
  const seed = randomBytes(32);
  const base = makeCert({ seed, subkeyPoint: x25519Base(randomBytes(32)), userId: 'S <s@example.org>', created: NOW, expiresIn: 0, signedAt: NOW });
  const subSeed = randomBytes(32);
  const subBody = publicKeyBody('ed25519', NOW, ed25519PublicKey(subSeed));
  const sub = readKeyPacket({ tag: TAG.PUBLIC_SUBKEY, body: subBody, raw: subBody });
  const signer = { seed, fingerprint: base.primary.fingerprint };
  const data = [keyData(base.primary), keyData(sub)];
  const flags = subpacket(SUB.KEY_FLAGS, Uint8Array.of(KEY_FLAG.SIGN));
  const withBinding = (hashed: Uint8Array[]) => ({ ...base, subkeys: [...base.subkeys, { key: sub, sigs: [readSignature(makeSignature(SIG.SUBKEY_BINDING, signer, data, NOW, hashed))] }] });
  const signingOf = (c: Cert) => keyState(c, NOW + 1).signing.map((k) => fingerprintHex(k.fingerprint));
  const primary = fingerprintHex(base.primary.fingerprint);
  assert.deepEqual(signingOf(withBinding([flags])), [primary]);
  const back = makeSignature(SIG.PRIMARY_BINDING, { seed: subSeed, fingerprint: sub.fingerprint }, data, NOW);
  assert.deepEqual(signingOf(withBinding([flags, subpacket(SUB.EMBEDDED, back)])), [primary, fingerprintHex(sub.fingerprint)]);
  const wrongBack = makeSignature(SIG.PRIMARY_BINDING, { seed: randomBytes(32), fingerprint: sub.fingerprint }, data, NOW);
  assert.deepEqual(signingOf(withBinding([flags, subpacket(SUB.EMBEDDED, wrongBack)])), [primary]);
});

test('keys outside the profile are told apart, and an expired key is expired', () => {
  const frank = keyState(cert('frank-public.asc'), NOW);
  assert.ok(!frank.supported);
  assert.match(frank.problem!, /RSA/);
  assert.equal(fingerprintHex(frank.fingerprint), 'A2E3CE40C173E35A0A2EEC68B94D78FAFBAA0CB3');
  const gina = keyState(cert('gina-public.asc'), NOW);
  assert.ok(gina.supported && gina.expired && !gina.valid);
  assert.equal(gina.expires, 1577923200);
  assert.equal(gina.encryption, null);
  assert.ok(keyState(cert('gina-public.asc'), 1577840000).valid);
});

test("Carol's local certification of Dave: seen by us, kept out of exports", () => {
  const dave = cert('dave-public-lsigned-by-carol.asc');
  const carol = cert('carol-public.asc');
  assert.deepEqual(verifiedBy(dave, [carol.primary], NOW), ['Dave Example <dave@example.org>']);
  const lsign = dave.users[0].sigs.find((s) => s.type === SIG.CERT_GENERIC)!;
  assert.ok(!exportable(lsign));
  const exported = parseCerts(writeCert(dave))[0];
  assert.deepEqual(verifiedBy(exported, [carol.primary], NOW), []);
  assert.deepEqual(verifiedBy(parseCerts(writeCert(dave, { local: true }))[0], [carol.primary], NOW), ['Dave Example <dave@example.org>']);
});

test('a key we make reads back as valid, with the profile preferences', () => {
  const seed = randomBytes(32);
  const sub = randomBytes(32);
  const made = makeCert({ seed, subkeyPoint: x25519Base(sub), userId: 'Тест Тестов <test@example.org>', created: NOW - 100, expiresIn: 3 * 365 * 86400, signedAt: NOW - 100 });
  const back = parseCerts(writeCert(made))[0];
  const s = keyState(back, NOW);
  assert.ok(s.valid);
  assert.equal(s.primaryUserId, 'Тест Тестов <test@example.org>');
  assert.equal(s.expires, NOW - 100 + 3 * 365 * 86400);
  assert.ok(s.encryption);
  assert.equal(hex(s.encryption!.point!), hex(x25519Base(sub)));
  const tags = readPackets(writeCert(made)).map((p) => p.tag);
  assert.deepEqual(tags, [TAG.PUBLIC_KEY, TAG.USER_ID, TAG.SIGNATURE, TAG.PUBLIC_SUBKEY, TAG.SIGNATURE]);
  // A new expiry, then no expiry.
  const longer = withExpiry(back, seed, 10 * 365 * 86400, NOW);
  assert.equal(keyState(longer, NOW + 1).expires, NOW - 100 + 10 * 365 * 86400);
  const never = withExpiry(longer, seed, 0, NOW + 5);
  assert.equal(keyState(never, NOW + 10).expires, null);
  assert.ok(keyState(never, NOW + 10).encryption);
  // Revoked.
  const rev = revocationSignature(back, seed, 2, 'lost', NOW + 1);
  const revoked = applyRevocation(back, rev, NOW + 2);
  const rs = keyState(revoked, NOW + 3);
  assert.ok(!rs.valid);
  assert.deepEqual(rs.revoked, { time: NOW + 1, code: 2, text: 'lost' });
  assert.throws(() => applyRevocation(cert('carol-public.asc'), rev, NOW + 2), /not made by this key/);
  // Someone else's seed cannot sign for this key.
  assert.throws(() => withExpiry(back, randomBytes(32), 0, NOW), /does not match/);
});

test('we can mark a key verified, and only our own keys count', () => {
  const ours = makeCert({ seed: randomBytes(32), subkeyPoint: x25519Base(randomBytes(32)), userId: 'Me <me@example.org>', created: NOW, expiresIn: 0, signedAt: NOW });
  const seed = randomBytes(32);
  const me = makeCert({ seed, subkeyPoint: x25519Base(randomBytes(32)), userId: 'Me <me@example.org>', created: NOW, expiresIn: 0, signedAt: NOW });
  const carol = cert('carol-public.asc');
  const marked = markVerified(carol, 'Carol Example <carol@example.org>', me.primary, seed, NOW + 1);
  assert.deepEqual(verifiedBy(marked, [me.primary], NOW + 2), ['Carol Example <carol@example.org>']);
  assert.deepEqual(verifiedBy(marked, [ours.primary], NOW + 2), []);
  assert.deepEqual(verifiedBy(parseCerts(writeCert(marked))[0], [me.primary], NOW + 2), []);
});

test('altered self-signatures and keys do not pass', () => {
  const c = cert('carol-public.asc');
  // Change the user ID: the self-signature no longer covers it.
  const renamed: Cert = { ...c, users: [{ ...c.users[0], raw: new TextEncoder().encode('Mallory <carol@example.org>'), text: 'Mallory <carol@example.org>' }] };
  const s = keyState(renamed, NOW);
  assert.ok(!s.valid);
  assert.equal(s.primaryUserId, null);
  // A subkey swapped for another: its binding fails.
  const other = cert('dave-public.asc');
  const swapped: Cert = { ...c, subkeys: [{ key: other.subkeys[0].key, sigs: c.subkeys[0].sigs }] };
  assert.equal(keyState(swapped, NOW).encryption, null);
});
