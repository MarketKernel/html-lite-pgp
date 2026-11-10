// Signatures over data: GnuPG's checked here, ours made here; every status a check can give.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { armor, dearmor } from '../src/core/armor.ts';
import { readCleartext } from '../src/core/cleartext.ts';
import { x25519Base } from '../src/core/crypto/x25519.ts';
import { applyRevocation, makeCert, parseCerts, revocationSignature } from '../src/core/keys.ts';
import type { Cert } from '../src/core/keys.ts';
import { readPackets } from '../src/core/packets.ts';
import { readSignature } from '../src/core/signature.ts';
import { checkSignature, signCleartext, signData } from '../src/core/verify.ts';

const NOW = 1_800_000_000;
const file = (name: string) => readFileSync(new URL(`./fixtures/gnupg/${name}`, import.meta.url));
const cert = (name: string): Cert => parseCerts(dearmor(file(name).toString()).data)[0];
const message = new Uint8Array(file('message.txt'));
const sigOf = (bytes: Uint8Array) => readSignature(readPackets(bytes)[0].body);

test("GnuPG's clear-signed text: good with Carol's key, unknown without, bad when changed", () => {
  const clear = readCleartext(file('clearsigned-by-carol.asc').toString());
  assert.equal(clear.text, file('message.txt').toString().replace(/\n$/, '').replace(/[ \t]+$/gm, ''));
  const carol = cert('carol-public.asc');
  assert.equal(checkSignature(clear.signatures[0], [clear.signed], [carol], NOW).status, 'good');
  assert.equal(checkSignature(clear.signatures[0], [clear.signed], [], NOW).status, 'unknown-key');
  const changed = readCleartext(file('clearsigned-by-carol.asc').toString().replace('10.', '11.'));
  assert.equal(checkSignature(changed.signatures[0], [changed.signed], [carol], NOW).status, 'bad');
  // Trailing spaces are not signed: adding some changes nothing.
  const spaced = readCleartext(file('clearsigned-by-carol.asc').toString().replace('Dash line', 'Dash line   '));
  assert.equal(checkSignature(spaced.signatures[0], [spaced.signed], [carol], NOW).status, 'good');
});

test("GnuPG's detached signatures, binary and armored, and by a signing subkey", () => {
  const carol = cert('carol-public.asc');
  assert.equal(checkSignature(sigOf(new Uint8Array(file('message.txt.carol.sig'))), [message], [carol], NOW).status, 'good');
  assert.equal(checkSignature(sigOf(dearmor(file('message.txt.carol.asc').toString()).data), [message], [carol], NOW).status, 'good');
  const erin = cert('erin-public.asc');
  const check = checkSignature(sigOf(new Uint8Array(file('message.txt.erin.sig'))), [message], [carol, erin], NOW);
  assert.equal(check.status, 'good');
  assert.equal(check.cert, erin);
  assert.notEqual(check.key, erin.primary);
  const other = new Uint8Array(message);
  other[0] ^= 1;
  assert.equal(checkSignature(sigOf(new Uint8Array(file('message.txt.carol.sig'))), [other], [carol], NOW).status, 'bad');
});

test("an RSA signature is outside the profile, with or without Frank's key", () => {
  const clear = readCleartext(file('clearsigned-by-frank.asc').toString());
  assert.equal(checkSignature(clear.signatures[0], [clear.signed], [cert('frank-public.asc')], NOW).status, 'unsupported');
  assert.equal(checkSignature(clear.signatures[0], [clear.signed], [], NOW).status, 'unsupported');
});

function ours(expiresIn = 0) {
  const seed = randomBytes(32);
  const c = makeCert({ seed, subkeyPoint: x25519Base(randomBytes(32)), userId: 'Me <me@example.org>', created: NOW, expiresIn, signedAt: NOW });
  return { seed, cert: c, signer: { cert: c, key: c.primary, seed } };
}

test('our signatures: clear-signed with dashes and escapes, detached; expired and revoked keys', () => {
  const me = ours(1000);
  const text = 'Привет\n-----BEGIN PGP SIGNATURE-----\n- dash\nlast line  \n';
  const signed = signCleartext(text, me.signer, NOW + 10);
  assert.match(signed, /^- -----BEGIN PGP SIGNATURE-----$/m);
  const clear = readCleartext(signed);
  assert.equal(clear.text, text.replace(/\n$/, '').replace(/[ \t]+$/gm, ''));
  assert.equal(checkSignature(clear.signatures[0], [clear.signed], [me.cert], NOW + 20).status, 'good');
  // Made after the key expired.
  const late = readCleartext(signCleartext('x', me.signer, NOW + 2000));
  assert.equal(checkSignature(late.signatures[0], [late.signed], [me.cert], NOW + 3000).status, 'key-expired');
  // Made before, checked after: still good.
  assert.equal(checkSignature(clear.signatures[0], [clear.signed], [me.cert], NOW + 3000).status, 'good');
  const data = randomBytes(5000);
  const sig = readSignature(signData(data, me.signer, NOW + 10));
  assert.equal(checkSignature(sig, [data], [me.cert], NOW + 20).status, 'good');
  const revoked = applyRevocation(me.cert, revocationSignature(me.cert, me.seed, 2, '', NOW + 30), NOW + 30);
  assert.equal(checkSignature(sig, [data], [revoked], NOW + 40).status, 'key-revoked');
  // From the future.
  const future = readSignature(signData(data, me.signer, NOW + 100_000));
  assert.equal(checkSignature(future, [data], [me.cert], NOW + 50).status, 'bad');
});

test('a Hash header must name the signature’s hash', () => {
  const me = ours();
  const signed = signCleartext('text', me.signer, NOW + 1).replace('Hash: SHA512', 'Hash: SHA256');
  assert.throws(() => readCleartext(signed), /does not announce/);
  // Without a Hash header (RFC 9580 allows it) the text still reads.
  assert.equal(readCleartext(signCleartext('text', me.signer, NOW + 1).replace('Hash: SHA512\n', '')).text, 'text');
  void armor;
});
