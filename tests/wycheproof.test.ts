// Wycheproof's vectors: the edge cases and the malicious inputs that implementations got wrong.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ed25519Verify } from '../src/core/crypto/ed25519.ts';
import { x25519 } from '../src/core/crypto/x25519.ts';
import { aesKeyUnwrap, aesKeyWrap } from '../src/core/crypto/keywrap.ts';

const unhex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const load = (name: string) => JSON.parse(readFileSync(new URL(`./vectors/wycheproof/${name}`, import.meta.url), 'utf8'));

test('Ed25519: every Wycheproof verification vector', () => {
  let count = 0;
  for (const group of load('ed25519_test.json').testGroups) {
    const pk = unhex(group.publicKey.pk);
    for (const t of group.tests) {
      const ok = ed25519Verify(pk, unhex(t.msg), unhex(t.sig));
      assert.equal(ok, t.result === 'valid', `tcId ${t.tcId}: ${t.comment}`);
      count++;
    }
  }
  assert.ok(count > 100);
});

test('X25519: every Wycheproof vector; an all-zero result is refused', () => {
  for (const group of load('x25519_test.json').testGroups) {
    for (const t of group.tests) {
      if (/^0+$/.test(t.shared)) {
        assert.throws(() => x25519(unhex(t.private), unhex(t.public)), /zero/, `tcId ${t.tcId}`);
      } else {
        assert.equal(hex(x25519(unhex(t.private), unhex(t.public))), t.shared, `tcId ${t.tcId}: ${t.comment}`);
      }
    }
  }
});

test('AES Key Wrap: every Wycheproof vector for 128- and 256-bit keys', () => {
  for (const group of load('aes_wrap_test.json').testGroups) {
    if (group.keySize === 192) continue; // AES-192 is outside the profile.
    for (const t of group.tests) {
      const key = unhex(t.key);
      const ct = unhex(t.ct);
      const msg = unhex(t.msg);
      const what = `tcId ${t.tcId}: ${t.comment}`;
      if (t.result === 'valid') {
        assert.equal(hex(aesKeyWrap(key, msg)), t.ct, what);
        assert.equal(hex(aesKeyUnwrap(key, ct)!), t.msg, what);
      } else if (t.result === 'invalid') {
        assert.equal(aesKeyUnwrap(key, ct), null, what);
      } else {
        // "acceptable": short inputs RFC 3394 itself does not define; either way is fine, but never a wrong key.
        const out = aesKeyUnwrap(key, ct);
        if (out) assert.equal(hex(out), t.msg, what);
      }
    }
  }
});
