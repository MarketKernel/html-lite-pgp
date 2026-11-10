// The top of the core: telling inputs apart, opening whatever comes, GnuPG's revocation file.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { applyRevocation, keyState } from '../src/core/keys.ts';
import { classify, open, readKeys, readRevocation, verifyDetached } from '../src/core/pgp.ts';

const NOW = 1_800_000_000;
const raw = (name: string) => new Uint8Array(readFileSync(new URL(`./fixtures/gnupg/${name}`, import.meta.url)));
const text = (name: string) => readFileSync(new URL(`./fixtures/gnupg/${name}`, import.meta.url), 'utf8');

test('every kind of GnuPG file is told apart, as text and as bytes', () => {
  const expect: Record<string, string> = {
    'carol-public.asc': 'public-keys',
    'carol-public.gpg': 'public-keys',
    'carol-secret.asc': 'secret-keys',
    'to-carol.gpg': 'encrypted',
    'to-carol-signed-by-erin.asc': 'encrypted',
    'symmetric.gpg': 'encrypted',
    'signed-by-carol.gpg': 'signed',
    'clearsigned-by-carol.asc': 'clear-signed',
    'message.txt.carol.sig': 'signature',
    'message.txt.carol.asc': 'signature',
    'carol-revocation.rev': 'revocation',
    'message.txt': 'unknown',
  };
  for (const [name, kind] of Object.entries(expect)) {
    assert.equal(classify(raw(name)), kind, name);
    if (name.endsWith('.asc') || name.endsWith('.rev')) assert.equal(classify(text(name)), kind, `${name} as text`);
  }
});

test('keys from several armored blocks at once', () => {
  const both = `${text('carol-public.asc')}\nand\n${text('erin-public.asc')}`;
  assert.deepEqual(readKeys(both).map((c) => keyState(c, NOW).primaryUserId), ['Carol Example <carol@example.org>', 'Erin Example <erin@example.org>']);
});

test("GnuPG's guarded revocation certificate revokes Carol's key", () => {
  const sig = readRevocation(text('carol-revocation.rev'));
  const carol = readKeys(text('carol-public.asc'))[0];
  const revoked = applyRevocation(carol, sig, NOW);
  assert.ok(keyState(revoked, NOW).revoked);
  assert.throws(() => applyRevocation(readKeys(text('erin-public.asc'))[0], sig, NOW), /not made by this key/);
});

test('opening a clear-signed text, a signed message, and a detached signature', async () => {
  const keyring = readKeys(text('carol-public.asc'));
  const clear = await open(text('clearsigned-by-carol.asc'), { keyring, now: NOW });
  assert.ok(clear.clearSigned);
  assert.deepEqual(clear.signatures.map((s) => s.status), ['good']);
  const signed = await open(raw('signed-by-carol.gpg'), { keyring, now: NOW });
  assert.deepEqual(signed.signatures.map((s) => s.status), ['good']);
  await assert.rejects(open(text('message.txt.carol.asc'), { keyring, now: NOW }), /detached signature/);
  assert.deepEqual(verifyDetached(text('message.txt.carol.asc'), raw('message.txt'), keyring, NOW).map((s) => s.status), ['good']);
  assert.deepEqual(verifyDetached(raw('message.txt.carol.sig'), raw('message.txt'), keyring, NOW).map((s) => s.status), ['good']);
});
