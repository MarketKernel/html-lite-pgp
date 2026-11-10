// Packet framing, MPIs and armor: round trips, the edges of every length encoding, GnuPG's own
// output, and broken input that must end in a PgpError and nothing else.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Reader, Writer } from '../src/core/bytes.ts';
import { PgpError } from '../src/core/errors.ts';
import { readPackets, writePacket, TAG } from '../src/core/packets.ts';
import { fixed, readMpi, writeMpi } from '../src/core/mpi.ts';
import { armor, dearmor, dearmorAll, fromBase64, reflowArmor, toBase64 } from '../src/core/armor.ts';

const fixture = (name: string) => readFileSync(new URL(`./fixtures/gnupg-hp/${name}`, import.meta.url));

test('packets round-trip at the edges of each length encoding', () => {
  for (const n of [0, 1, 191, 192, 193, 8383, 8384, 8385, 70_000]) {
    const body = randomBytes(n);
    const packets = readPackets(writePacket(TAG.LITERAL, body));
    assert.equal(packets.length, 1);
    assert.equal(packets[0].tag, TAG.LITERAL);
    assert.ok(Buffer.from(packets[0].body).equals(body), `length ${n}`);
  }
});

test('old-format headers, and partial lengths only where allowed', () => {
  const old = Uint8Array.of(0x80 | (TAG.USER_ID << 2) | 0, 3, 0x61, 0x62, 0x63, 0x80 | (TAG.LITERAL << 2) | 3, 1, 2);
  const packets = readPackets(old);
  assert.deepEqual(packets.map((p) => [p.tag, [...p.body]]), [[TAG.USER_ID, [0x61, 0x62, 0x63]], [TAG.LITERAL, [1, 2]]]);
  const part = randomBytes(512);
  const partial = new Uint8Array([0xc0 | TAG.LITERAL, 0xe9, ...part, 3, 7, 8, 9]);
  assert.deepEqual([...readPackets(partial)[0].body], [...part, 7, 8, 9]);
  const notData = new Uint8Array([0xc0 | TAG.USER_ID, 0xe9, ...part, 0]);
  assert.throws(() => readPackets(notData), (e: PgpError) => e.code === 'malformed');
  const small = new Uint8Array([0xc0 | TAG.LITERAL, 0xe1, 1, 2, 0]);
  assert.throws(() => readPackets(small), /512/);
  assert.throws(() => readPackets(Uint8Array.of(0x41, 0)), /not OpenPGP/);
});

test('MPIs: exact bit counts, leading zeros, padding back to a fixed size', () => {
  const w = new Writer();
  writeMpi(w, Uint8Array.of(0, 0, 0x01, 0xff));
  writeMpi(w, Uint8Array.of(0x40, ...new Uint8Array(32).fill(7)));
  const bytes = w.finish();
  assert.deepEqual([...bytes.subarray(0, 4)], [0, 9, 1, 0xff]);
  const r = new Reader(bytes);
  assert.deepEqual([...readMpi(r)], [1, 0xff]);
  assert.equal(readMpi(r).length, 33);
  r.done('the test');
  assert.deepEqual([...fixed(Uint8Array.of(5), 4, 'x')], [0, 0, 0, 5]);
  assert.throws(() => fixed(new Uint8Array(33), 32, 'x'));
  assert.deepEqual([...readMpi(new Reader(Uint8Array.of(0, 10, 1, 0xff)))], [1, 0xff]);
  assert.throws(() => readMpi(new Reader(Uint8Array.of(0, 9, 0xff, 0xff))), /longer than its bit count/);
  assert.throws(() => readMpi(new Reader(Uint8Array.of(0, 16, 1))), /past the end/);
});

test('base64 agrees with Node, and refuses what is not base64', () => {
  for (let n = 0; n < 50; n++) {
    const data = randomBytes(n);
    assert.equal(toBase64(data), data.toString('base64'));
    assert.ok(Buffer.from(fromBase64(data.toString('base64'))).equals(data));
  }
  assert.throws(() => fromBase64('ab!d'), /not base64/);
  assert.throws(() => fromBase64('abc'), /multiple of 4/);
  assert.throws(() => fromBase64('a=bc'), /not base64/);
});

test('armor round-trips; a damaged checksum and stray text are caught', () => {
  const data = randomBytes(1000);
  const text = armor('MESSAGE', data);
  assert.match(text, /^-----BEGIN PGP MESSAGE-----\n\n/);
  assert.ok(text.split('\n').every((line) => line.length <= 64));
  const back = dearmor(text);
  assert.equal(back.type, 'MESSAGE');
  assert.ok(Buffer.from(back.data).equals(data));
  assert.ok(Buffer.from(dearmor(text.replace(/\n/g, '\r\n')).data).equals(data));
  const damaged = text.replace(/\n([A-Za-z])/, (_m, c: string) => `\n${c === 'A' ? 'B' : 'A'}`);
  assert.throws(() => dearmor(damaged), (e: PgpError) => e.code === 'integrity');
  assert.throws(() => dearmor(text.replace('-----END PGP MESSAGE-----', '')), /END/);
  assert.throws(() => dearmor('hello'), (e: PgpError) => e.code === 'unexpected');
  const two = dearmorAll(`junk\n${armor('PUBLIC KEY BLOCK', Uint8Array.of(1))}between\n${armor('SIGNATURE', Uint8Array.of(2))}`);
  assert.deepEqual(two.map((b) => [b.type, [...b.data]]), [['PUBLIC KEY BLOCK', [1]], ['SIGNATURE', [2]]]);
});

test('armor flattened onto one line is put back', () => {
  const text = armor('MESSAGE', randomBytes(300));
  const flat = text.replace(/\n/g, ' ');
  assert.ok(Buffer.from(dearmor(reflowArmor(flat)).data).equals(Buffer.from(dearmor(text).data)));
});

test("GnuPG's armored key reads as packets", () => {
  const block = dearmor(fixture('alice-public.asc').toString());
  assert.equal(block.type, 'PUBLIC KEY BLOCK');
  const tags = readPackets(block.data).map((p) => p.tag);
  assert.equal(tags[0], TAG.PUBLIC_KEY);
  assert.ok(tags.includes(TAG.USER_ID));
  assert.ok(tags.includes(TAG.PUBLIC_SUBKEY));
  const binary = readPackets(new Uint8Array(fixture('bob-public.gpg')));
  assert.equal(binary[0].tag, TAG.PUBLIC_KEY);
});

test('broken input ends in a PgpError, never in anything else', () => {
  const sources = [dearmor(fixture('alice-public.asc').toString()).data, new Uint8Array(fixture('to-bob.gpg')), dearmor(fixture('to-alice-signed-by-bob.asc').toString()).data];
  for (let i = 0; i < 5000; i++) {
    const src = sources[i % sources.length];
    const cut = i % 2 === 0;
    const data = cut ? src.subarray(0, (i * 7919) % src.length) : new Uint8Array(src);
    if (!cut) data[(i * 104729) % data.length] ^= 1 << (i % 8);
    try {
      readPackets(data);
    } catch (error) {
      assert.ok(error instanceof PgpError, `case ${i}: ${(error as Error).stack}`);
    }
  }
  const text = armor('MESSAGE', randomBytes(500));
  for (let i = 0; i < 2000; i++) {
    const chars = [...text];
    chars[(i * 7919) % chars.length] = String.fromCharCode(32 + ((i * 31) % 95));
    try {
      dearmor(chars.join(''));
    } catch (error) {
      assert.ok(error instanceof PgpError, `armor case ${i}: ${(error as Error).stack}`);
    }
  }
});
