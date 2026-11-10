// The hashes and what is built on them, against the standards' own examples, constants derived
// again from their definition, and Node's OpenSSL on random inputs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, pbkdf2Sync, randomBytes, scryptSync } from 'node:crypto';
import { sha1, SHA1 } from '../src/core/crypto/sha1.ts';
import { sha256, SHA256, SHA256_H, SHA256_K } from '../src/core/crypto/sha256.ts';
import { sha512, SHA512, SHA512_H, SHA512_K } from '../src/core/crypto/sha512.ts';
import { hmac } from '../src/core/crypto/hmac.ts';
import { pbkdf2 } from '../src/core/crypto/pbkdf2.ts';
import { scrypt } from '../src/core/crypto/scrypt.ts';
import { HmacDrbg } from '../src/core/crypto/drbg.ts';
import { crc24 } from '../src/core/crypto/crc24.ts';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const bytes = (s: string) => new TextEncoder().encode(s);
const unhex = (s: string) => new Uint8Array(Buffer.from(s.replace(/\s+/g, ''), 'hex'));

function primes(count: number): bigint[] {
  const out: bigint[] = [];
  for (let n = 2n; out.length < count; n++) if (out.every((p) => n % p !== 0n)) out.push(n);
  return out;
}
function iroot(x: bigint, k: bigint): bigint {
  let r = 1n << (BigInt(x.toString(2).length) / k + 1n);
  for (;;) {
    const next = ((k - 1n) * r + x / r ** (k - 1n)) / k;
    if (next >= r) break;
    r = next;
  }
  while ((r + 1n) ** k <= x) r++;
  while (r ** k > x) r--;
  return r;
}
// The first `bits` bits of the fractional part of the k-th root of each prime.
const fractions = (count: number, k: bigint, bits: bigint) => primes(count).map((p) => iroot(p << (bits * k), k) & ((1n << bits) - 1n));

test('SHA-256 and SHA-512 constants are what their definition gives', () => {
  assert.deepEqual([...SHA256_K].map(BigInt), fractions(64, 3n, 32n));
  assert.deepEqual([...SHA256_H].map(BigInt), fractions(8, 2n, 32n));
  const pairs = (a: Uint32Array) => Array.from({ length: a.length / 2 }, (_, i) => (BigInt(a[2 * i]) << 32n) | BigInt(a[2 * i + 1]));
  assert.deepEqual(pairs(SHA512_K), fractions(80, 3n, 64n));
  assert.deepEqual(pairs(SHA512_H), fractions(8, 2n, 64n));
});

test('FIPS 180 examples', () => {
  assert.equal(hex(sha1(bytes('abc'))), 'a9993e364706816aba3e25717850c26c9cd0d89d');
  assert.equal(hex(sha256(bytes('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(hex(sha256(new Uint8Array(0))), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(
    hex(sha512(bytes('abc'))),
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
  );
  assert.equal(hex(sha1(new Uint8Array(1_000_000).fill(0x61))), '34aa973cd4c4daa4f61eeb2bdbad27316534016f');
});

test('the hashes agree with OpenSSL on every length around the block edges and at random', () => {
  const lengths = [...Array(300).keys(), 1000, 4095, 4096, 65537];
  for (const n of lengths) {
    const data = randomBytes(n);
    assert.equal(hex(sha1(data)), createHash('sha1').update(data).digest('hex'), `sha1 ${n}`);
    assert.equal(hex(sha256(data)), createHash('sha256').update(data).digest('hex'), `sha256 ${n}`);
    assert.equal(hex(sha512(data)), createHash('sha512').update(data).digest('hex'), `sha512 ${n}`);
  }
});

test('feeding a hash in pieces gives the same digest', () => {
  for (const algo of [SHA1, SHA256, SHA512]) {
    const data = randomBytes(1000);
    const h = algo.create();
    for (let at = 0; at < data.length; ) {
      const n = Math.floor(Math.random() * 150);
      h.update(data.subarray(at, at + n));
      at += n;
    }
    assert.equal(hex(h.digest()), createHash(algo.name.toLowerCase()).update(data).digest('hex'));
  }
});

test('HMAC: RFC 4231 case 2, and OpenSSL with keys of every size class', () => {
  assert.equal(
    hex(hmac(SHA256, bytes('Jefe'), bytes('what do ya want for nothing?'))),
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  );
  for (const keyLength of [0, 20, 64, 100, 128, 200]) {
    const key = randomBytes(keyLength);
    const data = randomBytes(77);
    for (const algo of [SHA1, SHA256, SHA512]) {
      assert.equal(hex(hmac(algo, key, data)), createHmac(algo.name.toLowerCase(), key).update(data).digest('hex'));
    }
  }
});

test('PBKDF2 agrees with OpenSSL', () => {
  for (const [iterations, length] of [[1, 32], [2, 64], [1000, 20], [3, 100]]) {
    const password = randomBytes(13);
    const salt = randomBytes(16);
    assert.equal(hex(pbkdf2(SHA256, password, salt, iterations, length)), pbkdf2Sync(password, salt, iterations, length, 'sha256').toString('hex'));
  }
});

test('scrypt: RFC 7914 §12, and OpenSSL', async () => {
  assert.equal(
    hex(await scrypt(new Uint8Array(0), new Uint8Array(0), { N: 16, r: 1, p: 1, length: 64 })),
    '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906',
  );
  assert.equal(
    hex(await scrypt(bytes('password'), bytes('NaCl'), { N: 1024, r: 8, p: 16, length: 64 })),
    'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640',
  );
  for (const [N, r, p] of [[2, 1, 1], [256, 2, 3], [4096, 8, 1]]) {
    const password = randomBytes(10);
    const salt = randomBytes(12);
    assert.equal(hex(await scrypt(password, salt, { N, r, p, length: 48 })), scryptSync(password, salt, 48, { N, r, p, maxmem: 2 ** 28 }).toString('hex'));
  }
});

// SP 800-90A HMAC_DRBG written out again, plainly, over OpenSSL's HMAC: the two must agree.
function referenceDrbg(entropy: Buffer, nonce: Buffer, pers: Buffer) {
  let K = Buffer.alloc(64, 0);
  let V = Buffer.alloc(64, 1);
  const mac = (key: Buffer, ...parts: Buffer[]) => createHmac('sha512', key).update(Buffer.concat(parts)).digest();
  const update = (data: Buffer) => {
    K = mac(K, V, Buffer.of(0), data);
    V = mac(K, V);
    if (data.length) {
      K = mac(K, V, Buffer.of(1), data);
      V = mac(K, V);
    }
  };
  update(Buffer.concat([entropy, nonce, pers]));
  return {
    generate(n: number, add = Buffer.alloc(0)) {
      if (add.length) update(add);
      let out = Buffer.alloc(0);
      while (out.length < n) {
        V = mac(K, V);
        out = Buffer.concat([out, V]);
      }
      update(add);
      return out.subarray(0, n);
    },
    reseed(entropy: Buffer, add = Buffer.alloc(0)) {
      update(Buffer.concat([entropy, add]));
    },
  };
}

test('HMAC_DRBG agrees with SP 800-90A written out plainly', () => {
  const entropy = randomBytes(48);
  const nonce = randomBytes(16);
  const pers = randomBytes(10);
  const ours = new HmacDrbg(entropy, nonce, pers);
  const theirs = referenceDrbg(entropy, nonce, pers);
  for (const n of [1, 64, 65, 200]) assert.equal(hex(ours.generate(n)), theirs.generate(n).toString('hex'));
  const add = randomBytes(20);
  assert.equal(hex(ours.generate(100, add)), theirs.generate(100, add).toString('hex'));
  const more = randomBytes(32);
  ours.reseed(more);
  theirs.reseed(more);
  assert.equal(hex(ours.generate(64)), theirs.generate(64).toString('hex'));
  assert.throws(() => new HmacDrbg(new Uint8Array(16)));
});

test('CRC-24: the catalogue check value', () => {
  assert.equal(crc24(bytes('123456789')), 0x21cf02);
  assert.equal(crc24(new Uint8Array(0)), 0xb704ce);
});
