// AES, CFB and Key Wrap against FIPS 197, RFC 3394 and OpenSSL.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { Aes } from '../src/core/crypto/aes.ts';
import { cfbDecrypt, cfbDecryptAsync, cfbEncrypt, cfbEncryptAsync } from '../src/core/crypto/cfb.ts';
import { aesKeyUnwrap, aesKeyWrap } from '../src/core/crypto/keywrap.ts';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const unhex = (s: string) => new Uint8Array(Buffer.from(s.replace(/\s+/g, ''), 'hex'));

// The S-box from its definition: inversion in GF(2^8) mod x^8+x^4+x^3+x+1, then the affine map.
function referenceSbox(): number[] {
  const mul = (a: number, b: number) => {
    let p = 0;
    for (; b; b >>= 1, a = (a << 1) ^ (a & 0x80 ? 0x11b : 0)) if (b & 1) p ^= a;
    return p & 0xff;
  };
  const inv = (x: number) => (x === 0 ? 0 : Array.from({ length: 256 }, (_, y) => y).find((y) => mul(x, y) === 1)!);
  const rotl = (x: number, n: number) => ((x << n) | (x >> (8 - n))) & 0xff;
  return Array.from({ length: 256 }, (_, x) => {
    const b = inv(x);
    return b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ 0x63;
  });
}

test('FIPS 197 appendix C', () => {
  const out = new Uint8Array(16);
  const plain = unhex('00112233445566778899aabbccddeeff');
  const a128 = new Aes(unhex('000102030405060708090a0b0c0d0e0f'));
  a128.encryptBlock(plain, 0, out, 0);
  assert.equal(hex(out), '69c4e0d86a7b0430d8cdb78070b4c55a');
  a128.decryptBlock(out, 0, out, 0);
  assert.equal(hex(out), hex(plain));
  const a256 = new Aes(unhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'));
  a256.encryptBlock(plain, 0, out, 0);
  assert.equal(hex(out), '8ea2b7ca516745bfeafc49904b496089');
  a256.decryptBlock(out, 0, out, 0);
  assert.equal(hex(out), hex(plain));
});

test('the reference S-box is right, and AES agrees with OpenSSL on blocks of every byte value', () => {
  const sbox = referenceSbox();
  assert.equal(sbox[0x00], 0x63);
  assert.equal(sbox[0x53], 0xed);
  assert.equal(new Set(sbox).size, 256);
  for (let v = 0; v < 256; v++) {
    const key = randomBytes(16);
    const block = new Uint8Array(16).fill(v);
    const out = new Uint8Array(16);
    new Aes(key).encryptBlock(block, 0, out, 0);
    assert.equal(hex(out), createCipheriv('aes-128-ecb', key, null).setAutoPadding(false).update(block).toString('hex'));
  }
});

test('AES-128 and AES-256 agree with OpenSSL both ways, one block and two at once', () => {
  for (let i = 0; i < 300; i++) {
    const key = randomBytes(i % 2 ? 32 : 16);
    const mode = key.length === 16 ? 'aes-128-ecb' : 'aes-256-ecb';
    const two = randomBytes(32);
    const expect = createCipheriv(mode, key, null).setAutoPadding(false).update(two);
    const aes = new Aes(key);
    const out = new Uint8Array(32);
    aes.encryptTwo(two, 0, 16, out, 0, 16);
    assert.equal(hex(out), expect.toString('hex'));
    const one = new Uint8Array(16);
    aes.encryptBlock(two, 16, one, 0);
    assert.equal(hex(one), expect.subarray(16).toString('hex'));
    aes.decryptBlock(out, 0, one, 0);
    assert.equal(hex(one), two.subarray(0, 16).toString('hex'));
  }
  assert.throws(() => new Aes(new Uint8Array(24)));
});

test('CFB agrees with OpenSSL for every length up to a few blocks, and at random', async () => {
  for (const n of [...Array(70).keys(), 1000, 4096, 100_001]) {
    const key = randomBytes(n % 2 ? 32 : 16);
    const iv = randomBytes(16);
    const data = randomBytes(n);
    const mode = key.length === 16 ? 'aes-128-cfb' : 'aes-256-cfb';
    const expect = createCipheriv(mode, key, iv).update(data);
    const ours = cfbEncrypt(key, data, iv);
    assert.equal(hex(ours), expect.toString('hex'), `encrypt ${n}`);
    assert.equal(hex(cfbDecrypt(key, ours, iv)), hex(data), `decrypt ${n}`);
  }
  const key = randomBytes(32);
  const data = randomBytes(3 * (1 << 20) + 5);
  const expect = createCipheriv('aes-256-cfb', key, Buffer.alloc(16)).update(data);
  const seen: number[] = [];
  const encrypted = await cfbEncryptAsync(key, data, (p) => seen.push(p));
  assert.ok(Buffer.from(encrypted).equals(expect));
  assert.equal(seen.at(-1), 1);
  assert.ok(Buffer.from(await cfbDecryptAsync(key, encrypted)).equals(data));
});

test('AES Key Wrap: RFC 3394 §4.1 and §4.6, OpenSSL, and refusing altered data', () => {
  const kek128 = unhex('000102030405060708090A0B0C0D0E0F');
  const data128 = unhex('00112233445566778899AABBCCDDEEFF');
  assert.equal(hex(aesKeyWrap(kek128, data128)), '1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5');
  const kek256 = unhex('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
  const data256 = unhex('00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F');
  const wrapped = aesKeyWrap(kek256, data256);
  assert.equal(hex(wrapped), '28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21');
  assert.equal(hex(aesKeyUnwrap(kek256, wrapped)!), hex(data256));
  for (let i = 0; i < 50; i++) {
    const kek = randomBytes(i % 2 ? 32 : 16);
    const plain = randomBytes(8 * (2 + (i % 5)));
    const mode = kek.length === 16 ? 'id-aes128-wrap' : 'id-aes256-wrap';
    const iv = Buffer.from('a6a6a6a6a6a6a6a6', 'hex');
    const expect = createCipheriv(mode, kek, iv).update(plain);
    assert.equal(hex(aesKeyWrap(kek, plain)), expect.toString('hex'));
    assert.equal(hex(aesKeyUnwrap(kek, expect)!), plain.toString('hex'));
    assert.ok(createDecipheriv(mode, kek, iv).update(Buffer.from(aesKeyWrap(kek, plain))).equals(plain));
    const altered = new Uint8Array(expect);
    altered[i % altered.length] ^= 1;
    assert.equal(aesKeyUnwrap(kek, altered), null);
  }
  assert.equal(aesKeyUnwrap(kek128, new Uint8Array(16)), null);
});
