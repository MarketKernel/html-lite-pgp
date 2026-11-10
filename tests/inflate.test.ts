// Inflate against zlib's own deflate: every level and strategy, broken streams, and bombs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { constants, deflateRawSync, deflateSync } from 'node:zlib';
import { InflateError, inflateRaw, inflateZlib } from '../src/core/inflate.ts';

const MB = 1 << 20;

function samples(): Uint8Array[] {
  const text = new TextEncoder().encode('Съешь же ещё этих мягких французских булок, да выпей чаю. The quick brown fox. '.repeat(500));
  const mixed = new Uint8Array(200_000);
  for (let i = 0; i < mixed.length; i++) mixed[i] = i % 1000 < 500 ? i & 7 : (i * 2654435761) >>> 24;
  return [new Uint8Array(0), Uint8Array.of(42), text, randomBytes(70_000), new Uint8Array(300_000), mixed];
}

test('raw DEFLATE from zlib at every level and strategy', () => {
  const strategies = [constants.Z_DEFAULT_STRATEGY, constants.Z_FILTERED, constants.Z_HUFFMAN_ONLY, constants.Z_RLE, constants.Z_FIXED];
  for (const data of samples()) {
    for (let level = 0; level <= 9; level++) {
      for (const strategy of strategies) {
        const packed = deflateRawSync(data, { level, strategy });
        assert.ok(Buffer.from(inflateRaw(packed, 10 * MB)).equals(Buffer.from(data)), `level ${level} strategy ${strategy} length ${data.length}`);
      }
    }
  }
});

test('zlib streams, with their checksum checked', () => {
  for (const data of samples()) {
    const packed = deflateSync(data, { level: 6 });
    assert.ok(Buffer.from(inflateZlib(packed, 10 * MB)).equals(Buffer.from(data)));
  }
  const packed = new Uint8Array(deflateSync(new TextEncoder().encode('hello hello hello')));
  packed[packed.length - 1] ^= 1;
  assert.throws(() => inflateZlib(packed, MB), /checksum/);
  assert.throws(() => inflateZlib(Uint8Array.of(0x78, 0x9c), MB), InflateError);
  assert.throws(() => inflateZlib(new Uint8Array(deflateRawSync(Uint8Array.of(1, 2, 3))), MB), InflateError);
});

test('a bomb stops at the limit', () => {
  const bomb = deflateRawSync(new Uint8Array(50 * MB), { level: 9 });
  assert.ok(bomb.length < 100_000);
  assert.throws(() => inflateRaw(bomb, 4 * MB), /limit/);
  assert.equal(inflateRaw(bomb, 50 * MB).length, 50 * MB);
});

test('broken streams end in InflateError, never in anything else, and never hang', () => {
  const sources = samples().filter((d) => d.length > 0);
  for (let i = 0; i < 3000; i++) {
    const data = sources[i % sources.length].subarray(0, 5000);
    const packed = new Uint8Array(deflateRawSync(data, { level: 1 + (i % 9) }));
    const broken = i % 3 === 0 ? packed.subarray(0, Math.floor((packed.length * (i % 97)) / 97)) : packed;
    if (i % 3 !== 0) for (let k = 0; k <= i % 4; k++) broken[(i * 7919 + k * 104729) % broken.length] ^= 1 << (i % 8);
    try {
      inflateRaw(broken, MB);
    } catch (error) {
      assert.ok(error instanceof InflateError, `case ${i}: ${(error as Error).stack}`);
    }
  }
});
