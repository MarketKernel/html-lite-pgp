// Rough speeds of the primitives, for README and for the decisions in Task.md (scrypt's
// parameters, the AES target). `node --run bench`.
import { cfbDecrypt, cfbEncrypt } from '../src/core/crypto/cfb.ts';
import { scrypt } from '../src/core/crypto/scrypt.ts';
import { sha1 } from '../src/core/crypto/sha1.ts';
import { sha256 } from '../src/core/crypto/sha256.ts';
import { sha512 } from '../src/core/crypto/sha512.ts';

async function time(what: string, run: () => unknown, bytes = 0): Promise<void> {
  const start = performance.now();
  await run();
  const ms = performance.now() - start;
  console.log(`${what.padEnd(34)} ${ms.toFixed(0).padStart(6)} ms${bytes ? `  ${(bytes / 1048576 / (ms / 1000)).toFixed(1)} MiB/s` : ''}`);
}

const data = new Uint8Array(16 * 1048576);
await time('SHA-1, 16 MiB', () => sha1(data), data.length);
await time('SHA-256, 16 MiB', () => sha256(data), data.length);
await time('SHA-512, 16 MiB', () => sha512(data), data.length);
const key = new Uint8Array(32);
const eight = data.subarray(0, 8 * 1048576);
const encrypted = cfbEncrypt(key, eight);
await time('AES-256-CFB encrypt, 8 MiB', () => cfbEncrypt(key, eight), eight.length);
await time('AES-256-CFB decrypt, 8 MiB', () => cfbDecrypt(key, encrypted), eight.length);
await time('scrypt N=2^18 r=8 p=1 (256 MiB)', () => scrypt(new Uint8Array(8), new Uint8Array(8), { N: 2 ** 18, r: 8, p: 1, length: 64 }));
