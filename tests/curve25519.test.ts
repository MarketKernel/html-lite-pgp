// The field, X25519 and Ed25519 against RFC 7748, RFC 8032 and OpenSSL, and the checks
// TweetNaCl leaves out.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { diffieHellman, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { D, D2, SQRT_M1, equal, fe, mul, pack, sub, ZERO, ONE } from '../src/core/crypto/field25519.ts';
import { x25519, x25519Base } from '../src/core/crypto/x25519.ts';
import { ed25519PublicKey, ed25519Sign, ed25519Verify } from '../src/core/crypto/ed25519.ts';

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const unhex = (s: string) => new Uint8Array(Buffer.from(s.replace(/\s+/g, ''), 'hex'));
const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const P = 2n ** 255n - 19n;
const feToBig = (a: Float64Array) => {
  const b = new Uint8Array(32);
  pack(b, a);
  return BigInt('0x' + hex(b.reverse()));
};

test('the constants are what their definitions give', () => {
  const inv = (x: bigint) => {
    let r = 1n, b = x % P, e = P - 2n;
    for (; e > 0n; e >>= 1n, b = (b * b) % P) if (e & 1n) r = (r * b) % P;
    return r;
  };
  assert.equal(feToBig(D), ((P - 121665n) * inv(121666n)) % P);
  assert.equal(feToBig(D2), (2n * feToBig(D)) % P);
  const i = feToBig(SQRT_M1);
  assert.equal((i * i) % P, P - 1n);
  const minusOne = fe();
  sub(minusOne, ZERO, ONE);
  const sq = fe();
  mul(sq, SQRT_M1, SQRT_M1);
  assert.ok(equal(sq, minusOne));
});

test('X25519: RFC 7748 §5.2 and §6.1', () => {
  assert.equal(
    hex(x25519(unhex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'), unhex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'))),
    'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552',
  );
  assert.equal(
    hex(x25519(unhex('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'), unhex('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'))),
    '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957',
  );
  const alice = unhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
  const bob = unhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
  assert.equal(hex(x25519Base(alice)), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
  assert.equal(hex(x25519Base(bob)), 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
  const shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';
  assert.equal(hex(x25519(alice, x25519Base(bob))), shared);
  assert.equal(hex(x25519(bob, x25519Base(alice))), shared);
});

test('X25519: RFC 7748 §5.2 iterated 1 and 1000 times', () => {
  let k = new Uint8Array(32);
  k[0] = 9;
  let u = new Uint8Array(k);
  for (let i = 1; i <= 1000; i++) {
    const next = x25519(k, u);
    u = k;
    k = next;
    if (i === 1) assert.equal(hex(k), '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079');
  }
  assert.equal(hex(k), '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51');
});

test('X25519 agrees with OpenSSL', () => {
  for (let i = 0; i < 40; i++) {
    const a = generateKeyPairSync('x25519');
    const b = generateKeyPairSync('x25519');
    const ad = new Uint8Array(Buffer.from(a.privateKey.export({ format: 'jwk' }).d!, 'base64url'));
    const bx = new Uint8Array(Buffer.from(b.publicKey.export({ format: 'jwk' }).x!, 'base64url'));
    assert.equal(b64u(x25519Base(ad)), a.publicKey.export({ format: 'jwk' }).x);
    assert.equal(hex(x25519(ad, bx)), hex(diffieHellman({ privateKey: a.privateKey, publicKey: b.publicKey })));
  }
});

test('X25519 refuses points of small order', () => {
  const k = randomBytes(32);
  const zero = new Uint8Array(32);
  const one = new Uint8Array(32);
  one[0] = 1;
  // An order-8 point (RFC 7748 errata / Wycheproof): the result is zero for every scalar.
  const order8 = unhex('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800');
  for (const u of [zero, one, order8]) assert.throws(() => x25519(k, u), /zero/);
});

const vectors = [
  {
    secret: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    public: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    message: '',
    signature: 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  },
  {
    secret: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    public: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    message: '72',
    signature: '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
  },
  {
    secret: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
    public: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    message: 'af82',
    signature: '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
  },
];

test('Ed25519: RFC 8032 §7.1', () => {
  for (const v of vectors) {
    const seed = unhex(v.secret);
    assert.equal(hex(ed25519PublicKey(seed)), v.public);
    assert.equal(hex(ed25519Sign(seed, unhex(v.message))), v.signature);
    assert.ok(ed25519Verify(unhex(v.public), unhex(v.message), unhex(v.signature)));
  }
});

test('Ed25519 agrees with OpenSSL both ways', () => {
  for (let i = 0; i < 40; i++) {
    const pair = generateKeyPairSync('ed25519');
    const jwk = pair.privateKey.export({ format: 'jwk' });
    const seed = new Uint8Array(Buffer.from(jwk.d!, 'base64url'));
    const pub = new Uint8Array(Buffer.from(jwk.x!, 'base64url'));
    assert.equal(hex(ed25519PublicKey(seed)), hex(pub));
    const message = randomBytes(i * 7);
    const ours = ed25519Sign(seed, message);
    assert.equal(hex(ours), hex(sign(null, message, pair.privateKey)));
    assert.ok(verify(null, message, pair.publicKey, ours));
    assert.ok(ed25519Verify(pub, message, ours));
    const altered = new Uint8Array(ours);
    altered[i % 64] ^= 0x10;
    assert.ok(!ed25519Verify(pub, message, altered));
    assert.ok(!ed25519Verify(pub, new Uint8Array([...message, 0]), ours));
  }
});

test('Ed25519 refuses S ≥ L, a y beyond p, and a negative zero x', () => {
  const v = vectors[0];
  const sig = unhex(v.signature);
  const pub = unhex(v.public);
  // S + L is the same scalar mod L: TweetNaCl alone would accept it.
  let carry = 0;
  const L = unhex('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010');
  const malleable = new Uint8Array(sig);
  for (let i = 0; i < 32; i++) {
    const s = malleable[32 + i] + L[i] + carry;
    malleable[32 + i] = s & 0xff;
    carry = s >> 8;
  }
  assert.ok(!ed25519Verify(pub, new Uint8Array(0), malleable));
  // y = p (non-canonical encoding of 0).
  const yIsP = new Uint8Array(32).fill(0xff);
  yIsP[0] = 0xed;
  yIsP[31] = 0x7f;
  assert.ok(!ed25519Verify(yIsP, new Uint8Array(0), sig));
  // y = 1 with the sign bit: x = 0 cannot be negative.
  const negZero = new Uint8Array(32);
  negZero[0] = 1;
  negZero[31] = 0x80;
  assert.ok(!ed25519Verify(negZero, new Uint8Array(0), sig));
  assert.ok(!ed25519Verify(pub, new Uint8Array(0), sig.subarray(0, 63)));
});
