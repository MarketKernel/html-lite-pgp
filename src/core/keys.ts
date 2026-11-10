// Keys: the key packets (RFC 4880 §5.5), how a transferable key is laid out (§11.1), which of
// its signatures hold, and what follows from them — is the key valid, until when, which subkey
// encrypts, which keys sign. And making keys and the signatures that change them.
//
// The profile (Task.md §7.1): a v4 EdDSA Ed25519 primary key and v4 ECDH Cv25519 subkeys.
// Other keys are read far enough to say what they are and to compute their fingerprints, then
// refused as 'unsupported'.

import { OID_CV25519, OID_ED25519, PUBKEY, HASH, SYM, kdfAllowed, algorithmName } from './algorithms.ts';
import { Reader, Writer, equalBytes, utf8 } from './bytes.ts';
import { ed25519PublicKey } from './crypto/ed25519.ts';
import { sha1 } from './crypto/sha1.ts';
import { concat } from './crypto/util.ts';
import { PgpError, malformed, unsupported } from './errors.ts';
import { readMpi, writeMpi } from './mpi.ts';
import { TAG, readPackets, writePacket } from './packets.ts';
import type { Packet } from './packets.ts';
import {
  KEY_FLAG, SIG, SUB, created, embedded, exportable, isPrimaryUserId, issuerFingerprint, issuerKeyId, keyExpires, keyFlags,
  makeSignature, readSignature, revocationReason, signatureExpires, subpacket, supported, u32Bytes, verifySignature,
} from './signature.ts';
import type { Signature, Signer } from './signature.ts';

export interface KeyPacket {
  tag: number;
  version: number;
  created: number;
  algorithm: number;
  /** The public part of the packet body: what the fingerprint and key signatures hash. */
  publicBody: Uint8Array;
  /** What follows it in a secret key packet. */
  secretBody: Uint8Array | null;
  fingerprint: Uint8Array;
  keyId: Uint8Array;
  curve: 'ed25519' | 'cv25519' | null;
  /** The 32-byte public key, without OpenPGP's 0x40 prefix. */
  point: Uint8Array | null;
  kdf: { hash: number; cipher: number } | null;
}

const isSecretTag = (tag: number): boolean => tag === TAG.SECRET_KEY || tag === TAG.SECRET_SUBKEY;

/** How many MPIs the public part of other algorithms holds — enough to find where it ends. */
const PUBLIC_MPIS: Record<number, number> = { [PUBKEY.RSA]: 2, [PUBKEY.RSA_E]: 2, [PUBKEY.RSA_S]: 2, [PUBKEY.DSA]: 4, [PUBKEY.ELGAMAL]: 3 };

export function readKeyPacket(packet: Packet): KeyPacket {
  const r = new Reader(packet.body);
  const version = r.byte('the key version');
  if (version !== 4) {
    const empty = new Uint8Array(0);
    return { tag: packet.tag, version, created: 0, algorithm: -1, publicBody: packet.body, secretBody: null, fingerprint: empty, keyId: empty, curve: null, point: null, kdf: null };
  }
  const time = r.u32('the key creation time');
  const algorithm = r.byte('the key algorithm');
  let curve: KeyPacket['curve'] = null;
  let point: Uint8Array | null = null;
  let kdf: KeyPacket['kdf'] = null;
  if (algorithm === PUBKEY.EDDSA || algorithm === PUBKEY.ECDH || algorithm === PUBKEY.ECDSA) {
    const oidLength = r.byte('a curve OID');
    if (oidLength === 0 || oidLength === 0xff) throw malformed('a reserved curve OID length');
    const oid = r.bytes(oidLength, 'a curve OID');
    const mpi = readMpi(r);
    if (algorithm === PUBKEY.ECDH) {
      const n = r.byte('the KDF parameters');
      const params = r.bytes(n, 'the KDF parameters');
      if (n === 3 && params[0] === 1) kdf = { hash: params[1], cipher: params[2] };
    }
    const native = mpi.length === 33 && mpi[0] === 0x40 ? mpi.subarray(1) : null;
    if (algorithm === PUBKEY.EDDSA && equalBytes(oid, OID_ED25519) && native) curve = 'ed25519';
    if (algorithm === PUBKEY.ECDH && equalBytes(oid, OID_CV25519) && native) curve = 'cv25519';
    if (curve) point = new Uint8Array(native!);
  } else if (PUBLIC_MPIS[algorithm]) {
    for (let i = 0; i < PUBLIC_MPIS[algorithm]; i++) readMpi(r);
  } else if (isSecretTag(packet.tag)) {
    throw unsupported(`a secret key of ${algorithmName(algorithm)}`);
  } else {
    r.rest();
  }
  const publicBody = packet.body.subarray(0, r.at);
  const secretBody = isSecretTag(packet.tag) ? packet.body.subarray(r.at) : (r.done('the public key'), null);
  const fingerprint = sha1(Uint8Array.of(0x99, publicBody.length >> 8, publicBody.length & 0xff), publicBody);
  return { tag: packet.tag, version, created: time, algorithm, publicBody, secretBody, fingerprint, keyId: fingerprint.subarray(12), curve, point, kdf };
}

/** What a key signature hashes for a key: 0x99, the length, the public part. */
export const keyData = (k: KeyPacket): Uint8Array => concat(Uint8Array.of(0x99, k.publicBody.length >> 8, k.publicBody.length & 0xff), k.publicBody);

/** What a certification hashes for a user ID. */
export const userIdData = (uid: Uint8Array): Uint8Array => concat(Uint8Array.of(0xb4), u32Bytes(uid.length), uid);

export interface UserId {
  /** The user ID's bytes; `text` is them as UTF-8 (or with replacement characters, if not). */
  raw: Uint8Array;
  text: string;
  sigs: Signature[];
}

export interface Subkey {
  key: KeyPacket;
  sigs: Signature[];
}

/** A transferable public or secret key: the primary key and everything that came with it. */
export interface Cert {
  primary: KeyPacket;
  /** Signatures right on the primary key: direct-key signatures and revocations. */
  direct: Signature[];
  users: UserId[];
  subkeys: Subkey[];
}

function readSig(packet: Packet): Signature | null {
  try {
    return readSignature(packet.body);
  } catch (error) {
    // A damaged signature from someone else should not keep the key out: it is dropped, as
    // GnuPG drops it. A damaged self-signature means the key has none, and is caught later.
    if (error instanceof PgpError) return null;
    throw error;
  }
}

/** The keys in a sequence of packets (a keyring, an export of one or more keys). */
export function readCerts(packets: Packet[]): Cert[] {
  const certs: Cert[] = [];
  let cert: Cert | null = null;
  let sigs: Signature[] | null = null;
  for (const p of packets) {
    switch (p.tag) {
      case TAG.PUBLIC_KEY:
      case TAG.SECRET_KEY:
        cert = { primary: readKeyPacket(p), direct: [], users: [], subkeys: [] };
        certs.push(cert);
        sigs = cert.direct;
        break;
      case TAG.USER_ID:
        if (!cert) throw malformed('a user ID before any key');
        if (p.body.length > 4096) throw new PgpError('too-large', 'a user ID longer than 4096 bytes');
        cert.users.push({ raw: p.body, text: new TextDecoder().decode(p.body), sigs: [] });
        sigs = cert.users[cert.users.length - 1].sigs;
        break;
      case TAG.USER_ATTRIBUTE:
        // Photo IDs: not shown, not kept; their signatures are dropped with them.
        if (!cert) throw malformed('a user attribute before any key');
        sigs = null;
        break;
      case TAG.PUBLIC_SUBKEY:
      case TAG.SECRET_SUBKEY:
        if (!cert) throw malformed('a subkey before any key');
        cert.subkeys.push({ key: readKeyPacket(p), sigs: [] });
        sigs = cert.subkeys[cert.subkeys.length - 1].sigs;
        break;
      case TAG.SIGNATURE: {
        if (!cert) throw new PgpError('unexpected', 'a signature, not a key');
        const sig = readSig(p);
        if (sig && sigs) sigs.push(sig);
        break;
      }
      case TAG.TRUST:
      case TAG.MARKER:
      case TAG.PADDING:
        break;
      default:
        throw new PgpError('unexpected', 'this is not a key');
    }
  }
  return certs;
}

/** The time a signature may be ahead of our clock and still count (clocks drift). */
export const CLOCK_SKEW = 600;

/** Made by `key`, as far as its issuer subpackets say. */
function issuedBy(sig: Signature, key: KeyPacket): boolean {
  const fpr = issuerFingerprint(sig);
  if (fpr) return equalBytes(fpr, key.fingerprint);
  const id = issuerKeyId(sig);
  return !!id && equalBytes(id, key.keyId);
}

/** Valid at `now`: made after the key, not in the future, not expired. */
function inTime(sig: Signature, key: KeyPacket, now: number): boolean {
  const c = created(sig);
  if (c === null || c < key.created || c > now + CLOCK_SKEW) return false;
  const e = signatureExpires(sig);
  return !e || c + e > now;
}

/** `sig` is a good signature by `signer` (an Ed25519 key) over `data`, valid at `now`. */
export function goodBy(sig: Signature, signer: KeyPacket, data: Uint8Array[], now: number): boolean {
  if (signer.curve !== 'ed25519' || !signer.point || !issuedBy(sig, signer) || !inTime(sig, signer, now)) return false;
  try {
    return verifySignature(sig, signer.point, data);
  } catch (error) {
    if (error instanceof PgpError) return false;
    throw error;
  }
}

const newest = (sigs: Signature[]): Signature | null => sigs.reduce<Signature | null>((best, s) => (!best || (created(s) ?? 0) > (created(best) ?? 0) ? s : best), null);

export interface Revocation {
  time: number;
  code: number;
  text: string;
}

export interface SubkeyState {
  key: KeyPacket;
  binding: Signature | null;
  flags: number;
  expires: number | null;
  expired: boolean;
  revoked: Revocation | null;
  /** Bound, not revoked, in the profile for what its flags say — expired or not. */
  usable: boolean;
}

export interface KeyState {
  cert: Cert;
  fingerprint: Uint8Array;
  /** Within the profile: an Ed25519 primary key. If not, `problem` says what it is. */
  supported: boolean;
  problem: string | null;
  primaryUserId: string | null;
  userIds: { text: string; revoked: boolean; valid: boolean }[];
  created: number;
  /** When the key expires (seconds since 1970), or null: never. */
  expires: number | null;
  expired: boolean;
  revoked: Revocation | null;
  /** A usable key: supported, self-signed, not expired, not revoked. */
  valid: boolean;
  flags: number;
  /** The subkey new messages are encrypted to, or null. */
  encryption: KeyPacket | null;
  /** Keys whose signatures count as this key's: the primary key and signing subkeys (expired ones too: their old signatures still count). */
  signing: KeyPacket[];
  subkeys: SubkeyState[];
  /** The self-signature that says the key's flags, expiry and preferences. */
  selfSignature: Signature | null;
}

function revocation(sigs: Signature[]): Revocation | null {
  const sig = newest(sigs);
  if (!sig) return null;
  const reason = revocationReason(sig);
  return { time: created(sig) ?? 0, code: reason?.code ?? 0, text: reason?.text ?? '' };
}

/** Everything that follows from the key's signatures, at time `now` (seconds since 1970). */
export function keyState(cert: Cert, now: number): KeyState {
  const p = cert.primary;
  const base: KeyState = {
    cert, fingerprint: p.fingerprint, supported: false, problem: null, primaryUserId: null, userIds: [], created: p.created,
    expires: null, expired: false, revoked: null, valid: false, flags: 0, encryption: null, signing: [], subkeys: [], selfSignature: null,
  };
  if (p.version !== 4) return { ...base, problem: `a version ${p.version} key` };
  if (p.curve !== 'ed25519') return { ...base, problem: `${algorithmName(p.algorithm)}${p.algorithm === PUBKEY.EDDSA || p.algorithm === PUBKEY.ECDSA ? ' on another curve' : ''}` };
  const primaryData = keyData(p);
  const self = (sig: Signature, data: Uint8Array[]) => goodBy(sig, p, data, now);

  const revocations = cert.direct.filter((s) => s.type === SIG.KEY_REVOCATION && self(s, [primaryData]));
  const directSig = newest(cert.direct.filter((s) => s.type === SIG.DIRECT_KEY && self(s, [primaryData])));

  const users = cert.users.map((u) => {
    const data = [primaryData, userIdData(u.raw)];
    const certs = u.sigs.filter((s) => s.type >= SIG.CERT_GENERIC && s.type <= SIG.CERT_POSITIVE && self(s, data));
    const revoked = u.sigs.some((s) => s.type === SIG.CERT_REVOCATION && self(s, data));
    return { u, latest: newest(certs), revoked };
  });
  const live = users.filter((x) => x.latest && !x.revoked);
  const chosen = live.find((x) => isPrimaryUserId(x.latest!)) ?? live[0] ?? null;
  const candidates = [chosen?.latest ?? null, directSig].filter((s): s is Signature => !!s);
  const selfSignature = newest(candidates);
  const flags = (selfSignature && keyFlags(selfSignature)) ?? KEY_FLAG.CERTIFY | KEY_FLAG.SIGN;
  const validFor = selfSignature ? keyExpires(selfSignature) : null;
  const expires = validFor ? p.created + validFor : null;
  const expired = expires !== null && expires <= now;
  const revoked = revocation(revocations);
  const valid = !!selfSignature && !!chosen && !expired && !revoked;

  const subkeys: SubkeyState[] = cert.subkeys.map(({ key, sigs }) => {
    const none: SubkeyState = { key, binding: null, flags: 0, expires: null, expired: false, revoked: null, usable: false };
    if (key.version !== 4) return none;
    const data = [primaryData, keyData(key)];
    const binding = newest(sigs.filter((s) => s.type === SIG.SUBKEY_BINDING && self(s, data)));
    if (!binding) return none;
    const subFlags = keyFlags(binding) ?? (key.algorithm === PUBKEY.ECDH ? KEY_FLAG.ENCRYPT_COMMS | KEY_FLAG.ENCRYPT_STORAGE : KEY_FLAG.SIGN);
    const subFor = keyExpires(binding);
    const subExpires = subFor ? key.created + subFor : null;
    const subRevoked = revocation(sigs.filter((s) => s.type === SIG.SUBKEY_REVOCATION && self(s, data)));
    const subExpired = subExpires !== null && subExpires <= now;
    let usable = !subRevoked;
    if (subFlags & KEY_FLAG.SIGN) {
      // A signing subkey must sign back: without that, anyone could attach someone else's key.
      usable &&= key.curve === 'ed25519' && embedded(binding).some((e) => e.type === SIG.PRIMARY_BINDING && goodBy(e, key, data, now));
    } else if (subFlags & (KEY_FLAG.ENCRYPT_COMMS | KEY_FLAG.ENCRYPT_STORAGE)) {
      usable &&= key.curve === 'cv25519' && !!key.kdf && kdfAllowed(key.kdf.hash, key.kdf.cipher);
    } else {
      usable = false;
    }
    return { key, binding, flags: subFlags, expires: subExpires, expired: subExpired, revoked: subRevoked, usable };
  });

  const encryption = newest0(subkeys.filter((s) => s.usable && !s.expired && s.flags & (KEY_FLAG.ENCRYPT_COMMS | KEY_FLAG.ENCRYPT_STORAGE)).map((s) => s.key));
  const signing = [...(flags & KEY_FLAG.SIGN ? [p] : []), ...subkeys.filter((s) => s.usable && s.flags & KEY_FLAG.SIGN).map((s) => s.key)];

  return {
    ...base,
    supported: true,
    primaryUserId: chosen ? chosen.u.text : null,
    userIds: users.map((x) => ({ text: x.u.text, revoked: x.revoked, valid: !!x.latest })),
    expires,
    expired,
    revoked,
    valid,
    flags,
    encryption: valid ? encryption : null,
    signing,
    subkeys,
    selfSignature,
  };
}

function newest0(keys: KeyPacket[]): KeyPacket | null {
  return keys.reduce<KeyPacket | null>((best, k) => (!best || k.created > best.created ? k : best), null);
}

/** Reads keys from binary packets; one or several. */
export function parseCerts(data: Uint8Array): Cert[] {
  const certs = readCerts(readPackets(data));
  if (!certs.length) throw new PgpError('unexpected', 'there is no key here');
  return certs;
}

const encodeSig = (s: Signature) => writePacket(TAG.SIGNATURE, s.body);

/**
 * The key as packets again. `secret`: keep the secret parts (a backup); otherwise public
 * packets only, and without non-exportable signatures (our "verified" marks stay ours).
 */
export function writeCert(cert: Cert, { secret = false, local = false }: { secret?: boolean; local?: boolean } = {}): Uint8Array {
  const out: Uint8Array[] = [];
  const keyPacket = (k: KeyPacket, primary: boolean) => {
    if (secret && k.secretBody) return writePacket(primary ? TAG.SECRET_KEY : TAG.SECRET_SUBKEY, concat(k.publicBody, k.secretBody));
    return writePacket(primary ? TAG.PUBLIC_KEY : TAG.PUBLIC_SUBKEY, k.publicBody);
  };
  const keep = (s: Signature) => local || secret || s.version !== 4 || exportable(s);
  out.push(keyPacket(cert.primary, true));
  for (const s of cert.direct) if (keep(s)) out.push(encodeSig(s));
  for (const u of cert.users) {
    out.push(writePacket(TAG.USER_ID, u.raw));
    for (const s of u.sigs) if (keep(s)) out.push(encodeSig(s));
  }
  for (const sk of cert.subkeys) {
    out.push(keyPacket(sk.key, false));
    for (const s of sk.sigs) if (keep(s)) out.push(encodeSig(s));
  }
  return concat(...out);
}

// ---- Making keys -------------------------------------------------------------------------

/** The public key packet body of an Ed25519 or Cv25519 key. */
export function publicKeyBody(kind: 'ed25519' | 'cv25519', time: number, point: Uint8Array): Uint8Array {
  const w = new Writer().byte(4).u32(time);
  if (kind === 'ed25519') {
    w.byte(PUBKEY.EDDSA).byte(OID_ED25519.length).bytes(OID_ED25519);
    writeMpi(w, concat(Uint8Array.of(0x40), point));
  } else {
    w.byte(PUBKEY.ECDH).byte(OID_CV25519.length).bytes(OID_CV25519);
    writeMpi(w, concat(Uint8Array.of(0x40), point));
    w.byte(3).byte(1).byte(HASH.SHA256).byte(SYM.AES128);
  }
  return w.finish();
}

/** What every self-signature of ours says about the key (Task.md §7.1). */
function primaryPreferences(expiresIn: number): Uint8Array[] {
  return [
    subpacket(SUB.KEY_FLAGS, Uint8Array.of(KEY_FLAG.CERTIFY | KEY_FLAG.SIGN)),
    ...(expiresIn ? [subpacket(SUB.KEY_EXPIRES, u32Bytes(expiresIn))] : []),
    subpacket(SUB.PREF_SYMMETRIC, Uint8Array.of(SYM.AES256)),
    subpacket(SUB.PREF_HASH, Uint8Array.of(HASH.SHA512, HASH.SHA256)),
    subpacket(SUB.PREF_COMPRESSION, Uint8Array.of(0)),
    // MDC only: announcing AEAD would make GnuPG 2.4+ answer in OCB, which we do not read.
    subpacket(SUB.FEATURES, Uint8Array.of(0x01)),
    subpacket(SUB.KEY_SERVER_PREFS, Uint8Array.of(0x80)),
    subpacket(SUB.PRIMARY_USER_ID, Uint8Array.of(1)),
  ];
}

const subkeyPreferences = (expiresIn: number): Uint8Array[] => [
  subpacket(SUB.KEY_FLAGS, Uint8Array.of(KEY_FLAG.ENCRYPT_COMMS | KEY_FLAG.ENCRYPT_STORAGE)),
  ...(expiresIn ? [subpacket(SUB.KEY_EXPIRES, u32Bytes(expiresIn))] : []),
];

export interface NewKey {
  /** The Ed25519 seed of the primary key. */
  seed: Uint8Array;
  /** The Cv25519 public point of the encryption subkey (its secret stays with the caller). */
  subkeyPoint: Uint8Array;
  userId: string;
  /** Creation time of both keys: part of their fingerprints. */
  created: number;
  /** Seconds the key is valid after `created`; 0: no expiry. */
  expiresIn: number;
  /** When the self-signatures are made (normally now). */
  signedAt: number;
}

/** A new public key in the profile: the primary key, the user ID, the subkey, their self-signatures. */
export function makeCert(spec: NewKey): Cert {
  if (!spec.userId.trim()) throw new PgpError('unexpected', 'a key needs a name or an address');
  const primaryBody = publicKeyBody('ed25519', spec.created, ed25519PublicKey(spec.seed));
  const primary = readKeyPacket({ tag: TAG.PUBLIC_KEY, body: primaryBody, raw: writePacket(TAG.PUBLIC_KEY, primaryBody) });
  const subBody = publicKeyBody('cv25519', spec.created, spec.subkeyPoint);
  const sub = readKeyPacket({ tag: TAG.PUBLIC_SUBKEY, body: subBody, raw: writePacket(TAG.PUBLIC_SUBKEY, subBody) });
  const signer: Signer = { seed: spec.seed, fingerprint: primary.fingerprint };
  const uid = utf8(spec.userId);
  const certification = makeSignature(SIG.CERT_POSITIVE, signer, [keyData(primary), userIdData(uid)], spec.signedAt, primaryPreferences(spec.expiresIn));
  const binding = makeSignature(SIG.SUBKEY_BINDING, signer, [keyData(primary), keyData(sub)], spec.signedAt, subkeyPreferences(spec.expiresIn));
  return {
    primary,
    direct: [],
    users: [{ raw: uid, text: spec.userId, sigs: [readSignature(certification)] }],
    subkeys: [{ key: sub, sigs: [readSignature(binding)] }],
  };
}

/** The signer for a primary key whose Ed25519 seed we hold; checks the seed is that key's. */
export function signerFor(primary: KeyPacket, seed: Uint8Array): Signer {
  if (!primary.point || !equalBytes(ed25519PublicKey(seed), primary.point)) throw new PgpError('integrity', 'the secret key does not match the public key');
  return { seed, fingerprint: primary.fingerprint };
}

/**
 * The key with a new expiry: new self-signatures for every valid user ID and the encryption
 * subkeys, saying the same as before but for the expiry. Nothing is removed — GnuPG takes the
 * newest self-signature, and others' certifications stay.
 */
export function withExpiry(cert: Cert, seed: Uint8Array, expiresIn: number, now: number): Cert {
  const state = keyState(cert, now);
  if (!state.supported) throw unsupported('this key');
  const signer = signerFor(cert.primary, seed);
  const primaryData = keyData(cert.primary);
  const users = cert.users.map((u) => {
    const ok = state.userIds.find((x) => x.text === u.text);
    if (!ok?.valid || ok.revoked) return u;
    const sig = makeSignature(SIG.CERT_POSITIVE, signer, [primaryData, userIdData(u.raw)], now, primaryPreferences(expiresIn).filter((_, i, all) => u.text === state.primaryUserId || all[i][1] !== SUB.PRIMARY_USER_ID));
    return { ...u, sigs: [...u.sigs, readSignature(sig)] };
  });
  const subkeys = cert.subkeys.map((s) => {
    const st = state.subkeys.find((x) => x.key === s.key);
    if (!st?.binding || st.revoked || !(st.flags & (KEY_FLAG.ENCRYPT_COMMS | KEY_FLAG.ENCRYPT_STORAGE))) return s;
    const subFor = expiresIn ? cert.primary.created + expiresIn - s.key.created : 0;
    const sig = makeSignature(SIG.SUBKEY_BINDING, signer, [primaryData, keyData(s.key)], now, subkeyPreferences(Math.max(0, subFor)));
    return { ...s, sigs: [...s.sigs, readSignature(sig)] };
  });
  return { ...cert, users, subkeys };
}

export const REASON = { NONE: 0, SUPERSEDED: 1, COMPROMISED: 2, RETIRED: 3 } as const;

/** A key revocation signature (0x20) — the key itself revoked, or kept aside as a certificate. */
export function revocationSignature(cert: Cert, seed: Uint8Array, code: number, text: string, now: number): Signature {
  const signer = signerFor(cert.primary, seed);
  const body = makeSignature(SIG.KEY_REVOCATION, signer, [keyData(cert.primary)], now, [subpacket(SUB.REASON, concat(Uint8Array.of(code), utf8(text)))]);
  return readSignature(body);
}

/** Adds a revocation signature to the key, after checking that it is the key's own. */
export function applyRevocation(cert: Cert, sig: Signature, now: number): Cert {
  if (sig.type !== SIG.KEY_REVOCATION || !goodBy(sig, cert.primary, [keyData(cert.primary)], now)) {
    throw new PgpError('integrity', 'this revocation was not made by this key');
  }
  if (cert.direct.some((s) => equalBytes(s.body, sig.body))) return cert;
  return { ...cert, direct: [...cert.direct, sig] };
}

/**
 * "I checked this key's fingerprint": a non-exportable certification of the user ID by our
 * key, as `gpg --lsign-key` makes it. It never leaves the keyring with an export.
 */
export function markVerified(target: Cert, userId: string, ourPrimary: KeyPacket, ourSeed: Uint8Array, now: number): Cert {
  const signer = signerFor(ourPrimary, ourSeed);
  const users = target.users.map((u) => {
    if (u.text !== userId) return u;
    const body = makeSignature(SIG.CERT_GENERIC, signer, [keyData(target.primary), userIdData(u.raw)], now, [subpacket(SUB.EXPORTABLE, Uint8Array.of(0), true)]);
    return { ...u, sigs: [...u.sigs, readSignature(body)] };
  });
  return { ...target, users };
}

/** The user IDs of `target` that one of `ours` certified (and did not revoke). */
export function verifiedBy(target: Cert, ours: KeyPacket[], now: number): string[] {
  const out: string[] = [];
  const primaryData = keyData(target.primary);
  for (const u of target.users) {
    const data = [primaryData, userIdData(u.raw)];
    const good = u.sigs.some((s) => s.type >= SIG.CERT_GENERIC && s.type <= SIG.CERT_POSITIVE && ours.some((k) => !equalBytes(k.fingerprint, target.primary.fingerprint) && goodBy(s, k, data, now)));
    const revoked = u.sigs.some((s) => s.type === SIG.CERT_REVOCATION && ours.some((k) => goodBy(s, k, data, now)));
    if (good && !revoked) out.push(u.text);
  }
  return out;
}

export const fingerprintHex = (fpr: Uint8Array): string => Array.from(fpr, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();

/** The fingerprint in groups of four, as GnuPG prints it. */
export const formatFingerprint = (fpr: Uint8Array): string =>
  fingerprintHex(fpr)
    .replace(/(.{4})/g, '$1 ')
    .trim()
    .replace(/^((?:\S{4} ){4}\S{4}) /, '$1  ');

