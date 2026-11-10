// The keyring: every key we know, ours (with their secret parts, still under passphrases) and
// others'. Stored as records — one per key, its packets as GnuPG would export them — in
// IndexedDB in the browser (app/store.ts) or in memory; the same records go into the file
// container (container.ts).
//
// A key imported again is merged with what we have: new user IDs, subkeys and signatures join
// it, a secret part joins its public key. Nothing is ever taken away by an import.

import { equalBytes } from './bytes.ts';
import { PgpError } from './errors.ts';
import { fingerprintHex, keyState, parseCerts, verifiedBy, writeCert } from './keys.ts';
import type { Cert, KeyPacket, KeyState, Subkey, UserId } from './keys.ts';
import { readProtection, secretHere } from './secret.ts';
import type { Signature } from './signature.ts';

/** Where a key of ours came from (Task.md §4): shown in its details. */
export type KeySource = 'hardware' | 'mouse' | 'phrase' | 'imported';

export interface KeyRecord {
  fingerprint: string;
  /** The key's packets: secret parts and our local certifications included. */
  data: Uint8Array;
  source: KeySource;
  added: number;
}

export interface KeyStore {
  load(): Promise<KeyRecord[]>;
  save(record: KeyRecord): Promise<void>;
  remove(fingerprint: string): Promise<void>;
}

export class MemoryStore implements KeyStore {
  private readonly records = new Map<string, KeyRecord>();

  async load(): Promise<KeyRecord[]> {
    return [...this.records.values()];
  }

  async save(record: KeyRecord): Promise<void> {
    this.records.set(record.fingerprint, record);
  }

  async remove(fingerprint: string): Promise<void> {
    this.records.delete(fingerprint);
  }
}

export interface Entry {
  record: KeyRecord;
  cert: Cert;
  /** Ours: we hold at least the primary key's secret. */
  secret: boolean;
}

export type ImportStatus = 'new' | 'updated' | 'unchanged' | 'refused';

export interface ImportResult {
  fingerprint: string;
  userId: string | null;
  status: ImportStatus;
  /** Why a key was refused. */
  problem?: string;
  secret: boolean;
}

const sameSig = (a: Signature, b: Signature) => equalBytes(a.body, b.body);

function mergeSigs(a: Signature[], b: Signature[]): Signature[] {
  return [...a, ...b.filter((s) => !a.some((t) => sameSig(s, t)))];
}

/** The key with a secret part from either copy: a secret that is here wins over GnuPG's mark that it is elsewhere. */
function withSecretOf(a: KeyPacket, b: KeyPacket): KeyPacket {
  if (secretHere(a) || !b.secretBody) return a;
  if (a.secretBody && !secretHere(b)) return a;
  return { ...a, tag: b.tag, secretBody: b.secretBody };
}

/** Two copies of the same key as one: everything either has. */
export function mergeCerts(a: Cert, b: Cert): Cert {
  if (!equalBytes(a.primary.fingerprint, b.primary.fingerprint)) throw new Error('merging different keys');
  const users: UserId[] = a.users.map((u) => {
    const other = b.users.find((v) => equalBytes(v.raw, u.raw));
    return other ? { ...u, sigs: mergeSigs(u.sigs, other.sigs) } : u;
  });
  for (const v of b.users) if (!a.users.some((u) => equalBytes(u.raw, v.raw))) users.push(v);
  const subkeys: Subkey[] = a.subkeys.map((s) => {
    const other = b.subkeys.find((t) => equalBytes(t.key.fingerprint, s.key.fingerprint));
    return other ? { key: withSecretOf(s.key, other.key), sigs: mergeSigs(s.sigs, other.sigs) } : s;
  });
  for (const t of b.subkeys) if (!a.subkeys.some((s) => equalBytes(s.key.fingerprint, t.key.fingerprint))) subkeys.push(t);
  return { primary: withSecretOf(a.primary, b.primary), direct: mergeSigs(a.direct, b.direct), users, subkeys };
}

const encode = (cert: Cert) => writeCert(cert, { secret: true, local: true });

/** Why a key cannot join the keyring, or null. */
function refusal(cert: Cert, now: number): string | null {
  const state = keyState(cert, now);
  if (!state.supported) return `${state.problem}: this program works with Curve25519 keys (ed25519 + cv25519) only`;
  if (!state.primaryUserId) return 'the key has no valid self-signed user ID';
  for (const k of [cert.primary, ...cert.subkeys.map((s) => s.key)]) {
    if (!k.secretBody) continue;
    try {
      readProtection(k);
    } catch (error) {
      if (error instanceof PgpError) return `its secret part: ${error.message}`;
      throw error;
    }
  }
  return null;
}

export class Keyring {
  private readonly store: KeyStore;
  private readonly entries = new Map<string, Entry>();

  constructor(store: KeyStore) {
    this.store = store;
  }

  async load(): Promise<void> {
    this.entries.clear();
    for (const record of await this.store.load()) {
      try {
        const cert = parseCerts(record.data)[0];
        this.entries.set(record.fingerprint, { record, cert, secret: !!cert.primary.secretBody });
      } catch {
        // A record that no longer reads is skipped rather than taking the keyring down.
      }
    }
  }

  get size(): number {
    return this.entries.size;
  }

  list(): Entry[] {
    return [...this.entries.values()];
  }

  get(fingerprint: string): Entry | undefined {
    return this.entries.get(fingerprint.toUpperCase());
  }

  certs(): Cert[] {
    return this.list().map((e) => e.cert);
  }

  ours(): Entry[] {
    return this.list().filter((e) => e.secret);
  }

  /** The entry holding the key (primary or subkey) with this key ID. */
  byKeyId(keyId: Uint8Array): Entry | undefined {
    return this.list().find((e) => [e.cert.primary, ...e.cert.subkeys.map((s) => s.key)].some((k) => equalBytes(k.keyId, keyId)));
  }

  state(entry: Entry, now: number): KeyState {
    return keyState(entry.cert, now);
  }

  /** Our own keys are trusted; another's when one of ours marked it verified. */
  verified(entry: Entry, now: number): boolean {
    if (entry.secret) return true;
    return verifiedBy(entry.cert, this.ours().map((e) => e.cert.primary), now).length > 0;
  }

  /** Stores a key as it is now (after a change), merged with nothing. */
  async put(cert: Cert, source: KeySource, now: number): Promise<Entry> {
    const fingerprint = fingerprintHex(cert.primary.fingerprint);
    const previous = this.entries.get(fingerprint);
    const record: KeyRecord = { fingerprint, data: encode(cert), source: previous?.record.source ?? source, added: previous?.record.added ?? now };
    await this.store.save(record);
    const entry = { record, cert, secret: !!cert.primary.secretBody };
    this.entries.set(fingerprint, entry);
    return entry;
  }

  /** Imports keys, merging each with the copy we have. */
  async importCerts(certs: Cert[], now: number, source: KeySource = 'imported'): Promise<ImportResult[]> {
    const results: ImportResult[] = [];
    for (const incoming of certs) {
      const fingerprint = fingerprintHex(incoming.primary.fingerprint);
      const problem = refusal(incoming, now);
      const userId = keyState(incoming, now).primaryUserId;
      const secret = !!incoming.primary.secretBody;
      if (problem) {
        results.push({ fingerprint, userId, status: 'refused', problem, secret });
        continue;
      }
      const existing = this.entries.get(fingerprint);
      if (!existing) {
        await this.put(incoming, source, now);
        results.push({ fingerprint, userId, status: 'new', secret });
        continue;
      }
      const merged = mergeCerts(existing.cert, incoming);
      if (equalBytes(encode(merged), existing.record.data)) {
        results.push({ fingerprint, userId, status: 'unchanged', secret });
        continue;
      }
      await this.put(merged, existing.record.source, now);
      results.push({ fingerprint, userId, status: 'updated', secret });
    }
    return results;
  }

  /** Deletes a key, or only its secret part. */
  async remove(fingerprint: string, { secretOnly = false } = {}): Promise<void> {
    const entry = this.get(fingerprint);
    if (!entry) return;
    if (secretOnly) {
      const pub = parseCerts(writeCert(entry.cert, { local: true }))[0];
      await this.put(pub, entry.record.source, entry.record.added);
      return;
    }
    await this.store.remove(entry.record.fingerprint);
    this.entries.delete(entry.record.fingerprint);
  }
}
