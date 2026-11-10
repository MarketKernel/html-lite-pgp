// WebAuthn, for unlocking and keeping keys with a passkey or a security key (Task.md §5.2–5.3)
// — the one module that calls navigator.credentials (tests/policy.test.ts checks), and only in
// the PWA: WebAuthn needs a secure origin with a domain, which a file opened from disk has not.
//
// WebAuthn serves here for two of its extensions, not to sign in anywhere. prf (CTAP's
// hmac-secret) gives 32 bytes bound to the credential and to our salt, after the device checked
// the user (fingerprint, face, PIN); src/core/device.ts derives from them the key that wraps a
// secret. largeBlob keeps a few hundred bytes on the device itself. There is no server: the
// challenge is random and nobody checks the assertion's signature.
//
// Also here: the records of what a device keeps for us (this origin's IndexedDB, a database of
// their own beside the keys), and the check that the app is alone on its origin — every page of
// an origin shares its IndexedDB and may ask WebAuthn for the same credentials.

/** Hosts where one origin holds the pages of many projects (user.github.io/project): not alone there. */
const SHARED_HOSTS = ['github.io', 'gitlab.io', 'codeberg.page'];

export type Where = 'ok' | 'insecure' | 'path' | 'host';

/** Whether the app may use devices here: a secure context, at the root of its origin, not on a shared host. */
export function aloneOnOrigin(): Where {
  if (!isSecureContext) return 'insecure';
  if (new URL('./', location.href).pathname !== '/') return 'path';
  const host = location.hostname.toLowerCase();
  if (SHARED_HOSTS.some((s) => host === s || host.endsWith(`.${s}`))) return 'host';
  return 'ok';
}

export const webAuthnHere = (): boolean => typeof PublicKeyCredential === 'function' && !!navigator.credentials;

type Capabilities = Record<string, boolean>;
type Pkc = typeof PublicKeyCredential & { getClientCapabilities?: () => Promise<Capabilities> };

/** What the browser says it can do: true, false, or null when it does not say (then only trying tells). */
export async function deviceSupport(): Promise<{ prf: boolean | null; largeBlob: boolean | null }> {
  try {
    const caps = await (PublicKeyCredential as Pkc).getClientCapabilities?.();
    if (!caps) return { prf: null, largeBlob: null };
    return { prf: caps['extension:prf'] ?? null, largeBlob: caps['extension:largeBlob'] ?? null };
  } catch {
    return { prf: null, largeBlob: null };
  }
}

/** The user closed the browser's prompt, it timed out, or no device holds the credential. */
export class DeviceCancelled extends Error {}

const TIMEOUT = 120_000;
/** Ed25519, P-256, RSA: whichever the device has. */
const ALGORITHMS = [-8, -7, -257].map((alg) => ({ type: 'public-key' as const, alg }));

const bytes = (b: ArrayBuffer | ArrayBufferView | undefined | null): Uint8Array | null =>
  !b ? null : b instanceof ArrayBuffer ? new Uint8Array(b.slice(0)) : new Uint8Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));

function failed(error: unknown): never {
  if (error instanceof DOMException && (error.name === 'NotAllowedError' || error.name === 'AbortError')) throw new DeviceCancelled(error.message);
  throw error;
}

interface Extensions {
  prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } };
  largeBlob?: { supported?: boolean; blob?: ArrayBuffer; written?: boolean };
}

export interface Created {
  credential: Uint8Array;
  /** The device can do PRF; its result, if it gave one already. */
  prfEnabled: boolean;
  prf: Uint8Array | null;
  blobSupported: boolean;
}

/** A new credential for this host: a discoverable one when it is to keep a largeBlob. */
export async function createCredential(o: { label: string; userId: Uint8Array; challenge: Uint8Array; salt: Uint8Array; blob: boolean }): Promise<Created> {
  let credential: PublicKeyCredential;
  try {
    credential = (await navigator.credentials.create({
      publicKey: {
        rp: { id: location.hostname, name: 'Simple PGP' },
        user: { id: o.userId as BufferSource, name: o.label, displayName: o.label },
        challenge: o.challenge as BufferSource,
        pubKeyCredParams: ALGORITHMS,
        timeout: TIMEOUT,
        attestation: 'none',
        authenticatorSelection: { userVerification: 'required', residentKey: o.blob ? 'required' : 'preferred', requireResidentKey: o.blob },
        extensions: { prf: { eval: { first: o.salt as BufferSource } }, ...(o.blob ? { largeBlob: { support: 'required' } } : {}) } as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential;
  } catch (error) {
    failed(error);
  }
  const ext = credential.getClientExtensionResults() as Extensions;
  return {
    credential: bytes(credential.rawId)!,
    prfEnabled: ext.prf?.enabled === true || !!ext.prf?.results?.first,
    prf: bytes(ext.prf?.results?.first),
    blobSupported: ext.largeBlob?.supported === true,
  };
}

export interface Asserted {
  credential: Uint8Array;
  prf: Uint8Array | null;
  blob: Uint8Array | null;
  written: boolean;
}

/**
 * A touch: the device checks the user and answers for the credential (or, with none given, for
 * one the user picks among this host's passkeys) — the PRF of our salt, and its largeBlob read
 * or written.
 */
export async function touch(o: { credential: Uint8Array | null; challenge: Uint8Array; salt?: Uint8Array; read?: boolean; write?: Uint8Array }): Promise<Asserted> {
  const extensions: Record<string, unknown> = {};
  if (o.salt) extensions['prf'] = { eval: { first: o.salt } };
  if (o.read) extensions['largeBlob'] = { read: true };
  if (o.write) extensions['largeBlob'] = { write: o.write };
  let credential: PublicKeyCredential;
  try {
    credential = (await navigator.credentials.get({
      publicKey: {
        challenge: o.challenge as BufferSource,
        rpId: location.hostname,
        timeout: TIMEOUT,
        userVerification: 'required',
        allowCredentials: o.credential ? [{ type: 'public-key', id: o.credential as BufferSource }] : [],
        extensions: extensions as AuthenticationExtensionsClientInputs,
      },
    })) as PublicKeyCredential;
  } catch (error) {
    failed(error);
  }
  const ext = credential.getClientExtensionResults() as Extensions;
  return { credential: bytes(credential.rawId)!, prf: bytes(ext.prf?.results?.first), blob: bytes(ext.largeBlob?.blob), written: ext.largeBlob?.written === true };
}

// ---- What devices keep for us ----------------------------------------------------------------

export interface DeviceRecord {
  /** `${kind}:${id}`: the store's key. */
  slot: string;
  /** prf — the device unlocks what is wrapped here; blob — the device holds the secrets itself. */
  kind: 'prf' | 'blob';
  /** 'key:<fingerprint>' or 'container:<hash of its SKESK>'. */
  id: string;
  credential: Uint8Array;
  /** prf: our random salt. */
  salt: Uint8Array | null;
  /** prf: the secrets (or the container's key) wrapped under the PRF's key. */
  wrapped: Uint8Array | null;
  added: number;
}

const DB = 'html-simple-pgp-devices';
const STORE = 'devices';
const records = new Map<string, DeviceRecord>();
let db: IDBDatabase | null = null;

function request<T>(work: (s: IDBObjectStore) => IDBRequest<T>, mode: IDBTransactionMode): Promise<T> {
  return new Promise((resolve, reject) => {
    if (!db) return reject(new Error('IndexedDB is not open'));
    const tx = db.transaction(STORE, mode);
    const r = work(tx.objectStore(STORE));
    tx.oncomplete = () => resolve(r.result);
    tx.onerror = () => reject(tx.error ?? new Error('IndexedDB'));
    tx.onabort = () => reject(tx.error ?? new Error('IndexedDB'));
  });
}

/** Reads every record into memory; false when this browser keeps no data. */
export async function loadRecords(): Promise<boolean> {
  try {
    db ??= await new Promise<IDBDatabase>((resolve, reject) => {
      const open = indexedDB.open(DB, 1);
      open.onupgradeneeded = () => open.result.createObjectStore(STORE, { keyPath: 'slot' });
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(open.error ?? new Error('IndexedDB'));
    });
    const all = await request((s) => s.getAll() as IDBRequest<DeviceRecord[]>, 'readonly');
    records.clear();
    for (const r of all) records.set(r.slot, r);
    return true;
  } catch {
    return false;
  }
}

export const recordOf = (kind: DeviceRecord['kind'], id: string): DeviceRecord | null => records.get(`${kind}:${id}`) ?? null;

export async function putRecord(r: Omit<DeviceRecord, 'slot' | 'added'>): Promise<void> {
  const full: DeviceRecord = { ...r, slot: `${r.kind}:${r.id}`, added: Math.floor(Date.now() / 1000) };
  await request((s) => s.put(full), 'readwrite');
  records.set(full.slot, full);
}

export async function deleteRecord(kind: DeviceRecord['kind'], id: string): Promise<void> {
  if (!records.has(`${kind}:${id}`)) return;
  await request((s) => s.delete(`${kind}:${id}`), 'readwrite');
  records.delete(`${kind}:${id}`);
}

export const recordCount = (): number => records.size;
