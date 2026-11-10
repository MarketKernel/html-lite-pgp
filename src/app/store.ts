// The keyring's records in IndexedDB, one per key, by fingerprint — each key's packets as GnuPG
// would export them, secret parts still under their passphrases. Every window of the app on
// this origin shares the store; a change is announced on a BroadcastChannel. (After html-pgp.)
//
// Also kept here, apart from the keys: the handle of the container file (File System Access),
// so the file can be opened again with a click — the handle only, never its contents.

import type { KeyRecord, KeyStore } from '../core/keyring.ts';
import { MemoryStore } from '../core/keyring.ts';

const DB = 'html-simple-pgp';
const KEYS = 'keys';
const HANDLES = 'handles';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(KEYS, { keyPath: 'fingerprint' });
      request.result.createObjectStore(HANDLES);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB'));
    request.onblocked = () => reject(new Error('IndexedDB is blocked by another window'));
  });
}

const channel = typeof BroadcastChannel === 'function' ? new BroadcastChannel('html-simple-pgp') : null;

function run<T>(db: IDBDatabase, store: string, mode: IDBTransactionMode, work: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, mode);
    const request = work(tx.objectStore(store));
    tx.oncomplete = () => resolve(request.result);
    tx.onerror = () => reject(tx.error ?? new Error('IndexedDB'));
    tx.onabort = () => reject(tx.error ?? new Error('IndexedDB'));
  });
}

export class IdbStore implements KeyStore {
  private readonly db: IDBDatabase;

  constructor(db: IDBDatabase) {
    this.db = db;
  }

  async load(): Promise<KeyRecord[]> {
    return run(this.db, KEYS, 'readonly', (s) => s.getAll() as IDBRequest<KeyRecord[]>);
  }

  async save(record: KeyRecord): Promise<void> {
    await run(this.db, KEYS, 'readwrite', (s) => s.put(record));
    channel?.postMessage('changed');
  }

  async remove(fingerprint: string): Promise<void> {
    await run(this.db, KEYS, 'readwrite', (s) => s.delete(fingerprint));
    channel?.postMessage('changed');
  }

  /** Deletes every key record (when the keys move into a container). */
  async clear(): Promise<void> {
    await run(this.db, KEYS, 'readwrite', (s) => s.clear());
    channel?.postMessage('changed');
  }

  async getHandle(): Promise<FileSystemFileHandle | null> {
    return ((await run(this.db, HANDLES, 'readonly', (s) => s.get('container'))) as FileSystemFileHandle | undefined) ?? null;
  }

  async setHandle(handle: FileSystemFileHandle | null): Promise<void> {
    await run(this.db, HANDLES, 'readwrite', (s) => (handle ? s.put(handle, 'container') : s.delete('container')));
  }
}

let database: IdbStore | null = null;

/** The browser's store, or null when IndexedDB is not there (the keys then last as long as the page). */
export async function openIdb(): Promise<IdbStore | null> {
  if (database) return database;
  try {
    database = new IdbStore(await openDb());
    return database;
  } catch {
    return null;
  }
}

export const memoryStore = (): KeyStore => new MemoryStore();

export function onStoreChanged(listener: () => void): void {
  channel?.addEventListener('message', (event) => {
    if (event.data === 'changed') listener();
  });
}

/** Asks the browser not to clear the keyring when space runs short — after the user did something, never on start. */
export function keepStorage(): void {
  void navigator.storage?.persist?.().catch(() => undefined);
}
