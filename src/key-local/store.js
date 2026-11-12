/**
 * Device-only persistence for scan progress, funded-key history, and the
 * opt-in email setting. Names here are new; existing localStorage keys
 * (clar-verificator-history-v1 and the rest) are not used or renamed.
 * Private keys are written only to IndexedDB, never to localStorage.
 */

export const DB_NAME = 'clar-key-screener';
export const DB_VERSION = 1;

export async function digestHex(value) {
  const bytes = typeof value === 'string'
    ? new TextEncoder().encode(value)
    : value;
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  let hex = '';
  for (const byte of new Uint8Array(digest)) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

export async function fingerprintFile(file) {
  const size = file.size;
  const chunk = Math.min(size, 1024 * 1024);
  const first = await file.slice(0, chunk).arrayBuffer();
  const last = await file.slice(Math.max(0, size - chunk), size).arrayBuffer();
  const firstHash = await digestHex(first);
  const lastHash = await digestHex(last);
  const id = await digestHex(`${file.name || ''}\n${size}\n${firstHash}\n${lastHash}`);
  return {
    id,
    name: file.name || 'fișier',
    size,
    firstHash,
    lastHash,
  };
}

export function createMemoryStore() {
  const progress = new Map();
  const history = new Map();
  const notified = new Map();
  let settings = { id: 'email', email: '', enabled: false };

  return {
    async getProgress(id) {
      const found = progress.get(id);
      return found ? { ...found } : null;
    },
    async putProgress(record) {
      progress.set(record.id, { ...record });
    },
    async deleteProgress(id) {
      progress.delete(id);
    },
    async getHistory() {
      return [...history.values()]
        .map((entry) => ({ ...entry, addresses: entry.addresses?.map((item) => ({ ...item })), assets: entry.assets?.map((item) => ({ ...item })) }))
        .sort((left, right) => right.foundAt - left.foundAt);
    },
    async putHistory(entry) {
      history.set(entry.id, {
        ...entry,
        addresses: entry.addresses?.map((item) => ({ ...item })) || [],
        assets: entry.assets?.map((item) => ({ ...item })) || [],
      });
    },
    async clearHistory() {
      history.clear();
    },
    async wasNotified(id) {
      return notified.has(id);
    },
    async markNotified(id) {
      notified.set(id, { id, at: Date.now() });
    },
    async getSettings() {
      return { ...settings };
    },
    async putSettings(next) {
      settings = {
        id: 'email',
        email: typeof next.email === 'string' ? next.email : settings.email,
        enabled: Boolean(next.enabled),
      };
    },
  };
}

function requestToPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

let databasePromise;

function openDatabase() {
  if (!databasePromise) {
    databasePromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains('progress')) db.createObjectStore('progress', { keyPath: 'id' });
        if (!db.objectStoreNames.contains('history')) db.createObjectStore('history', { keyPath: 'id' });
        if (!db.objectStoreNames.contains('notified')) db.createObjectStore('notified', { keyPath: 'id' });
        if (!db.objectStoreNames.contains('settings')) db.createObjectStore('settings', { keyPath: 'id' });
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    }).catch((error) => {
      databasePromise = undefined;
      throw error;
    });
  }
  return databasePromise;
}

async function withStore(storeName, mode, run) {
  const db = await openDatabase();
  const tx = db.transaction(storeName, mode);
  const store = tx.objectStore(storeName);
  const result = await run(store);
  await new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error || new Error('IndexedDB a întrerupt operația.'));
  });
  return result;
}

export function openBrowserStore() {
  return {
    async getProgress(id) {
      return withStore('progress', 'readonly', (store) => requestToPromise(store.get(id)));
    },
    async putProgress(record) {
      await withStore('progress', 'readwrite', (store) => requestToPromise(store.put({ ...record })));
    },
    async deleteProgress(id) {
      await withStore('progress', 'readwrite', (store) => requestToPromise(store.delete(id)));
    },
    async getHistory() {
      const rows = await withStore('history', 'readonly', (store) => requestToPromise(store.getAll()));
      return (rows || []).sort((left, right) => right.foundAt - left.foundAt);
    },
    async putHistory(entry) {
      await withStore('history', 'readwrite', (store) => requestToPromise(store.put(entry)));
    },
    async clearHistory() {
      await withStore('history', 'readwrite', (store) => requestToPromise(store.clear()));
    },
    async wasNotified(id) {
      const row = await withStore('notified', 'readonly', (store) => requestToPromise(store.get(id)));
      return Boolean(row);
    },
    async markNotified(id) {
      await withStore('notified', 'readwrite', (store) => requestToPromise(store.put({ id, at: Date.now() })));
    },
    async getSettings() {
      const row = await withStore('settings', 'readonly', (store) => requestToPromise(store.get('email')));
      return {
        id: 'email',
        email: typeof row?.email === 'string' ? row.email : '',
        enabled: Boolean(row?.enabled),
      };
    },
    async putSettings(next) {
      await withStore('settings', 'readwrite', (store) => requestToPromise(store.put({
        id: 'email',
        email: typeof next.email === 'string' ? next.email : '',
        enabled: Boolean(next.enabled),
      })));
    },
  };
}
