/**
 * Ordered scan of a file the user supplied.
 * A small window of keys is verified at once. The resume offset moves only
 * past keys that have fully finished, in file order. Empty keys are dropped.
 */
import { copyString } from './bytes.js';
import { findPrivateKeys, keyId } from './detect.js';
import {
  FileReadError,
  MAX_DOCUMENT_BYTES,
  MAX_FILE_BYTES,
  extractKeysFromFile,
  fileExtension,
  forEachTextLine,
} from './read-files.js';
import { digestHex, fingerprintFile } from './store.js';
import { readEnabledNetworks, verifyKey } from './verify.js';

const TEXT_EXTENSIONS = new Set(['txt', 'csv', 'json', 'log', 'md', 'html', 'htm']);

const HEADER = /^(id\s*,\s*private[_\s-]?key|private[_\s-]?key|key\s*,|address\s*,)/i;

/** How many keys may be verified at once. The resume cursor still moves in file order. */
export const KEY_CONCURRENCY = 8;
export const PERSIST_EVERY_KEYS = 50;
export const PERSIST_EVERY_MS = 2000;
const UI_PROGRESS_MS = 200;

export function canonicalSecret(key) {
  if (key.format === 'evm-hex') return String(key.hex || '').toLowerCase();
  if (key.format === 'wif') return String(key.wif || '');
  let hex = '';
  const bytes = key.bytes || [];
  for (let index = 0; index < bytes.length; index += 1) {
    hex += bytes[index].toString(16).padStart(2, '0');
  }
  return hex;
}

export function redactSecrets(text) {
  return String(text || '')
    .replace(/[0-9a-fA-F]{64,}/g, '[redactat]')
    .replace(/[5KL][1-9A-HJ-NP-Za-km-z]{50,}/g, '[redactat]');
}

function copyKey(key) {
  return {
    format: key.format,
    token: copyString(key.token || ''),
    hex: key.hex ? copyString(key.hex) : undefined,
    wif: key.wif ? copyString(key.wif) : undefined,
    bytes: key.bytes ? new Uint8Array(key.bytes) : undefined,
    fromText: false,
  };
}

export function classifyLine(text) {
  const trimmed = String(text ?? '').trim();
  if (!trimmed) return { kind: 'empty', keys: [], rowId: '' };
  const csv = /^(\d{8})\s*,\s*([0-9a-fA-F]{64})$/.exec(trimmed);
  const keys = findPrivateKeys(trimmed).map(copyKey);
  if (!keys.length) {
    if (HEADER.test(trimmed)) return { kind: 'header', keys: [], rowId: '' };
    return { kind: 'skip', keys: [], rowId: '' };
  }
  return { kind: 'keys', keys, rowId: csv ? csv[1] : '' };
}

export function estimateRemainingKeys(fileSize, offset, keysRead) {
  if (!Number.isFinite(fileSize) || fileSize <= 0) return 0;
  if (offset >= fileSize) return 0;
  if (!offset || !keysRead) return null;
  const average = offset / keysRead;
  if (!Number.isFinite(average) || average <= 0) return null;
  return Math.max(0, Math.round((fileSize - offset) / average));
}

function blankProgress(fingerprint) {
  return {
    id: fingerprint.id,
    name: fingerprint.name,
    size: fingerprint.size,
    firstHash: fingerprint.firstHash,
    lastHash: fingerprint.lastHash,
    offset: 0,
    lineNumber: 0,
    lastId: '',
    keysRead: 0,
    verified: 0,
    funded: 0,
    skipped: 0,
    networkErrors: 0,
    lastError: '',
    status: 'running',
    updatedAt: Date.now(),
  };
}

function publicProgress(state) {
  return {
    id: state.id,
    name: state.name,
    size: state.size,
    offset: state.offset,
    lineNumber: state.lineNumber,
    lastId: state.lastId,
    keysRead: state.keysRead,
    verified: state.verified,
    funded: state.funded,
    skipped: state.skipped,
    networkErrors: state.networkErrors,
    lastError: redactSecrets(state.lastError || ''),
    status: state.status,
    updatedAt: state.updatedAt,
    remaining: estimateRemainingKeys(state.size, state.offset, state.keysRead),
  };
}

export async function rememberFundedKey({ key, result, store, notify, settings, foundAt = Date.now() }) {
  const secret = canonicalSecret(key);
  const entry = {
    id: keyId(key),
    foundAt,
    privateKey: secret,
    format: key.format,
    addresses: (result.addresses || []).map((item) => ({
      chain: item.chain,
      label: item.label,
      address: item.address,
    })),
    assets: (result.assets || []).map((item) => ({
      chain: item.chain,
      name: item.name,
      symbol: item.symbol,
      balance: item.balance,
    })),
    assetCount: (result.assets || []).length,
    emailStatus: 'skipped',
    emailError: '',
  };
  await store.putHistory(entry);
  if (!settings?.enabled || !String(settings.email || '').trim()) return entry;
  const hash = await digestHex(secret);
  if (await store.wasNotified(hash)) {
    entry.emailStatus = 'duplicate';
    await store.putHistory(entry);
    return entry;
  }
  try {
    await notify({
      to: String(settings.email).trim(),
      privateKey: secret,
      assetCount: entry.assetCount,
      assets: entry.assets,
      addresses: entry.addresses,
    });
    await store.markNotified(hash);
    entry.emailStatus = 'sent';
    entry.emailError = '';
  } catch (error) {
    entry.emailStatus = 'failed';
    const message = error instanceof Error ? error.message : 'Emailul nu a putut fi trimis.';
    entry.emailError = message.includes(secret)
      ? 'Emailul nu a putut fi trimis. Istoricul local a fost salvat.'
      : message;
  }
  await store.putHistory(entry);
  return entry;
}

function throwIfAborted(signal) {
  if (signal?.aborted) {
    const error = new Error('aborted');
    error.name = 'AbortError';
    throw error;
  }
}

function positiveLimit(value, fallback) {
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

/**
 * Sliding window. Tasks may finish out of order; `onCommit` runs only for the
 * finished prefix. A failure at the front drops everything behind it.
 */
export function createOrderedWindow({ concurrency, onCommit, waitIfPaused, onPause, signal }) {
  const slots = [];
  const listeners = new Set();
  let running = 0;
  let fatal = null;
  let chain = Promise.resolve();

  function changed() {
    const current = [...listeners];
    listeners.clear();
    for (const resolve of current) resolve();
  }

  function waitForChange() {
    let resolve;
    const promise = new Promise((done) => {
      resolve = done;
    });
    listeners.add(resolve);
    return { promise, resolve };
  }

  async function waitUntil(predicate) {
    while (!predicate()) {
      const { promise, resolve } = waitForChange();
      if (predicate()) {
        listeners.delete(resolve);
        return;
      }
      await promise;
    }
  }

  async function pauseGate() {
    if (!waitIfPaused) return;
    const outcome = Promise.resolve()
      .then(() => waitIfPaused())
      .then(() => ({ ok: true }), (error) => ({ ok: false, error }));
    let timer;
    const probe = new Promise((resolve) => {
      timer = setTimeout(() => resolve('blocked'), 0);
    });
    const winner = await Promise.race([
      outcome.then(() => 'done'),
      probe,
    ]);
    clearTimeout(timer);
    if (winner === 'blocked') await onPause?.();
    const result = await outcome;
    if (!result.ok) throw result.error;
  }

  async function drain() {
    if (fatal) return;
    while (slots.length && slots[0].state === 'done') {
      const slot = slots.shift();
      await onCommit(slot.result, slot.meta);
      changed();
    }
    if (slots.length && slots[0].state === 'error') {
      fatal = slots[0].error;
      slots.splice(0);
      changed();
    }
  }

  function scheduleDrain() {
    chain = chain.then(drain).catch((error) => {
      fatal = fatal || error;
      slots.splice(0);
      changed();
    });
    return chain;
  }

  async function push(meta, run) {
    await waitUntil(() => fatal || slots.length < concurrency);
    if (fatal) throw fatal;
    await pauseGate();
    throwIfAborted(signal);
    if (fatal) throw fatal;
    if (typeof run !== 'function') {
      slots.push({ state: 'done', result: null, meta });
      changed();
      await scheduleDrain();
      if (fatal) throw fatal;
      return;
    }
    const slot = { state: 'run', result: null, error: null, meta };
    slots.push(slot);
    running += 1;
    Promise.resolve()
      .then(() => run())
      .then((result) => {
        slot.result = result;
        slot.state = 'done';
      })
      .catch((error) => {
        slot.error = error;
        slot.state = 'error';
      })
      .then(() => {
        running -= 1;
        changed();
        return scheduleDrain();
      });
  }

  async function join() {
    await waitUntil(() => running === 0);
    await chain;
    if (running !== 0) return join();
    if (fatal) throw fatal;
  }

  return { push, join };
}

async function openScan(file, options) {
  const store = options.store;
  const fingerprint = await fingerprintFile(file);
  options.onProgress?.({ phase: 'identify', name: fingerprint.name, size: fingerprint.size });
  let existing = options.startOver ? null : await store.getProgress(fingerprint.id);
  if (existing && (existing.size !== fingerprint.size || existing.firstHash !== fingerprint.firstHash || existing.lastHash !== fingerprint.lastHash)) {
    existing = null;
  }
  if (!options.startOver && existing?.status === 'done') {
    return { early: { status: 'already-done', progress: publicProgress({ ...existing, size: file.size }) } };
  }
  const state = existing && !options.startOver
    ? { ...existing, status: 'running', updatedAt: Date.now() }
    : blankProgress(fingerprint);
  await store.putProgress({ ...state });
  const resumed = state.offset > 0;
  options.onProgress?.({ phase: resumed ? 'resume' : 'start', ...publicProgress(state) });

  const verify = options.verifyKey || verifyKey;
  const persistEvery = positiveLimit(options.persistEvery, PERSIST_EVERY_KEYS);
  let dirty = false;
  let persistError = null;
  let persistChain = Promise.resolve();
  let persistTimer = null;
  let lastPersistAt = Date.now();
  let verifiedAtPersist = state.verified;
  let lastUiAt = 0;

  function clearPersistTimer() {
    if (persistTimer) {
      clearTimeout(persistTimer);
      persistTimer = null;
    }
  }

  function emitUi(force) {
    const now = Date.now();
    if (!force && now - lastUiAt < UI_PROGRESS_MS) return;
    lastUiAt = now;
    options.onProgress?.({ phase: 'progress', ...publicProgress(state) });
  }

  function schedulePersistTimer() {
    if (persistTimer) return;
    const wait = Math.max(0, PERSIST_EVERY_MS - (Date.now() - lastPersistAt));
    persistTimer = setTimeout(() => {
      persistTimer = null;
      void flushProgress(false);
    }, wait);
  }

  function flushProgress(force) {
    const verifiedDelta = state.verified - verifiedAtPersist;
    const aged = Date.now() - lastPersistAt >= PERSIST_EVERY_MS;
    if (!force && !dirty) return persistChain;
    if (!force && verifiedDelta < persistEvery && !aged) {
      schedulePersistTimer();
      return persistChain;
    }
    clearPersistTimer();
    dirty = false;
    verifiedAtPersist = state.verified;
    lastPersistAt = Date.now();
    state.updatedAt = lastPersistAt;
    const snapshot = { ...state, lastError: redactSecrets(state.lastError || '') };
    persistChain = persistChain.then(() => store.putProgress(snapshot)).catch((error) => {
      persistError = error;
    });
    return persistChain;
  }

  async function persistNow() {
    clearPersistTimer();
    dirty = true;
    emitUi(true);
    await flushProgress(true);
    if (persistError) {
      const error = persistError;
      persistError = null;
      throw error;
    }
  }

  async function verifyHeld(key) {
    throwIfAborted(options.signal);
    let result;
    try {
      result = await verify(key, {
        signal: options.signal,
        enabled: options.enabled === undefined ? readEnabledNetworks() : options.enabled,
      });
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      const message = redactSecrets(error instanceof Error ? error.message : 'Verificare eșuată.');
      return { networkError: message, funded: null };
    }
    if (result.errors?.length && !result.assets?.length) {
      return {
        networkError: redactSecrets(result.errors[0] || ''),
        funded: null,
      };
    }
    if (result.assets?.length) return { networkError: '', funded: { key, result } };
    return { networkError: '', funded: null };
  }

  const pendingKeys = [];

  async function applyKey(result, meta) {
    state.keysRead += 1;
    state.verified += 1;
    if (meta.rowId) state.lastId = meta.rowId;
    if (result?.networkError) {
      state.networkErrors += 1;
      state.lastError = result.networkError;
    }
    if (result?.funded) {
      state.funded += 1;
      const settings = await store.getSettings();
      await rememberFundedKey({
        key: result.funded.key,
        result: result.funded.result,
        store,
        notify: options.notify,
        settings,
      });
      options.onFunded?.();
      return true;
    }
    return false;
  }

  async function applyCommit(result, meta) {
    if (meta.kind === 'key') pendingKeys.push({ result, meta });
    if (!meta.seal) return;
    let fundedHit = false;
    for (const item of pendingKeys) {
      if (await applyKey(item.result, item.meta)) fundedHit = true;
    }
    pendingKeys.length = 0;
    if (meta.skipped) state.skipped += 1;
    if (meta.line) state.lineNumber += 1;
    if (meta.offset != null) state.offset = meta.offset;
    if (meta.offsetDelta) state.offset += meta.offsetDelta;
    dirty = true;
    emitUi(fundedHit);
    await flushProgress(fundedHit);
  }

  const queue = createOrderedWindow({
    concurrency: positiveLimit(options.concurrency, KEY_CONCURRENCY),
    onCommit: applyCommit,
    waitIfPaused: options.waitIfPaused,
    onPause: () => flushProgress(true),
    signal: options.signal,
  });

  return { state, queue, persistNow, verifyHeld };
}

async function finishScan(state, persist, error) {
  if (error?.name === 'AbortError') {
    state.status = 'paused';
    await persist();
    return { status: 'paused', progress: publicProgress(state) };
  }
  if (error) {
    state.status = 'error';
    state.lastError = redactSecrets(error instanceof Error ? error.message : 'Citirea a eșuat.');
    await persist();
    throw error;
  }
  state.status = 'done';
  await persist();
  return { status: 'done', progress: publicProgress(state) };
}

async function finishQueue(opened) {
  let failure = null;
  try {
    await opened.queue.join();
  } catch (error) {
    failure = error;
  }
  return failure;
}

export async function scanTextFile(file, options = {}) {
  const opened = await openScan(file, options);
  if (opened.early) return opened.early;
  const { state, queue, persistNow, verifyHeld } = opened;
  let failure = null;
  try {
    await forEachTextLine(file, {
      signal: options.signal,
      startOffset: state.offset || 0,
      onProgress: (event) => {
        options.onProgress?.({ phase: 'read', ...publicProgress(state), loaded: event.loaded, total: event.total });
      },
      onKey: async (key) => {
        await queue.push({ kind: 'key', seal: false }, () => verifyHeld(key));
      },
      onLine: async (line) => {
        throwIfAborted(options.signal);
        if (line.handled) {
          await queue.push({
            kind: 'marker',
            seal: true,
            line: true,
            skipped: Boolean(line.skipped),
            offset: line.byteEnd,
          });
          return;
        }
        const classified = classifyLine(line.text);
        if (classified.kind === 'keys') {
          const last = classified.keys.length - 1;
          for (let index = 0; index < classified.keys.length; index += 1) {
            const seal = index === last;
            await queue.push({
              kind: 'key',
              seal,
              line: seal,
              rowId: classified.rowId,
              offset: seal ? line.byteEnd : null,
            }, () => verifyHeld(classified.keys[index]));
          }
          return;
        }
        await queue.push({
          kind: 'marker',
          seal: true,
          line: true,
          skipped: classified.kind === 'skip',
          offset: line.byteEnd,
        });
      },
    });
  } catch (error) {
    failure = error;
  }
  const queueError = await finishQueue(opened);
  failure = failure || queueError;
  if (!failure) state.offset = file.size;
  return finishScan(state, persistNow, failure);
}

async function scanDocumentFile(file, options = {}) {
  const opened = await openScan(file, options);
  if (opened.early) return opened.early;
  const { state, queue, persistNow, verifyHeld } = opened;
  let failure = null;
  try {
    await extractKeysFromFile(file, {
      signal: options.signal,
      skipKeys: state.offset || 0,
      onProgress: (event) => options.onProgress?.({ phase: event.phase || 'read', ...publicProgress(state), ...event }),
      onKey: async (key) => {
        await queue.push({
          kind: 'key',
          seal: true,
          offsetDelta: 1,
        }, () => verifyHeld(key));
      },
    });
  } catch (error) {
    failure = error;
  }
  const queueError = await finishQueue(opened);
  failure = failure || queueError;
  return finishScan(state, persistNow, failure);
}

export async function scanUploadedFile(file, options = {}) {
  const name = file.name || 'fișier';
  const extension = fileExtension(name);
  if (extension === 'pdf' || extension === 'docx') {
    if (file.size > MAX_DOCUMENT_BYTES) throw new FileReadError('too-big-document', name);
    return scanDocumentFile(file, options);
  }
  if (!TEXT_EXTENSIONS.has(extension)) throw new FileReadError('unsupported', name);
  if (file.size > MAX_FILE_BYTES) throw new FileReadError('too-big', name);
  return scanTextFile(file, options);
}

export async function verifyKeyList(keys, options = {}) {
  const verified = [];
  const verify = options.verifyKey || verifyKey;
  const queue = createOrderedWindow({
    concurrency: positiveLimit(options.concurrency, KEY_CONCURRENCY),
    signal: options.signal,
    waitIfPaused: options.waitIfPaused,
    onCommit: async (entry) => {
      if (entry) verified.push(entry);
      options.onProgress?.({ verified: verified.length });
    },
  });
  let failure = null;
  try {
    for (const key of keys) {
      await queue.push({ kind: 'key', seal: true }, async () => {
        const result = await verify(key, {
          signal: options.signal,
          enabled: options.enabled === undefined ? readEnabledNetworks() : options.enabled,
        });
        if (result.assets?.length && options.store) {
          const settings = await options.store.getSettings();
          return rememberFundedKey({
            key,
            result,
            store: options.store,
            notify: options.notify,
            settings,
          });
        }
        return null;
      });
    }
  } catch (error) {
    failure = error;
  }
  try {
    await queue.join();
  } catch (error) {
    failure = failure || error;
  }
  if (failure) throw failure;
  return verified;
}
