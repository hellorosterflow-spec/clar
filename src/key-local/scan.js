/**
 * Ordered scan of a file the user supplied.
 * Keys are derived and checked one at a time, then dropped unless they have funds.
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

  const persist = async () => {
    state.updatedAt = Date.now();
    await store.putProgress({ ...state, lastError: redactSecrets(state.lastError || '') });
    options.onProgress?.({ phase: 'progress', ...publicProgress(state) });
  };
  const verify = options.verifyKey || verifyKey;
  const verifyOne = async (key, rowId) => {
    await options.waitIfPaused?.();
    throwIfAborted(options.signal);
    state.keysRead += 1;
    options.onProgress?.({ phase: 'verify', ...publicProgress(state) });
    let result;
    try {
      result = await verify(key, {
        signal: options.signal,
        enabled: options.enabled === undefined ? readEnabledNetworks() : options.enabled,
      });
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      state.lastError = redactSecrets(error instanceof Error ? error.message : 'Verificare eșuată.');
      result = { addresses: [], assets: [], assetCount: 0, errors: [state.lastError] };
    }
    if (result.errors?.length && !result.assets?.length) {
      state.networkErrors += 1;
      state.lastError = redactSecrets(result.errors[0] || state.lastError);
    }
    state.verified += 1;
    if (rowId) state.lastId = rowId;
    if (result.assets?.length) {
      state.funded += 1;
      const settings = await store.getSettings();
      await rememberFundedKey({
        key,
        result,
        store,
        notify: options.notify,
        settings,
      });
      options.onFunded?.();
    }
  };
  return { state, persist, verifyOne };
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

export async function scanTextFile(file, options = {}) {
  const opened = await openScan(file, options);
  if (opened.early) return opened.early;
  const { state, persist, verifyOne } = opened;
  let failure = null;
  try {
    await forEachTextLine(file, {
      signal: options.signal,
      startOffset: state.offset || 0,
      onProgress: (event) => {
        options.onProgress?.({ phase: 'read', ...publicProgress(state), loaded: event.loaded, total: event.total });
      },
      onKey: async (key) => {
        await verifyOne(key, '');
      },
      onLine: async (line) => {
        throwIfAborted(options.signal);
        if (line.handled) {
          state.offset = line.byteEnd;
          state.lineNumber += 1;
          if (line.skipped) state.skipped += 1;
          await persist();
          return;
        }
        const classified = classifyLine(line.text);
        state.lineNumber += 1;
        if (classified.kind === 'empty' || classified.kind === 'header') {
          state.offset = line.byteEnd;
          await persist();
          return;
        }
        if (classified.kind === 'skip') {
          state.skipped += 1;
          state.offset = line.byteEnd;
          await persist();
          return;
        }
        for (const key of classified.keys) {
          await verifyOne(key, classified.rowId);
        }
        state.offset = line.byteEnd;
        await persist();
      },
    });
    state.offset = file.size;
  } catch (error) {
    failure = error;
  }
  return finishScan(state, persist, failure);
}

async function scanDocumentFile(file, options = {}) {
  const opened = await openScan(file, options);
  if (opened.early) return opened.early;
  const { state, persist, verifyOne } = opened;
  let failure = null;
  try {
    await extractKeysFromFile(file, {
      signal: options.signal,
      skipKeys: state.offset || 0,
      onProgress: (event) => options.onProgress?.({ phase: event.phase || 'read', ...publicProgress(state), ...event }),
      onKey: async (key) => {
        await verifyOne(key, '');
        state.offset += 1;
        await persist();
      },
    });
  } catch (error) {
    failure = error;
  }
  return finishScan(state, persist, failure);
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
  for (const key of keys) {
    await options.waitIfPaused?.();
    if (options.signal?.aborted) {
      const error = new Error('aborted');
      error.name = 'AbortError';
      throw error;
    }
    const result = await (options.verifyKey || verifyKey)(key, {
      signal: options.signal,
      enabled: options.enabled === undefined ? readEnabledNetworks() : options.enabled,
    });
    if (result.assets?.length && options.store) {
      const settings = await options.store.getSettings();
      const entry = await rememberFundedKey({
        key,
        result,
        store: options.store,
        notify: options.notify,
        settings,
      });
      verified.push(entry);
    }
    options.onProgress?.({ verified: verified.length });
  }
  return verified;
}
