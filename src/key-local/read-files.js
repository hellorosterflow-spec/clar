/**
 * Reads files the user selected, in chunks, and returns only extracted keys.
 * File bytes are not uploaded, stored, or placed in the page URL.
 */
import { unzipSync } from 'fflate';
import { copyString } from './bytes.js';
import { createKeyBuffer, dedupeKeys, findPrivateKeys, findPrivateKeysInDocument, keyId } from './detect.js';

/** Text, CSV, JSON, LOG, MD, and HTML. 1 GiB also accepts a decimal “1 GB” file (10^9 bytes). */
export const MAX_FILE_BYTES = 1024 * 1024 * 1024;
/** PDF and DOCX are opened as a whole, so they stay well below the text cap. */
export const MAX_DOCUMENT_BYTES = 100 * 1024 * 1024;
export const READ_CHUNK_BYTES = 1024 * 1024;
/** A single text line above this is scanned in windows so a huge line is not kept whole. */
const MAX_LINE_BYTES = 2 * 1024 * 1024;
const KEY_CARRY_BYTES = 64 * 1024;
const TEXT_EXTENSIONS = new Set(['txt', 'csv', 'json', 'log', 'md', 'html', 'htm']);
const DOCUMENT_EXTENSIONS = new Set(['pdf', 'docx']);

export function formatUploadLimit(bytes) {
  const gib = 1024 * 1024 * 1024;
  const mib = 1024 * 1024;
  if (bytes >= gib && bytes % gib === 0) return `${bytes / gib} GB`;
  if (bytes >= mib && bytes % mib === 0) return `${bytes / mib} MB`;
  if (bytes >= mib) return `${Math.round(bytes / mib)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

export function fileReadLimitMessage(code, fileName) {
  const name = fileName || 'fișier';
  if (code === 'too-big') {
    return `„${name}” depășește limita de ${formatUploadLimit(MAX_FILE_BYTES)}.`;
  }
  if (code === 'too-big-document') {
    return `„${name}” trebuie deschis ca întreg, așa că limita pentru PDF și DOCX este ${formatUploadLimit(MAX_DOCUMENT_BYTES)}. Un fișier TXT, CSV, JSON, LOG, MD sau HTML de ${formatUploadLimit(MAX_FILE_BYTES)} este în regulă.`;
  }
  return code;
}

export class FileReadError extends Error {
  constructor(code, fileName) {
    super(fileReadLimitMessage(code, fileName));
    this.name = 'FileReadError';
    this.code = code;
    this.fileName = fileName;
  }
}

export function yieldToUi() {
  return new Promise((resolve) => {
    setTimeout(resolve, 0);
  });
}

function throwIfAborted(signal) {
  if (signal?.aborted) {
    const error = new Error('aborted');
    error.name = 'AbortError';
    throw error;
  }
}

export function fileExtension(name) {
  const base = String(name || '').split(/[/\\]/).pop() || '';
  const dot = base.lastIndexOf('.');
  if (dot <= 0) return '';
  return base.slice(dot + 1).toLowerCase();
}

function decodeEncoding(bytes) {
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) return 'utf-16le';
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) return 'utf-16be';
  return 'utf-8';
}

async function readChunked(blob, { signal, onProgress, onBytes }) {
  const total = blob.size;
  let offset = 0;
  while (offset < total) {
    throwIfAborted(signal);
    const end = Math.min(total, offset + READ_CHUNK_BYTES);
    const bytes = new Uint8Array(await blob.slice(offset, end).arrayBuffer());
    offset = end;
    await onBytes(bytes, offset >= total);
    onProgress?.({ phase: 'read', loaded: offset, total });
    await yieldToUi();
  }
}

function concatBytes(left, right) {
  if (!left.length) return right;
  if (!right.length) return left;
  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
}

function indexOfByte(bytes, value) {
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] === value) return index;
  }
  return -1;
}

function decodeLineBytes(bytes) {
  let start = 0;
  let end = bytes.length;
  if (end >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) start = 3;
  if (end > start && bytes[end - 1] === 0x0a) end -= 1;
  if (end > start && bytes[end - 1] === 0x0d) end -= 1;
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(start, end));
}

function detachKey(key) {
  return {
    format: key.format,
    token: copyString(key.token),
    hex: key.hex ? copyString(key.hex) : undefined,
    wif: key.wif ? copyString(key.wif) : undefined,
    bytes: key.bytes ? new Uint8Array(key.bytes) : undefined,
    fromText: false,
  };
}

async function emitLongLine(bytes, options) {
  let ascii = true;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] > 0x7f) {
      ascii = false;
      break;
    }
  }
  if (!ascii) return 0;
  const decoder = new TextDecoder('utf-8', { fatal: false });
  let offset = 0;
  let found = 0;
  while (offset < bytes.length) {
    throwIfAborted(options.signal);
    const eof = offset + KEY_CARRY_BYTES >= bytes.length;
    const sliceEnd = Math.min(bytes.length, offset + KEY_CARRY_BYTES + READ_CHUNK_BYTES);
    const text = decoder.decode(bytes.subarray(offset, sliceEnd));
    const stable = eof ? text.length : Math.max(0, text.length - KEY_CARRY_BYTES);
    const keys = findPrivateKeys(text).filter((key) => key.end <= stable).map(detachKey);
    if (options.onKey) {
      for (const key of keys) {
        found += 1;
        await options.onKey(key);
      }
    } else if (keys.length && options.onLine) {
      await options.onLine({
        text: text.slice(0, stable),
        byteStart: 0,
        byteEnd: 0,
        handled: false,
        skipped: false,
      });
    }
    found = options.onKey ? found : keys.length;
    if (eof) break;
    offset += stable;
    await yieldToUi();
  }
  return found;
}

/**
 * Read a text-like file from `startOffset` without building one giant string.
 * Each complete line (or each key inside a very long line) is handed off before
 * the next one is kept. The 1 MiB chunk size, yield, and AbortSignal stay.
 */
export async function forEachTextLine(file, options = {}) {
  const total = file.size;
  let filePos = Math.min(total, Math.max(0, options.startOffset || 0));
  let pending = new Uint8Array(0);
  let pendingStart = filePos;

  while (filePos < total || pending.length) {
    throwIfAborted(options.signal);
    if (pending.length <= MAX_LINE_BYTES && filePos < total) {
      const end = Math.min(total, filePos + READ_CHUNK_BYTES);
      const chunk = new Uint8Array(await file.slice(filePos, end).arrayBuffer());
      pending = concatBytes(pending, chunk);
      filePos = end;
      options.onProgress?.({ phase: 'read', loaded: filePos, total });
      await yieldToUi();
    }

    let drained = false;
    while (true) {
      const newline = indexOfByte(pending, 0x0a);
      if (newline === -1 || newline > MAX_LINE_BYTES) break;
      const lineBytes = pending.subarray(0, newline + 1);
      const byteStart = pendingStart;
      const byteEnd = byteStart + lineBytes.length;
      pending = pending.subarray(newline + 1);
      pendingStart = byteEnd;
      drained = true;
      await options.onLine?.({
        text: decodeLineBytes(lineBytes),
        byteStart,
        byteEnd,
        handled: false,
        skipped: false,
      });
    }
    if (pending.length && pending.length < 64 * 1024) pending = pending.slice();

    const eof = filePos >= total;
    if (pending.length > MAX_LINE_BYTES || (eof && pending.length > MAX_LINE_BYTES)) {
      const newline = indexOfByte(pending, 0x0a);
      const limit = newline === -1 ? pending.length : newline + 1;
      const lineBytes = pending.subarray(0, limit);
      const byteStart = pendingStart;
      const byteEnd = byteStart + lineBytes.length;
      const found = await emitLongLine(lineBytes, options);
      pending = pending.subarray(limit);
      pendingStart = byteEnd;
      if (pending.length && pending.length < 64 * 1024) pending = pending.slice();
      await options.onLine?.({
        text: '',
        byteStart,
        byteEnd,
        handled: true,
        skipped: found === 0,
      });
      continue;
    }

    if (eof) {
      if (pending.length) {
        const byteStart = pendingStart;
        const byteEnd = byteStart + pending.length;
        await options.onLine?.({
          text: decodeLineBytes(pending),
          byteStart,
          byteEnd,
          handled: false,
          skipped: false,
        });
      }
      break;
    }
    if (!drained && filePos >= total) break;
  }
}

async function scanTextBlob(blob, options) {
  const head = new Uint8Array(await blob.slice(0, Math.min(4, blob.size)).arrayBuffer());
  if (decodeEncoding(head) !== 'utf-8') {
    const decoder = new TextDecoder(decodeEncoding(head), { ignoreBOM: true });
    const buffer = createKeyBuffer();
    await readChunked(blob, {
      signal: options.signal,
      onProgress: options.onProgress,
      onBytes: async (bytes, final) => {
        buffer.push(decoder.decode(bytes, { stream: !final }), final);
      },
    });
    return buffer.finish();
  }
  const keys = [];
  await forEachTextLine(blob, {
    ...options,
    onKey: async (key) => {
      keys.push(key);
    },
    onLine: async ({ text, handled }) => {
      if (handled || !text) return;
      for (const key of findPrivateKeys(text)) keys.push(detachKey(key));
    },
  });
  return { keys: dedupeKeys(keys), overflow: 0 };
}

function xmlToText(xml) {
  return xml
    .replace(/<w:tab\/>/g, '\t')
    .replace(/<w:br\/>/g, '\n')
    .replace(/<\/w:p>/g, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#(\d+);/g, (_, value) => String.fromCodePoint(Number(value)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, value) => String.fromCodePoint(Number.parseInt(value, 16)));
}

async function readAll(blob, options) {
  const out = new Uint8Array(blob.size);
  let offset = 0;
  await readChunked(blob, {
    ...options,
    onBytes: async (bytes) => {
      out.set(bytes, offset);
      offset += bytes.length;
    },
  });
  return out;
}

async function scanDocx(blob, options) {
  let files;
  try {
    const bytes = await readAll(blob, options);
    throwIfAborted(options.signal);
    options.onProgress?.({ phase: 'docx', loaded: blob.size, total: blob.size });
    await yieldToUi();
    files = unzipSync(bytes);
  } catch (error) {
    if (error?.name === 'AbortError') throw error;
    throw new FileReadError('docx', blob.name);
  }
  const parts = [];
  for (const name of Object.keys(files)) {
    if (!name.startsWith('word/') || !name.endsWith('.xml')) continue;
    parts.push(xmlToText(new TextDecoder('utf-8').decode(files[name])));
  }
  const text = parts.join('\n');
  if (options.onKey) {
    const seen = new Set();
    let emitted = 0;
    let carry = '';
    const slice = 128 * 1024;
    for (let index = 0; index < text.length; index += slice) {
      throwIfAborted(options.signal);
      const final = index + slice >= text.length;
      const piece = `${carry}${text.slice(index, index + slice)}`;
      const stable = final ? piece.length : Math.max(0, piece.length - 4096);
      for (const key of findPrivateKeysInDocument(piece)) {
        if (!final && key.end > stable) continue;
        const id = keyId(key);
        if (seen.has(id)) continue;
        seen.add(id);
        emitted += 1;
        if (emitted <= (options.skipKeys || 0)) continue;
        await options.onKey(detachKey(key));
      }
      carry = piece.slice(-4096);
      await yieldToUi();
    }
    return { keys: [], overflow: 0 };
  }
  const direct = createKeyBuffer();
  const slice = 128 * 1024;
  for (let index = 0; index < text.length; index += slice) {
    throwIfAborted(options.signal);
    const final = index + slice >= text.length;
    direct.push(text.slice(index, index + slice), final);
    await yieldToUi();
  }
  const scanned = direct.finish();
  const wrapped = text.length <= 2_000_000 ? findPrivateKeysInDocument(text) : [];
  return { keys: dedupeKeys([...scanned.keys, ...wrapped]), overflow: 0 };
}

let pdfLibrary;

export async function loadPdfLibrary() {
  if (!pdfLibrary) {
    const href = new URL('./pdfjs-parser.js', import.meta.url).href;
    pdfLibrary = import(/* @vite-ignore */ href).catch((error) => {
      pdfLibrary = undefined;
      throw error;
    });
  }
  return pdfLibrary;
}

function pageText(content) {
  let text = '';
  let lastY = null;
  for (const item of content.items) {
    if (!item || typeof item.str !== 'string') continue;
    const y = Array.isArray(item.transform) ? item.transform[5] : null;
    if (lastY != null && y != null && Math.abs(y - lastY) > 2) text += '\n';
    text += item.str;
    if (item.hasEOL) text += '\n';
    lastY = y ?? lastY;
  }
  return text;
}

async function scanPdf(blob, options) {
  const data = await readAll(blob, options);
  throwIfAborted(options.signal);
  let pdfjs;
  try {
    pdfjs = await loadPdfLibrary();
  } catch {
    throw new FileReadError('pdf', blob.name);
  }
  pdfjs.GlobalWorkerOptions.workerSrc = new URL('./pdf.worker.min.js', import.meta.url).href;
  let task;
  try {
    task = pdfjs.getDocument({
      data,
      disableRange: true,
      disableStream: true,
      disableAutoFetch: true,
      isEvalSupported: false,
      useSystemFonts: false,
      verbosity: 0,
    });
    const pdf = await task.promise;
    const found = [];
    const seen = new Set();
    let emitted = 0;
    let carry = '';
    const deliver = async (key) => {
      const id = keyId(key);
      if (seen.has(id)) return;
      seen.add(id);
      emitted += 1;
      const stored = detachKey(key);
      if (emitted <= (options.skipKeys || 0)) return;
      if (options.onKey) await options.onKey(stored);
      else found.push(stored);
    };
    for (let pageNumber = 1; pageNumber <= pdf.numPages; pageNumber += 1) {
      throwIfAborted(options.signal);
      options.onProgress?.({ phase: 'pdf', page: pageNumber, pages: pdf.numPages, loaded: data.length, total: data.length });
      const page = await pdf.getPage(pageNumber);
      const content = await page.getTextContent();
      const text = pageText(content);
      for (const key of findPrivateKeysInDocument(`${carry}\n${text}`)) await deliver(key);
      carry = text.slice(-2000);
      page.cleanup();
      await yieldToUi();
    }
    await pdf.destroy();
    return { keys: options.onKey ? [] : found, overflow: 0 };
  } catch (error) {
    if (error?.name === 'AbortError') throw error;
    try { await task?.destroy(); } catch { /* already closed */ }
    throw new FileReadError('pdf', blob.name);
  }
}

export async function extractKeysFromFile(file, options = {}) {
  const name = file.name || 'fișier';
  const extension = fileExtension(name);
  if (DOCUMENT_EXTENSIONS.has(extension)) {
    if (file.size > MAX_DOCUMENT_BYTES) throw new FileReadError('too-big-document', name);
  } else if (file.size > MAX_FILE_BYTES) {
    throw new FileReadError('too-big', name);
  }
  throwIfAborted(options.signal);
  if (extension === 'pdf') return scanPdf(file, options);
  if (extension === 'docx') return scanDocx(file, options);
  if (TEXT_EXTENSIONS.has(extension)) return scanTextBlob(file, options);
  throw new FileReadError('unsupported', name);
}
