/**
 * Reads files the user selected, in chunks, and returns only extracted keys.
 * File bytes are not uploaded, stored, or placed in the page URL.
 */
import { unzipSync } from 'fflate';
import { createKeyBuffer, findPrivateKeysInDocument, dedupeKeys } from './detect.js';

/** Text, CSV, JSON, LOG, MD, and HTML. 1 GiB also accepts a decimal “1 GB” file (10^9 bytes). */
export const MAX_FILE_BYTES = 1024 * 1024 * 1024;
/** PDF and DOCX are opened as a whole, so they stay well below the text cap. */
export const MAX_DOCUMENT_BYTES = 100 * 1024 * 1024;
export const READ_CHUNK_BYTES = 1024 * 1024;
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

async function scanTextBlob(blob, { signal, onProgress }) {
  const head = new Uint8Array(await blob.slice(0, 4).arrayBuffer());
  const decoder = new TextDecoder(decodeEncoding(head), { ignoreBOM: true });
  const buffer = createKeyBuffer();
  await readChunked(blob, {
    signal,
    onProgress,
    onBytes: async (bytes, final) => {
      buffer.push(decoder.decode(bytes, { stream: !final }), final);
    },
  });
  return buffer.finish();
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
  return capKeys({ keys: dedupeKeys([...scanned.keys, ...wrapped]), overflow: scanned.overflow });
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

function capKeys(result) {
  const keys = result.keys.slice(0, 100);
  return {
    keys,
    overflow: result.overflow + Math.max(0, result.keys.length - keys.length),
  };
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
    let carry = '';
    for (let pageNumber = 1; pageNumber <= pdf.numPages; pageNumber += 1) {
      throwIfAborted(options.signal);
      options.onProgress?.({ phase: 'pdf', page: pageNumber, pages: pdf.numPages, loaded: data.length, total: data.length });
      const page = await pdf.getPage(pageNumber);
      const content = await page.getTextContent();
      const text = pageText(content);
      found.push(...findPrivateKeysInDocument(`${carry}\n${text}`));
      carry = text.slice(-2000);
      page.cleanup();
      await yieldToUi();
    }
    await pdf.destroy();
    return { keys: dedupeKeys(found), overflow: 0 };
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
  if (extension === 'pdf') return capKeys(await scanPdf(file, options));
  if (extension === 'docx') return scanDocx(file, options);
  if (TEXT_EXTENSIONS.has(extension)) return capKeys(await scanTextBlob(file, options));
  throw new FileReadError('unsupported', name);
}
