/**
 * Reads files the user selected, in chunks, and returns only extracted keys.
 * File bytes are not uploaded, stored, or placed in the page URL.
 */
import { unzipSync } from 'fflate';
import { createKeyBuffer, findPrivateKeysInDocument, dedupeKeys } from './detect.js';

export const MAX_FILE_BYTES = 40 * 1024 * 1024;
const READ_CHUNK = 256 * 1024;
const TEXT_EXTENSIONS = new Set(['txt', 'csv', 'json', 'log', 'md', 'html', 'htm']);

export class FileReadError extends Error {
  constructor(code, fileName) {
    super(code);
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
    const end = Math.min(total, offset + READ_CHUNK);
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
  if (file.size > MAX_FILE_BYTES) throw new FileReadError('too-big', name);
  const extension = fileExtension(name);
  throwIfAborted(options.signal);
  if (extension === 'pdf') return capKeys(await scanPdf(file, options));
  if (extension === 'docx') return scanDocx(file, options);
  if (TEXT_EXTENSIONS.has(extension)) return capKeys(await scanTextBlob(file, options));
  throw new FileReadError('unsupported', name);
}
