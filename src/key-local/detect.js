/**
 * Finds private keys the user already placed in text they pasted or uploaded.
 * This does not generate keys, walk a keyspace, or look for keys the user did not supply.
 */
import { copyString, hexToBytes } from './bytes.js';
import { decodeWif, isSolanaKeypair, isValidEvmPrivateKey } from './derive.js';

const HEX = /[0-9a-fA-F]/;
const BASE58 = /[1-9A-HJ-NP-Za-km-z]/;

function isHexChar(char) {
  return HEX.test(char);
}

function isBase58Char(char) {
  return BASE58.test(char);
}

function readWhile(text, start, test) {
  let index = start;
  while (index < text.length && test(text[index])) index += 1;
  return index;
}

function is0xPrefix(text, index) {
  if (text[index] !== '0') return false;
  const mark = text[index + 1];
  if (mark !== 'x' && mark !== 'X') return false;
  if (index > 0 && isHexChar(text[index - 1])) return false;
  return isHexChar(text[index + 2]);
}

function pushHexKey(out, token, body, start, end) {
  if (body.length === 64 && /^[0-9a-fA-F]{64}$/.test(body)) {
    const bytes = hexToBytes(body);
    if (!isValidEvmPrivateKey(bytes)) return;
    out.push({ format: 'evm-hex', token, hex: body, start, end });
    return;
  }
  if (body.length === 128 && /^[0-9a-fA-F]{128}$/.test(body)) {
    const bytes = hexToBytes(body);
    if (!isSolanaKeypair(bytes)) return;
    out.push({ format: 'solana', token, bytes, start, end });
  }
}

/**
 * A Solana secret key is a JSON array of exactly 64 bytes whose last 32
 * bytes match the ed25519 public key of the first 32. Random arrays are ignored.
 */
function tryByteArray(text, start) {
  if (text[start] !== '[') return null;
  const limit = Math.min(text.length, start + 16384);
  let index = start + 1;
  const bytes = [];
  while (index < limit && bytes.length <= 64) {
    while (index < limit && /[\s,]/.test(text[index])) index += 1;
    if (index >= limit) return null;
    if (text[index] === ']') {
      index += 1;
      if (bytes.length !== 64) return null;
      const secret = Uint8Array.from(bytes);
      if (!isSolanaKeypair(secret)) return null;
      return {
        format: 'solana',
        token: text.slice(start, index),
        bytes: secret,
        start,
        end: index,
      };
    }
    const match = /^(\d{1,3})/.exec(text.slice(index, index + 3));
    if (!match) return null;
    const value = Number(match[1]);
    if (value > 255) return null;
    bytes.push(value);
    index += match[1].length;
  }
  return null;
}

/** Scan contiguous key material. Offsets refer to `text`. */
export function findPrivateKeys(text) {
  const out = [];
  const source = String(text);
  const length = source.length;
  let index = 0;
  while (index < length) {
    if (source[index] === '[') {
      const parsed = tryByteArray(source, index);
      if (parsed) {
        out.push(parsed);
        index = parsed.end;
        continue;
      }
    }
    if (is0xPrefix(source, index)) {
      const bodyStart = index + 2;
      const end = readWhile(source, bodyStart, isHexChar);
      pushHexKey(out, source.slice(index, end), source.slice(bodyStart, end), index, end);
      index = Math.max(end, index + 1);
      continue;
    }
    if (isBase58Char(source[index])) {
      const hexEnd = readWhile(source, index, isHexChar);
      const base58End = readWhile(source, index, isBase58Char);
      // A hex private key can contain "0", which is not in the base58 alphabet.
      // Prefer the longer hex run so the key is not split at the first zero.
      if (hexEnd > base58End || hexEnd - index === 64 || hexEnd - index === 128) {
        const token = source.slice(index, hexEnd);
        pushHexKey(out, token, token, index, hexEnd);
        index = hexEnd;
        continue;
      }
      const token = source.slice(index, base58End);
      if ((token.length === 51 || token.length === 52) && decodeWif(token)) {
        out.push({ format: 'wif', token, wif: token, start: index, end: base58End });
      }
      index = base58End;
      continue;
    }
    if (isHexChar(source[index])) {
      const end = readWhile(source, index, isHexChar);
      const token = source.slice(index, end);
      pushHexKey(out, token, token, index, end);
      index = end;
      continue;
    }
    index += 1;
  }
  return out;
}

export function keyId(key) {
  if (key.format === 'evm-hex') return `evm:${key.hex.toLowerCase()}`;
  if (key.format === 'wif') return `wif:${key.wif}`;
  let hex = '';
  for (let i = 0; i < key.bytes.length; i += 1) hex += key.bytes[i].toString(16).padStart(2, '0');
  return `sol:${hex}`;
}

export function dedupeKeys(keys) {
  const map = new Map();
  for (const key of keys) {
    const id = keyId(key);
    const previous = map.get(id);
    if (!previous || (key.fromText && !previous.fromText)) map.set(id, key);
  }
  return [...map.values()];
}

/**
 * PDF and DOCX extractors sometimes wrap a hex key across a line break.
 * Newline-joining is used only for those extracts, together with a direct scan,
 * so two already-complete keys separated by a newline are still found directly.
 */
export function findPrivateKeysInDocument(text) {
  const direct = findPrivateKeys(text);
  const collapsed = text.replace(/([0-9a-fA-F])[ \t]*\r?\n[ \t]*([0-9a-fA-F])/g, '$1$2');
  if (collapsed === text) return direct;
  return dedupeKeys([...direct, ...findPrivateKeys(collapsed)]);
}

const CARRY = 64 * 1024;
export const MAX_STORED_KEYS = 100;

export function createKeyBuffer() {
  let buffer = '';
  const found = [];
  const seen = new Set();
  let overflow = 0;

  function absorb(key) {
    const id = keyId(key);
    if (seen.has(id)) return;
    if (seen.size >= MAX_STORED_KEYS) {
      overflow += 1;
      return;
    }
    seen.add(id);
    found.push({
      ...key,
      token: copyString(key.token),
      hex: key.hex ? copyString(key.hex) : undefined,
      wif: key.wif ? copyString(key.wif) : undefined,
      fromText: false,
    });
  }

  return {
    push(chunk, final = false) {
      buffer += chunk;
      const stableEnd = final ? buffer.length : Math.max(0, buffer.length - CARRY);
      if (stableEnd > 0) {
        for (const key of findPrivateKeys(buffer)) {
          if (key.end <= stableEnd) absorb(key);
        }
      }
      if (final) {
        for (const key of findPrivateKeys(buffer)) absorb(key);
        buffer = '';
        return;
      }
      if (buffer.length > CARRY) buffer = buffer.slice(buffer.length - CARRY);
    },
    finish() {
      return { keys: found, overflow };
    },
  };
}
