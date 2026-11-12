/**
 * Turns pasted text (and keys already extracted from a file) into the
 * public identifiers the existing checker understands.
 * The checker limit matches `Ge` in assets/index.js.
 */
import { bytesToHex } from './bytes.js';
import { deriveKey } from './derive.js';
import { dedupeKeys, findPrivateKeys, keyId } from './detect.js';

export const IDENTIFIER_LIMIT = 20;

const EVM_ADDRESS = /^0x[a-fA-F0-9]{40}$/;
const TX_HASH = /^(?:0x)?[a-fA-F0-9]{64}$/;
const BITCOIN_ADDRESS = /^(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/i;
const SOLANA_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

export function isExistingIdentifier(line) {
  return EVM_ADDRESS.test(line) || TX_HASH.test(line) || BITCOIN_ADDRESS.test(line) || SOLANA_ADDRESS.test(line);
}

export function maskKey(key) {
  if (key.format === 'evm-hex') {
    const body = key.hex.toLowerCase();
    return `0x${body.slice(0, 4)}…${body.slice(-4)}`;
  }
  if (key.format === 'wif') return `${key.wif.slice(0, 2)}…${key.wif.slice(-4)}`;
  const hex = bytesToHex(key.bytes);
  return `${hex.slice(0, 4)}…${hex.slice(-4)}`;
}

export function secretVariants(key) {
  const variants = new Set();
  const add = (value) => {
    if (typeof value === 'string' && value.length >= 32) variants.add(value);
  };
  add(key.token);
  if (key.format === 'evm-hex') {
    const raw = key.hex;
    const lower = raw.toLowerCase();
    const upper = raw.toUpperCase();
    for (const body of new Set([raw, lower, upper])) {
      add(body);
      add(`0x${body}`);
      add(`0X${body}`);
    }
  } else if (key.format === 'wif') {
    add(key.wif);
  } else if (key.format === 'solana' && key.bytes) {
    const hex = bytesToHex(key.bytes);
    add(hex);
    add(`0x${hex}`);
    add(`0X${hex}`);
    add(JSON.stringify(Array.from(key.bytes)));
    add(key.token);
  }
  return [...variants];
}

function cleanFragment(value) {
  return value.replace(/^[\s"'`,;:()[\]{}<>]+|[\s"'`,;:()[\]{}<>]+$/g, '').trim();
}

function lineKey(line) {
  return EVM_ADDRESS.test(line) ? `evm:${line.toLowerCase()}` : `raw:${line}`;
}

/**
 * @param {string} text textarea contents
 * @param {object[]} [extraKeys] keys already extracted from a file; never echoed back
 */
export function planCheck(text, extraKeys = []) {
  const kept = [];
  const hashEchoes = [];
  const found = [];

  for (const line of String(text ?? '').split(/\r?\n/)) {
    const keys = findPrivateKeys(line).map((key) => ({ ...key, fromText: true }));
    if (!keys.length) {
      const trimmed = line.trim();
      if (trimmed) kept.push(trimmed);
      continue;
    }
    let rest = line;
    for (const key of [...keys].sort((a, b) => b.start - a.start)) {
      if (key.format === 'evm-hex' && TX_HASH.test(key.token)) hashEchoes.push(key.token);
      rest = `${rest.slice(0, key.start)} ${rest.slice(key.end)}`;
    }
    const removed = new Set(keys.map((key) => key.token));
    for (const piece of rest.split(/\s+/)) {
      const clean = cleanFragment(piece);
      if (!clean || removed.has(clean) || !isExistingIdentifier(clean)) continue;
      kept.push(clean);
    }
    found.push(...keys);
  }

  for (const key of extraKeys) found.push({ ...key, fromText: Boolean(key.fromText) });

  const unique = dedupeKeys(found).filter((key) => deriveKey(key).length > 0);
  if (!unique.length) return { intercept: false };

  const entries = unique.map((key) => ({
    id: keyId(key),
    format: key.format,
    mask: maskKey(key),
    fromText: Boolean(key.fromText),
    addresses: deriveKey(key),
  }));

  const derivedLines = [];
  const derivedIds = new Set();
  for (const entry of entries) {
    for (const item of entry.addresses) {
      const id = item.chain === 'EVM' ? item.address.toLowerCase() : item.address;
      if (derivedIds.has(id)) continue;
      derivedIds.add(id);
      derivedLines.push(item.address);
    }
  }

  const keptLines = [];
  const seenKept = new Set();
  for (const line of kept) {
    const id = lineKey(line);
    if (seenKept.has(id)) continue;
    seenKept.add(id);
    keptLines.push(line);
  }

  const ordered = [
    ...keptLines.map((line) => ({ line, kind: 'kept' })),
    ...derivedLines.map((line) => ({ line, kind: 'derived' })),
    ...hashEchoes.map((line) => ({ line, kind: 'hash' })),
  ];

  const submission = [];
  const seen = new Set();
  let keptOmitted = 0;
  let derivedOmitted = 0;
  for (const item of ordered) {
    if (seen.has(item.line)) continue;
    if (submission.length >= IDENTIFIER_LIMIT) {
      if (item.kind === 'kept') keptOmitted += 1;
      if (item.kind === 'derived') derivedOmitted += 1;
      continue;
    }
    seen.add(item.line);
    submission.push(item.line);
  }

  const included = new Set(submission);
  const secrets = [];
  const secretMasks = [];
  for (const key of unique) {
    const mask = maskKey(key);
    for (const secret of secretVariants(key)) {
      secrets.push(secret);
      secretMasks.push({ secret, mask });
    }
  }
  const secretSet = new Set(secrets);
  const maskedText = submission.filter((line) => !secretSet.has(line)).join('\n');
  const checkedDerived = derivedLines.filter((line) => included.has(line)).length;

  return {
    intercept: true,
    submissionText: submission.join('\n'),
    maskedText,
    entries: entries.map((entry) => ({
      ...entry,
      addresses: entry.addresses.map((item) => ({
        ...item,
        included: included.has(item.address),
      })),
    })),
    foundCount: unique.length,
    derivedCount: derivedLines.length,
    checkedCount: checkedDerived,
    derivedOmitted,
    keptOmitted,
    hashEchoCount: submission.filter((line) => hashEchoes.includes(line)).length,
    secrets: secretMasks,
  };
}
