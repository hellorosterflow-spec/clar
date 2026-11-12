import assert from 'node:assert/strict';
import test from 'node:test';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from './bytes.js';
import { createKeyBuffer, findPrivateKeys, findPrivateKeysInDocument } from './detect.js';

const HARDHAT = 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

function solanaBytes() {
  const seed = new Uint8Array(32).fill(9);
  const pub = ed25519.getPublicKey(seed);
  const bytes = new Uint8Array(64);
  bytes.set(seed, 0);
  bytes.set(pub, 32);
  return bytes;
}

test('detects EVM hex with and without 0x and ignores addresses', () => {
  const text = [
    `prefix 0x${HARDHAT} suffix`,
    HARDHAT.toUpperCase(),
    '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    `0x${'ab'.repeat(70)}`,
    `0x${'00'.repeat(32)}`,
  ].join('\n');
  const found = findPrivateKeys(text);
  assert.equal(found.length, 2);
  assert.equal(found[0].hex.toLowerCase(), HARDHAT);
  assert.equal(found[0].token, `0x${HARDHAT}`);
  assert.equal(found[1].hex.toLowerCase(), HARDHAT);
});

test('does not treat a Solana keypair hex string as an EVM key', () => {
  const hex = bytesToHex(solanaBytes());
  const found = findPrivateKeys(`key ${hex} end`);
  assert.equal(found.length, 1);
  assert.equal(found[0].format, 'solana');
});

test('detects a Solana JSON byte array and a Bitcoin WIF', () => {
  const bytes = solanaBytes();
  const json = `[\n  ${Array.from(bytes).join(', ')}\n]`;
  const text = `backup ${json}\nWIF KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn done`;
  const found = findPrivateKeys(text);
  assert.deepEqual(found.map((key) => key.format).sort(), ['solana', 'wif']);
});

test('joins a hex key wrapped across a newline without dropping separate keys', () => {
  const wrapped = `${HARDHAT.slice(0, 20)}\n${HARDHAT.slice(20)}`;
  const other = `0x${'11'.repeat(32)}`;
  const found = findPrivateKeysInDocument(`${wrapped}\n--\n${other}`);
  const hexes = found.filter((key) => key.format === 'evm-hex').map((key) => key.hex.toLowerCase());
  assert.ok(hexes.includes(HARDHAT));
  assert.ok(hexes.includes('11'.repeat(32)));
});

test('keeps a key that spans a read chunk', () => {
  const token = `0x${HARDHAT}`;
  const head = '.'.repeat((64 * 1024) + 50);
  const buffer = createKeyBuffer();
  buffer.push(head + token.slice(0, 12), false);
  buffer.push(token.slice(12) + '\n', true);
  const { keys } = buffer.finish();
  assert.equal(keys.length, 1);
  assert.equal(keys[0].hex.toLowerCase(), HARDHAT);
});
