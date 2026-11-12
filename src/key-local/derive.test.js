import assert from 'node:assert/strict';
import test from 'node:test';
import { ed25519 } from '@noble/curves/ed25519';
import { base58 } from '@scure/base';
import { bytesToHex } from './bytes.js';
import { deriveKey, isSolanaKeypair } from './derive.js';

const HARDHAT = 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const HARDHAT_ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

test('derives the well-known Hardhat EVM address', () => {
  const [address] = deriveKey({ format: 'evm-hex', hex: HARDHAT });
  assert.equal(address.address, HARDHAT_ADDRESS);
  assert.equal(address.chain, 'EVM');
});

test('derives compressed Bitcoin P2PKH and P2WPKH for private key 1', () => {
  const addresses = deriveKey({
    format: 'wif',
    wif: 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn',
  });
  assert.deepEqual(addresses.map((item) => item.address), [
    '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH',
    'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
  ]);
});

test('derives only P2PKH for an uncompressed WIF', () => {
  const addresses = deriveKey({
    format: 'wif',
    wif: '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf',
  });
  assert.deepEqual(addresses.map((item) => item.address), [
    '1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm',
  ]);
});

test('derives a Solana address from a matching 64-byte keypair', () => {
  const seed = new Uint8Array(32).fill(7);
  const pub = ed25519.getPublicKey(seed);
  const bytes = new Uint8Array(64);
  bytes.set(seed, 0);
  bytes.set(pub, 32);
  assert.equal(isSolanaKeypair(bytes), true);
  const [address] = deriveKey({ format: 'solana', bytes });
  assert.equal(address.address, base58.encode(pub));
  const tampered = new Uint8Array(bytes);
  tampered[63] ^= 1;
  assert.equal(isSolanaKeypair(tampered), false);
  assert.equal(deriveKey({ format: 'solana', bytes: tampered }).length, 0);
  assert.equal(bytesToHex(bytes).length, 128);
});
