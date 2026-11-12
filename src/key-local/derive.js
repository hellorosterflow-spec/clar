/**
 * Local public-address derivation only.
 * Nothing here broadcasts, signs, or generates keys.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { keccak_256 } from '@noble/hashes/sha3';
import { base58, base58check, bech32 } from '@scure/base';
import { bytesToHex, equalBytes, hexToBytes } from './bytes.js';

const coder = base58check(sha256);

export function isValidEvmPrivateKey(bytes) {
  return bytes.length === 32 && secp256k1.utils.isValidPrivateKey(bytes);
}

export function evmAddressFromPrivateKey(bytes) {
  const uncompressed = secp256k1.getPublicKey(bytes, false);
  const hash = keccak_256(uncompressed.subarray(1));
  const body = bytesToHex(hash.subarray(12));
  const checksum = bytesToHex(keccak_256(new TextEncoder().encode(body)));
  let out = '0x';
  for (let i = 0; i < body.length; i += 1) {
    out += Number.parseInt(checksum[i], 16) >= 8 ? body[i].toUpperCase() : body[i];
  }
  return out;
}

/**
 * Mainnet WIF. Returns null when the checksum, version, or length is wrong.
 * @returns {{ privateKey: Uint8Array, compressed: boolean } | null}
 */
export function decodeWif(wif) {
  if (typeof wif !== 'string' || (wif.length !== 51 && wif.length !== 52)) return null;
  if (!/^[5KL][1-9A-HJ-NP-Za-km-z]+$/.test(wif)) return null;
  let decoded;
  try {
    decoded = coder.decode(wif);
  } catch {
    return null;
  }
  if (decoded[0] !== 0x80) return null;
  if (decoded.length === 33) {
    const privateKey = decoded.subarray(1, 33);
    if (!isValidEvmPrivateKey(privateKey)) return null;
    return { privateKey, compressed: false };
  }
  if (decoded.length === 34 && decoded[33] === 0x01) {
    const privateKey = decoded.subarray(1, 33);
    if (!isValidEvmPrivateKey(privateKey)) return null;
    return { privateKey, compressed: true };
  }
  return null;
}

function hash160(data) {
  return ripemd160(sha256(data));
}

function p2pkh(hash) {
  const payload = new Uint8Array(21);
  payload[0] = 0x00;
  payload.set(hash, 1);
  return coder.encode(payload);
}

function p2wpkh(hash) {
  return bech32.encode('bc', [0, ...bech32.toWords(hash)]);
}

export function isSolanaKeypair(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 64) return false;
  const seed = bytes.subarray(0, 32);
  const embedded = bytes.subarray(32);
  let derived;
  try {
    derived = ed25519.getPublicKey(seed);
  } catch {
    return false;
  }
  return equalBytes(derived, embedded);
}

export function solanaAddressFromKeypair(bytes) {
  return base58.encode(bytes.subarray(32));
}

/**
 * @param {{ format: 'evm-hex' | 'wif' | 'solana', hex?: string, wif?: string, bytes?: Uint8Array }} key
 * @returns {{ chain: 'EVM' | 'Bitcoin' | 'Solana', label: string, address: string }[]}
 */
export function deriveKey(key) {
  if (key.format === 'evm-hex') {
    const bytes = hexToBytes(key.hex);
    if (!isValidEvmPrivateKey(bytes)) return [];
    return [{ chain: 'EVM', label: 'Adresă EVM', address: evmAddressFromPrivateKey(bytes) }];
  }
  if (key.format === 'wif') {
    const decoded = decodeWif(key.wif);
    if (!decoded) return [];
    const pub = secp256k1.getPublicKey(decoded.privateKey, decoded.compressed);
    const hashed = hash160(pub);
    const addresses = [
      {
        chain: 'Bitcoin',
        label: decoded.compressed ? 'Bitcoin P2PKH (comprimată)' : 'Bitcoin P2PKH',
        address: p2pkh(hashed),
      },
    ];
    if (decoded.compressed) {
      addresses.push({ chain: 'Bitcoin', label: 'Bitcoin P2WPKH', address: p2wpkh(hashed) });
    }
    return addresses;
  }
  if (key.format === 'solana') {
    if (!isSolanaKeypair(key.bytes)) return [];
    return [{ chain: 'Solana', label: 'Adresă Solana', address: solanaAddressFromKeypair(key.bytes) }];
  }
  return [];
}
