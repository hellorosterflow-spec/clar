import assert from 'node:assert/strict';
import test from 'node:test';
import { createMemoryStore } from './store.js';
import {
  classifyLine,
  estimateRemainingKeys,
  rememberFundedKey,
  scanTextFile,
} from './scan.js';

const HARDHAT = 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

function hexKey(index) {
  return index.toString(16).padStart(64, '0');
}

function csvFile(lines, name = 'chei.csv') {
  return new File([lines.join('\n') + '\n'], name, { type: 'text/csv' });
}

test('classifies a header, a csv key, and a broken row', () => {
  assert.equal(classifyLine('id,private_key_hex').kind, 'header');
  assert.equal(classifyLine('').kind, 'empty');
  assert.equal(classifyLine('not-a-key').kind, 'skip');
  const row = classifyLine(`00000042,${HARDHAT}`);
  assert.equal(row.kind, 'keys');
  assert.equal(row.rowId, '00000042');
  assert.equal(row.keys.length, 1);
  assert.equal(row.keys[0].hex.toLowerCase(), HARDHAT);
});

test('estimates remaining keys from the byte position', () => {
  assert.equal(estimateRemainingKeys(1000, 0, 0), null);
  assert.equal(estimateRemainingKeys(1000, 250, 25), 75);
  assert.equal(estimateRemainingKeys(1000, 1000, 10), 0);
});

test('checks every csv key in order, including duplicates past the old caps', async () => {
  const lines = ['id,private_key_hex', 'not-a-key'];
  for (let index = 1; index <= 25; index += 1) lines.push(`${String(index).padStart(8, '0')},${hexKey(index)}`);
  lines.push(`00000099,${hexKey(1)}`);
  const seen = [];
  const store = createMemoryStore();
  const outcome = await scanTextFile(csvFile(lines), {
    store,
    enabled: null,
    verifyKey: async (key) => {
      seen.push(key.hex.toLowerCase());
      return { addresses: [], assets: [], assetCount: 0, errors: [] };
    },
  });
  assert.equal(outcome.status, 'done');
  assert.equal(seen.length, 26);
  assert.deepEqual(seen.slice(0, 3), [hexKey(1), hexKey(2), hexKey(3)]);
  assert.equal(seen.at(-1), hexKey(1));
  assert.equal(outcome.progress.skipped, 1);
  assert.equal(outcome.progress.verified, 26);
  assert.equal(outcome.progress.funded, 0);
  assert.equal(outcome.progress.lastId, '00000099');
  const saved = await store.getProgress(outcome.progress.id);
  assert.equal(JSON.stringify(saved).includes(hexKey(1)), false);
  assert.equal(JSON.stringify(saved).includes(HARDHAT), false);
});

test('resumes after an abort and can restart from the beginning', async () => {
  const first = hexKey(1);
  const second = hexKey(2);
  const third = hexKey(3);
  const file = csvFile([
    'id,private_key_hex',
    `00000001,${first}`,
    `00000002,${second}`,
    `00000003,${third}`,
  ]);
  const store = createMemoryStore();
  const controller = new AbortController();
  let calls = 0;
  const stopped = await scanTextFile(file, {
    store,
    signal: controller.signal,
    enabled: null,
    verifyKey: async (key) => {
      calls += 1;
      if (key.hex.toLowerCase() === second) {
        controller.abort();
        const error = new Error('aborted');
        error.name = 'AbortError';
        throw error;
      }
      return { addresses: [], assets: [], assetCount: 0, errors: [] };
    },
  });
  assert.equal(stopped.status, 'paused');
  assert.equal(stopped.progress.verified, 1);
  assert.equal(stopped.progress.lastId, '00000001');

  const resumed = [];
  const continued = await scanTextFile(file, {
    store,
    enabled: null,
    verifyKey: async (key) => {
      resumed.push(key.hex.toLowerCase());
      return { addresses: [], assets: [], assetCount: 0, errors: [] };
    },
  });
  assert.equal(continued.status, 'done');
  assert.deepEqual(resumed, [second, third]);

  const again = await scanTextFile(file, {
    store,
    startOver: true,
    enabled: null,
    verifyKey: async () => ({ addresses: [], assets: [], assetCount: 0, errors: [] }),
  });
  assert.equal(again.status, 'done');
  assert.equal(again.progress.verified, 3);
  const repeat = await scanTextFile(file, { store, enabled: null, verifyKey: async () => { throw new Error('should not run'); } });
  assert.equal(repeat.status, 'already-done');
});

test('keeps a funded key in history when email fails, and does not email twice', async () => {
  const secret = hexKey(4);
  const file = csvFile([`00000004,${secret}`], 'one.csv');
  const store = createMemoryStore();
  await store.putSettings({ email: 'person@example.com', enabled: true });
  let sends = 0;
  const outcome = await scanTextFile(file, {
    store,
    enabled: null,
    notify: async () => {
      sends += 1;
      throw new Error('delivery-failed');
    },
    verifyKey: async () => ({
      addresses: [{ chain: 'EVM', label: 'Adresă EVM', address: '0xabc' }],
      assets: [{ chain: 'Ethereum', name: 'Ethereum', symbol: 'ETH', balance: '1' }],
      assetCount: 1,
      errors: [],
    }),
  });
  assert.equal(outcome.status, 'done');
  assert.equal(outcome.progress.funded, 1);
  const [entry] = await store.getHistory();
  assert.equal(entry.privateKey, secret);
  assert.equal(entry.assetCount, 1);
  assert.equal(entry.emailStatus, 'failed');
  assert.equal(entry.emailError.includes(secret), false);
  assert.equal(sends, 1);

  await store.markNotified(await (async () => {
    const { digestHex } = await import('./store.js');
    return digestHex(secret);
  })());
  const duplicate = await rememberFundedKey({
    key: { format: 'evm-hex', hex: secret, token: secret },
    result: {
      addresses: [{ chain: 'EVM', label: 'Adresă EVM', address: '0xabc' }],
      assets: [{ chain: 'Ethereum', name: 'Ethereum', symbol: 'ETH', balance: '1' }],
    },
    store,
    notify: async () => { sends += 1; },
    settings: { email: 'person@example.com', enabled: true },
  });
  assert.equal(duplicate.emailStatus, 'duplicate');
  assert.equal(sends, 1);
});
