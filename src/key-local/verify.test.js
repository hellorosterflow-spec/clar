import assert from 'node:assert/strict';
import test from 'node:test';
import {
  EVM_CHAINS,
  VERIFY_BATCH,
  buildJsonRpcBatch,
  readJsonRpcBatch,
  selectEvmProbes,
  verifyAddress,
  verifyKey,
} from './verify.js';

const HARDHAT = 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

function hexKey(index) {
  return index.toString(16).padStart(64, '0');
}

function evmKey(hex) {
  return { format: 'evm-hex', hex, token: hex };
}

function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function rpcResult(body, result) {
  const calls = Array.isArray(body) ? body : [body];
  const payload = calls.map((call) => ({ jsonrpc: '2.0', id: call.id, result }));
  return Array.isArray(body) ? json(payload) : json(payload[0]);
}

test('selects the empty-wallet probe from the native balance', () => {
  const ethereum = EVM_CHAINS.find((chain) => chain.id === 'ethereum');
  const bnb = EVM_CHAINS.find((chain) => chain.id === 'bnb');
  assert.equal(selectEvmProbes(ethereum, 0n, null), 'nonce');
  assert.equal(selectEvmProbes(ethereum, 0n, 0n), 'done');
  assert.equal(selectEvmProbes(ethereum, 0n, 2n), 'tokens');
  assert.equal(selectEvmProbes(ethereum, 1n, null), 'tokens');
  assert.equal(selectEvmProbes(bnb, 0n, null), 'done');
  assert.equal(selectEvmProbes(bnb, 5n, null), 'done');
});

test('reads a JSON-RPC batch by id and rejects a non-array payload', () => {
  const body = buildJsonRpcBatch([
    { method: 'eth_getBalance', params: ['0xabc', 'latest'] },
    { method: 'eth_getTransactionCount', params: ['0xdef', 'latest'] },
  ]);
  assert.equal(body.length, 2);
  assert.equal(body[0].id, 1);
  assert.equal(body[1].method, 'eth_getTransactionCount');
  const parsed = readJsonRpcBatch([
    { jsonrpc: '2.0', id: 2, result: '0x2' },
    { jsonrpc: '2.0', id: 1, result: '0x1' },
  ], 2);
  assert.equal(parsed[0].result, '0x1');
  assert.equal(parsed[1].result, '0x2');
  assert.throws(() => readJsonRpcBatch({ error: { message: 'no batch' } }, 2), (error) => error.name === 'BatchRejected');
});

test('empty EVM key checks native balances before nonce and skips token indexing', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const target = String(url);
    if (!init?.body) {
      calls.push({ url: target, method: 'GET' });
      return json([]);
    }
    const body = JSON.parse(init.body);
    const list = Array.isArray(body) ? body : [body];
    for (const call of list) calls.push({ url: target, method: call.method });
    return rpcResult(body, '0x0');
  };
  const outcome = await verifyKey(evmKey(HARDHAT), { enabled: null, fetchImpl });
  assert.equal(outcome.assets.length, 0);
  const balances = calls.filter((call) => call.method === 'eth_getBalance');
  const nonces = calls.filter((call) => call.method === 'eth_getTransactionCount');
  assert.equal(balances.length, EVM_CHAINS.length);
  assert.equal(nonces.length, EVM_CHAINS.filter((chain) => !chain.tokensUnsupported && chain.blockscout).length);
  assert.equal(calls.some((call) => call.method === 'GET'), false);
  const ethereum = calls.filter((call) => call.url.includes('ethereum-rpc.publicnode.com'));
  assert.deepEqual(ethereum.map((call) => call.method), ['eth_getBalance', 'eth_getTransactionCount']);
  const bnb = calls.filter((call) => call.url.includes('bsc-rpc.publicnode.com'));
  assert.deepEqual(bnb.map((call) => call.method), ['eth_getBalance']);
  assert.ok(balances.length + nonces.length < EVM_CHAINS.length * 2);
});

test('positive native balance loads tokens without a nonce prefetch', async () => {
  const methods = [];
  const fetchImpl = async (url, init) => {
    const target = String(url);
    if (!init?.body) {
      methods.push('tokens');
      return json([{
        token: { type: 'ERC-20', name: 'USD Coin', symbol: 'USDC', decimals: 6 },
        value: '1000000',
      }]);
    }
    const body = JSON.parse(init.body);
    methods.push(body.method);
    if (body.method === 'eth_getTransactionCount') {
      throw new Error('nonce is not required once the native balance is positive');
    }
    return json({ jsonrpc: '2.0', id: body.id, result: '0xde0b6b3a7640000' });
  };
  const outcome = await verifyKey(evmKey(HARDHAT), {
    enabled: new Set(['ethereum']),
    fetchImpl,
  });
  assert.deepEqual(methods, ['eth_getBalance', 'tokens']);
  assert.equal(outcome.assets.length, 2);
  assert.equal(outcome.assets[0].symbol, 'ETH');
  assert.equal(outcome.assets[1].symbol, 'USDC');
});

test('zero balance with a positive nonce still loads tokens', async () => {
  const fetchImpl = async (url, init) => {
    if (!init?.body) {
      return json([{
        token: { type: 'ERC-20', name: 'USD Coin', symbol: 'USDC', decimals: 6 },
        value: '1000000',
      }]);
    }
    const body = JSON.parse(init.body);
    const result = body.method === 'eth_getTransactionCount' ? '0x2' : '0x0';
    return json({ jsonrpc: '2.0', id: body.id, result });
  };
  const outcome = await verifyKey(evmKey(HARDHAT), {
    enabled: new Set(['ethereum']),
    fetchImpl,
  });
  assert.equal(outcome.assets.length, 1);
  assert.equal(outcome.assets[0].symbol, 'USDC');
});

test('batches eth_getBalance for the same chain across keys', async () => {
  const bodies = [];
  const fetchImpl = async (url, init) => {
    const body = JSON.parse(init.body);
    bodies.push(body);
    if (Array.isArray(body)) return rpcResult(body, '0x0');
    return json({ jsonrpc: '2.0', id: body.id, result: '0x0' });
  };
  await Promise.all([1, 2].map((index) => verifyKey(evmKey(hexKey(index)), {
    enabled: new Set(['ethereum']),
    fetchImpl,
  })));
  const balanceBatches = bodies.filter((body) => Array.isArray(body)
    && body.every((call) => call.method === 'eth_getBalance'));
  assert.ok(balanceBatches.some((body) => body.length === 2));
  assert.equal(balanceBatches.some((body) => body.some((call) => call.method !== 'eth_getBalance')), false);
});

test('caps a JSON-RPC batch at VERIFY_BATCH', async () => {
  const sizes = [];
  const fetchImpl = async (url, init) => {
    const body = JSON.parse(init.body);
    const list = Array.isArray(body) ? body : [body];
    if (list.every((call) => call.method === 'eth_getBalance')) sizes.push(list.length);
    if (Array.isArray(body)) return rpcResult(body, '0x0');
    return json({ jsonrpc: '2.0', id: body.id, result: '0x0' });
  };
  await Promise.all(Array.from({ length: VERIFY_BATCH + 1 }, (_, index) => verifyKey(evmKey(hexKey(index + 1)), {
    enabled: new Set(['bnb']),
    fetchImpl,
  })));
  assert.ok(sizes.includes(VERIFY_BATCH));
  assert.equal(sizes.some((size) => size > VERIFY_BATCH), false);
});

test('falls back to single JSON-RPC calls when a batch is rejected', async () => {
  const singles = [];
  let batches = 0;
  const fetchImpl = async (url, init) => {
    const body = JSON.parse(init.body);
    if (Array.isArray(body)) {
      batches += 1;
      return json({ error: { message: 'batch not allowed' } });
    }
    singles.push(body.method);
    return json({ jsonrpc: '2.0', id: body.id, result: '0x0' });
  };
  const outcome = await Promise.all([1, 2].map((index) => verifyKey(evmKey(hexKey(index)), {
    enabled: new Set(['bnb']),
    fetchImpl,
  })));
  assert.equal(outcome.every((item) => item.assets.length === 0), true);
  assert.equal(batches, 1);
  assert.deepEqual(singles, ['eth_getBalance', 'eth_getBalance']);
});

test('keeps bitcoin and solana lookups on their own endpoints', async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const target = String(url);
    calls.push({ url: target, method: init?.body ? JSON.parse(init.body).method : 'GET' });
    if (target.includes('mempool.space')) {
      return json({
        chain_stats: { funded_txo_sum: 1000, spent_txo_sum: 0 },
        mempool_stats: { funded_txo_sum: 0, spent_txo_sum: 0 },
      });
    }
    const body = JSON.parse(init.body);
    if (body.method === 'getBalance') return json({ jsonrpc: '2.0', id: body.id, result: { value: 0 } });
    return json({ jsonrpc: '2.0', id: body.id, result: { value: [] } });
  };
  const bitcoin = await verifyAddress('1BoatSLRHtKNngkdXEeobR76b53LETtpyT', 'Bitcoin', { fetchImpl });
  assert.equal(bitcoin.assets[0].symbol, 'BTC');
  const solana = await verifyAddress('So11111111111111111111111111111111111111112', 'Solana', { fetchImpl });
  assert.equal(solana.assets.length, 0);
  assert.equal(calls.some((call) => call.url.includes('mempool.space') && call.method === 'GET'), true);
  assert.equal(calls.some((call) => call.method === 'getBalance'), true);
  assert.equal(calls.some((call) => call.method === 'eth_getBalance'), false);
});
