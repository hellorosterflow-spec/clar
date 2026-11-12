/**
 * Balance checks for addresses the page already derived locally.
 * Same public endpoints as the existing checker. Several keys may be in flight;
 * same-chain JSON-RPC calls are coalesced into one HTTP batch.
 * Nothing here accepts or transmits a private key.
 */
import { deriveKey } from './derive.js';

/** Max JSON-RPC calls in one HTTP batch. Key concurrency lives in the scanner. */
export const VERIFY_BATCH = 20;
const TOKEN_LIMIT = 30;
const RPC_TIMEOUT_MS = 30_000;
const ATTEMPTS = 3;

export const EVM_CHAINS = [
  { id: 'ethereum', name: 'Ethereum', rpc: 'https://ethereum-rpc.publicnode.com', blockscout: 'https://eth.blockscout.com/api/v2', native: 'ETH', decimals: 18 },
  { id: 'base', name: 'Base', rpc: 'https://base-rpc.publicnode.com', blockscout: 'https://base.blockscout.com/api/v2', native: 'ETH', decimals: 18 },
  { id: 'arbitrum', name: 'Arbitrum', rpc: 'https://arbitrum-one-rpc.publicnode.com', blockscout: 'https://arbitrum.blockscout.com/api/v2', native: 'ETH', decimals: 18 },
  { id: 'optimism', name: 'Optimism', rpc: 'https://optimism-rpc.publicnode.com', blockscout: 'https://explorer.optimism.io/api/v2', native: 'ETH', decimals: 18 },
  { id: 'polygon', name: 'Polygon', rpc: 'https://polygon-bor-rpc.publicnode.com', blockscout: 'https://polygon.blockscout.com/api/v2', native: 'POL', decimals: 18 },
  { id: 'bnb', name: 'BNB', rpc: 'https://bsc-rpc.publicnode.com', blockscout: '', native: 'BNB', decimals: 18, tokensUnsupported: true },
];

const BITCOIN = { id: 'bitcoin', name: 'Bitcoin' };
const SOLANA = { id: 'solana', name: 'Solana' };
const MEMPOOL = 'https://mempool.space';
const SOLANA_RPC = 'https://solana-rpc.publicnode.com';

export function formatUnits(value, decimals, digits = 8) {
  try {
    const raw = BigInt(value);
    const negative = raw < 0n;
    const amount = negative ? -raw : raw;
    const places = Number.isFinite(decimals) && decimals >= 0 ? decimals : 18;
    const scale = 10n ** BigInt(places);
    const whole = amount / scale;
    const fraction = amount % scale;
    const sign = negative ? '-' : '';
    if (!fraction) return `${sign}${whole.toString()}`;
    const trimmed = fraction.toString().padStart(places, '0').slice(0, digits).replace(/0+$/, '');
    return trimmed ? `${sign}${whole.toString()}.${trimmed}` : `${sign}${whole.toString()}`;
  } catch {
    return '0';
  }
}

export function balanceIsPositive(value) {
  if (value == null) return false;
  const text = String(value).replace(/,/g, '').trim();
  if (!text || text === '0' || text === '0.0') return false;
  const numeric = Number(text);
  if (Number.isFinite(numeric)) return numeric > 0;
  return !/^0*\.?0*$/.test(text);
}

export function readEnabledNetworks() {
  if (typeof document === 'undefined') return null;
  const buttons = document.querySelectorAll('[data-testid^="toggle-network-"]');
  if (!buttons.length) return null;
  const enabled = new Set();
  for (const button of buttons) {
    if (button.getAttribute('aria-pressed') === 'true') {
      enabled.add(String(button.getAttribute('data-testid') || '').replace('toggle-network-', ''));
    }
  }
  return enabled;
}

function networkAllowed(enabled, id) {
  return !enabled || enabled.has(id);
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      const error = new Error('aborted');
      error.name = 'AbortError';
      reject(error);
    };
    if (signal?.aborted) {
      onAbort();
      return;
    }
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function withTimeout(signal, ms) {
  const timeout = AbortSignal.timeout(ms);
  if (!signal) return timeout;
  if (typeof AbortSignal.any === 'function') return AbortSignal.any([signal, timeout]);
  return signal;
}

async function request(url, init, signal, fetchImpl) {
  const fetchFn = fetchImpl || fetch;
  let lastError;
  for (let attempt = 0; attempt < ATTEMPTS; attempt += 1) {
    try {
      const response = await fetchFn(url, { ...init, signal: withTimeout(signal, RPC_TIMEOUT_MS) });
      if (response.status === 429 || response.status >= 500) {
        if (attempt === ATTEMPTS - 1) return response;
        await sleep(500 * (2 ** attempt), signal);
        continue;
      }
      return response;
    } catch (error) {
      if (signal?.aborted || error?.name === 'AbortError') throw error;
      lastError = error;
      if (attempt === ATTEMPTS - 1) break;
      await sleep(400 * (2 ** attempt), signal);
    }
  }
  throw lastError instanceof Error ? lastError : new Error('Cerere eșuată');
}

/**
 * After the native balance is known, decide the next read.
 * `nonce` stays null until the activity signal is fetched.
 * Empty wallets stop after the balance on chains that cannot index tokens.
 * @returns {'nonce' | 'tokens' | 'done'}
 */
export function selectEvmProbes(chain, balance, nonce) {
  const tokensPossible = !chain?.tokensUnsupported && Boolean(chain?.blockscout);
  if (balance > 0n) return tokensPossible ? 'tokens' : 'done';
  if (!tokensPossible) return 'done';
  if (nonce == null) return 'nonce';
  return nonce > 0n ? 'tokens' : 'done';
}

export function buildJsonRpcBatch(calls) {
  return calls.map((call, index) => ({
    jsonrpc: '2.0',
    id: index + 1,
    method: call.method,
    params: call.params,
  }));
}

export function readJsonRpcBatch(payload, size) {
  if (!Array.isArray(payload)) {
    const error = new Error(payload?.error?.message || 'Batch respins');
    error.name = 'BatchRejected';
    throw error;
  }
  const byId = new Map();
  for (const entry of payload) {
    if (entry && entry.id != null) byId.set(Number(entry.id), entry);
  }
  const results = [];
  for (let index = 0; index < size; index += 1) {
    const entry = byId.get(index + 1);
    if (!entry) {
      results.push({ error: new Error('Răspuns RPC incomplet') });
    } else if (entry.error) {
      results.push({ error: new Error(entry.error.message || 'Răspuns RPC invalid') });
    } else {
      results.push({ result: entry.result });
    }
  }
  return results;
}

const fetchIds = new WeakMap();
let fetchSerial = 0;
const rpcLanes = new Map();

function fetchLaneId(fetchImpl) {
  if (!fetchImpl || fetchImpl === fetch) return 'global';
  let id = fetchIds.get(fetchImpl);
  if (!id) {
    fetchSerial += 1;
    id = `fetch-${fetchSerial}`;
    fetchIds.set(fetchImpl, id);
  }
  return id;
}

function abortError() {
  const error = new Error('aborted');
  error.name = 'AbortError';
  return error;
}

function combinedSignal(items) {
  const signals = [];
  for (const item of items) {
    if (item.signal && !signals.includes(item.signal)) signals.push(item.signal);
  }
  if (!signals.length) return undefined;
  if (signals.length === 1) return signals[0];
  if (typeof AbortSignal.any === 'function') return AbortSignal.any(signals);
  return signals[0];
}

async function rpcOnce(url, method, params, signal, fetchImpl) {
  const response = await request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  }, signal, fetchImpl);
  if (!response.ok) throw new Error(`RPC indisponibil (HTTP ${response.status})`);
  const payload = await response.json();
  if (payload.error) throw new Error(payload.error.message || 'Răspuns RPC invalid');
  return payload.result;
}

async function rpcBatchOnce(url, items, fetchImpl) {
  const response = await request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(buildJsonRpcBatch(items)),
  }, combinedSignal(items), fetchImpl);
  if (!response.ok) {
    if (response.status === 400 || response.status === 413 || response.status === 415) {
      const error = new Error(`RPC indisponibil (HTTP ${response.status})`);
      error.name = 'BatchRejected';
      throw error;
    }
    throw new Error(`RPC indisponibil (HTTP ${response.status})`);
  }
  let payload;
  try {
    payload = await response.json();
  } catch (error) {
    const rejected = new Error('Batch respins');
    rejected.name = 'BatchRejected';
    rejected.cause = error;
    throw rejected;
  }
  return readJsonRpcBatch(payload, items.length);
}

async function deliverRpc(url, items, fetchImpl) {
  const live = items.filter((item) => !item.aborted);
  if (!live.length) return;
  try {
    if (live.length === 1) {
      const result = await rpcOnce(url, live[0].method, live[0].params, live[0].signal, fetchImpl);
      live[0].cleanup?.();
      live[0].resolve(result);
      return;
    }
    const results = await rpcBatchOnce(url, live, fetchImpl);
    live.forEach((item, index) => {
      item.cleanup?.();
      const outcome = results[index];
      if (outcome?.error) item.reject(outcome.error);
      else item.resolve(outcome?.result);
    });
  } catch (error) {
    if (error?.name === 'BatchRejected' && live.length > 1) {
      await Promise.all(live.map(async (item) => {
        try {
          const result = await rpcOnce(url, item.method, item.params, item.signal, fetchImpl);
          item.cleanup?.();
          item.resolve(result);
        } catch (inner) {
          item.cleanup?.();
          item.reject(inner);
        }
      }));
      return;
    }
    for (const item of live) {
      item.cleanup?.();
      item.reject(error);
    }
  }
}

function flushLane(key) {
  const lane = rpcLanes.get(key);
  if (!lane) return;
  if (lane.timer) {
    clearTimeout(lane.timer);
    lane.timer = null;
  }
  const items = lane.items.splice(0, VERIFY_BATCH);
  if (!lane.items.length) rpcLanes.delete(key);
  else if (!lane.timer) lane.timer = setTimeout(() => flushLane(key), 0);
  for (const item of items) {
    if (item.aborted) item.cleanup?.();
  }
  void deliverRpc(lane.url, items, lane.fetchImpl);
}

function enqueueRpc(url, method, params, signal, fetchImpl) {
  if (signal?.aborted) return Promise.reject(abortError());
  const key = `${url}\n${fetchLaneId(fetchImpl)}`;
  let lane = rpcLanes.get(key);
  if (!lane) {
    lane = { url, fetchImpl, items: [], timer: null };
    rpcLanes.set(key, lane);
  }
  return new Promise((resolve, reject) => {
    const item = { method, params, signal, resolve, reject, aborted: false, cleanup: null };
    const onAbort = () => {
      item.aborted = true;
      item.cleanup?.();
      reject(abortError());
    };
    if (signal) {
      signal.addEventListener('abort', onAbort, { once: true });
      item.cleanup = () => signal.removeEventListener('abort', onAbort);
    }
    lane.items.push(item);
    if (lane.items.length >= VERIFY_BATCH) flushLane(key);
    else if (!lane.timer) lane.timer = setTimeout(() => flushLane(key), 0);
  });
}

function rpc(url, method, params, signal, fetchImpl) {
  return enqueueRpc(url, method, params, signal, fetchImpl);
}

async function mapPool(items, limit, task) {
  const queue = items.slice();
  let failure = null;
  const workers = Array.from({ length: Math.min(limit, queue.length) }, async () => {
    while (queue.length && !failure) {
      const item = queue.shift();
      try {
        await task(item);
      } catch (error) {
        failure = error;
        throw error;
      }
    }
  });
  await Promise.all(workers);
}

async function evmAssets(address, chain, signal, fetchImpl) {
  const assets = [];
  const errors = [];
  let balance = 0n;
  try {
    const balanceResult = await rpc(chain.rpc, 'eth_getBalance', [address, 'latest'], signal, fetchImpl);
    balance = BigInt(balanceResult || '0x0');
  } catch (error) {
    if (error?.name === 'AbortError') throw error;
    return { assets, errors: [error instanceof Error ? error.message : 'Nu s-a putut citi soldul nativ.'] };
  }
  if (balance > 0n) {
    assets.push({
      chain: chain.name,
      name: chain.name,
      symbol: chain.native,
      balance: formatUnits(balance, chain.decimals),
    });
  }
  let nonce = null;
  let step = selectEvmProbes(chain, balance, nonce);
  if (step === 'nonce') {
    try {
      const nonceResult = await rpc(chain.rpc, 'eth_getTransactionCount', [address, 'latest'], signal, fetchImpl);
      nonce = BigInt(nonceResult || '0x0');
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      nonce = 0n;
    }
    step = selectEvmProbes(chain, balance, nonce);
  }
  if (step !== 'tokens') return { assets, errors };
  try {
    await sleep(50, signal);
    const response = await request(`${chain.blockscout}/addresses/${address}/token-balances`, {
      headers: { accept: 'application/json' },
    }, signal, fetchImpl);
    if (!response.ok) throw new Error(`Indexatorul de tokenuri nu a răspuns (HTTP ${response.status})`);
    const rows = await response.json();
    if (Array.isArray(rows)) {
      for (const row of rows) {
        if (assets.length >= TOKEN_LIMIT) break;
        if (row?.token?.type !== 'ERC-20') continue;
        if (BigInt(row.value || '0') <= 0n) continue;
        assets.push({
          chain: chain.name,
          name: row.token.name || row.token.symbol || 'Token',
          symbol: row.token.symbol || '—',
          balance: formatUnits(String(row.value), Number(row.token.decimals ?? 18)),
        });
      }
    }
  } catch (error) {
    if (error?.name === 'AbortError') throw error;
    errors.push(error instanceof Error ? error.message : 'Tokenurile nu au putut fi încărcate.');
  }
  return { assets, errors };
}

async function bitcoinAssets(address, signal, fetchImpl) {
  const response = await request(`${MEMPOOL}/api/address/${encodeURIComponent(address)}`, {
    headers: { accept: 'application/json' },
  }, signal, fetchImpl);
  if (!response.ok) throw new Error(`mempool.space nu a răspuns (HTTP ${response.status})`);
  const payload = await response.json();
  const chain = payload.chain_stats || {};
  const mempool = payload.mempool_stats || {};
  const sats = BigInt(chain.funded_txo_sum || 0) - BigInt(chain.spent_txo_sum || 0)
    + BigInt(mempool.funded_txo_sum || 0) - BigInt(mempool.spent_txo_sum || 0);
  if (sats <= 0n) return { assets: [], errors: [] };
  return {
    assets: [{ chain: 'Bitcoin', name: 'Bitcoin', symbol: 'BTC', balance: formatUnits(sats, 8) }],
    errors: [],
  };
}

async function solanaAssets(address, signal, fetchImpl) {
  const lamports = await rpc(SOLANA_RPC, 'getBalance', [address], signal, fetchImpl);
  const amount = Number(lamports?.value ?? lamports ?? 0);
  const assets = [];
  const errors = [];
  if (amount > 0) {
    assets.push({ chain: 'Solana', name: 'Solana', symbol: 'SOL', balance: formatUnits(String(Math.trunc(amount)), 9) });
    try {
      const rows = await rpc(SOLANA_RPC, 'getTokenAccountsByOwner', [
        address,
        { programId: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' },
        { encoding: 'jsonParsed' },
      ], signal, fetchImpl);
      const list = rows?.value;
      if (Array.isArray(list)) {
        for (const item of list) {
          if (assets.length >= TOKEN_LIMIT) break;
          const info = item?.account?.data?.parsed?.info;
          const raw = info?.tokenAmount?.amount || '0';
          if (BigInt(raw) <= 0n) continue;
          const mint = info?.mint || '';
          assets.push({
            chain: 'Solana',
            name: mint ? `SPL ${mint.slice(0, 4)}…${mint.slice(-4)}` : 'Token SPL',
            symbol: 'SPL',
            balance: info?.tokenAmount?.uiAmountString || formatUnits(raw, Number(info?.tokenAmount?.decimals ?? 0)),
          });
        }
      }
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      errors.push(error instanceof Error ? error.message : 'Tokenurile SPL nu sunt disponibile.');
    }
  }
  return { assets, errors };
}

export async function verifyAddress(address, chainName, options = {}) {
  const signal = options.signal;
  const fetchImpl = options.fetchImpl;
  if (chainName === 'Bitcoin') return bitcoinAssets(address, signal, fetchImpl);
  if (chainName === 'Solana') return solanaAssets(address, signal, fetchImpl);
  const chain = EVM_CHAINS.find((item) => item.name === chainName);
  if (!chain) return { assets: [], errors: [`Rețea necunoscută`] };
  return evmAssets(address, chain, signal, fetchImpl);
}

/**
 * Check every derived address of one key.
 * Enabled chains run together so their JSON-RPC calls can share a batch.
 * The scanner may run several keys at once; this function still checks every chain.
 */
export async function verifyKey(key, options = {}) {
  const addresses = deriveKey(key);
  const assets = [];
  const errors = [];
  const enabled = options.enabled === undefined ? readEnabledNetworks() : options.enabled;
  for (const item of addresses) {
    if (options.signal?.aborted) {
      const error = new Error('aborted');
      error.name = 'AbortError';
      throw error;
    }
    const chains = item.chain === 'Bitcoin'
      ? (networkAllowed(enabled, BITCOIN.id) ? [BITCOIN] : [])
      : item.chain === 'Solana'
        ? (networkAllowed(enabled, SOLANA.id) ? [SOLANA] : [])
        : EVM_CHAINS.filter((chain) => networkAllowed(enabled, chain.id));
    const partial = new Array(chains.length);
    await mapPool(chains.map((chain, index) => ({ chain, index })), chains.length, async ({ chain, index }) => {
      try {
        partial[index] = await verifyAddress(item.address, chain.name, options);
      } catch (error) {
        if (error?.name === 'AbortError') throw error;
        partial[index] = {
          assets: [],
          errors: [error instanceof Error ? error.message : 'Verificare eșuată.'],
        };
      }
    });
    for (const result of partial) {
      if (!result) continue;
      assets.push(...result.assets);
      errors.push(...result.errors);
    }
  }
  return {
    addresses,
    assets,
    assetCount: assets.length,
    errors,
  };
}
