/**
 * clar-balance-proxy
 *
 * The previous Worker source was not in this repository. /proxy and the simple
 * balance route are kept so a deploy does not drop the live checker. POST /notify
 * is the opt-in email path.
 */
import { handleNotify } from './notify.js';

const ALLOWED_HOSTS = [
  'ethereum-rpc.publicnode.com',
  'base-rpc.publicnode.com',
  'arbitrum-one-rpc.publicnode.com',
  'optimism-rpc.publicnode.com',
  'polygon-bor-rpc.publicnode.com',
  'bsc-rpc.publicnode.com',
  'solana-rpc.publicnode.com',
  'eth.blockscout.com',
  'base.blockscout.com',
  'arbitrum.blockscout.com',
  'polygon.blockscout.com',
  'explorer.optimism.io',
  'mempool.space',
  'api.etherscan.io',
  'api.blockcypher.com',
  'api.mainnet-beta.solana.com',
];

const ALLOWED = new Set(ALLOWED_HOSTS);

const EVM_RPC = {
  eth: 'https://ethereum-rpc.publicnode.com',
  ethereum: 'https://ethereum-rpc.publicnode.com',
  base: 'https://base-rpc.publicnode.com',
  arb: 'https://arbitrum-one-rpc.publicnode.com',
  arbitrum: 'https://arbitrum-one-rpc.publicnode.com',
  op: 'https://optimism-rpc.publicnode.com',
  optimism: 'https://optimism-rpc.publicnode.com',
  polygon: 'https://polygon-bor-rpc.publicnode.com',
  matic: 'https://polygon-bor-rpc.publicnode.com',
  bnb: 'https://bsc-rpc.publicnode.com',
  bsc: 'https://bsc-rpc.publicnode.com',
};

const SUPPORTED = [
  ...Object.keys(EVM_RPC),
  'btc',
  'bitcoin',
  'sol',
  'solana',
  'eth-etherscan',
  'btc-blockcypher',
];

function corsHeaders(extra = {}) {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'content-type, accept',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-max-age': '86400',
    ...extra,
  };
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: corsHeaders({ 'content-type': 'application/json; charset=utf-8' }),
  });
}

function info() {
  return {
    name: 'clar-balance-proxy',
    usage: {
      proxy: 'GET|POST /proxy?url=<https allowlisted upstream>',
      simple: 'GET /?address=<addr>&chain=<eth|base|arb|op|polygon|bnb|btc|sol>',
    },
    allowlistedHosts: ALLOWED_HOSTS,
  };
}

async function handleProxy(request, url) {
  const target = url.searchParams.get('url');
  if (!target) return json({ error: 'Missing url query parameter' }, 400);
  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    return json({ error: 'URL not allowlisted for proxy' }, 403);
  }
  if (parsed.protocol !== 'https:' || !ALLOWED.has(parsed.hostname)) {
    return json({ error: 'URL not allowlisted for proxy' }, 403);
  }
  const headers = new Headers();
  const contentType = request.headers.get('content-type');
  if (contentType) headers.set('content-type', contentType);
  const accept = request.headers.get('accept');
  if (accept) headers.set('accept', accept);
  const init = { method: request.method, headers, redirect: 'follow' };
  if (request.method !== 'GET' && request.method !== 'HEAD') init.body = request.body;
  const upstream = await fetch(parsed.toString(), init);
  const responseHeaders = new Headers(upstream.headers);
  responseHeaders.set('access-control-allow-origin', '*');
  responseHeaders.set('access-control-allow-headers', 'content-type, accept');
  responseHeaders.set('access-control-allow-methods', 'GET, POST, OPTIONS');
  responseHeaders.set('access-control-max-age', '86400');
  responseHeaders.delete('content-encoding');
  responseHeaders.delete('content-length');
  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders,
  });
}

async function handleSimple(url) {
  const address = url.searchParams.get('address');
  if (!address) return json(info(), 200);
  const chain = (url.searchParams.get('chain') || '').toLowerCase();
  if (!SUPPORTED.includes(chain)) return json({ error: 'Unsupported chain', supported: SUPPORTED }, 400);
  if (EVM_RPC[chain]) {
    const rpc = EVM_RPC[chain];
    const upstream = await fetch(rpc, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'eth_getBalance',
        params: [address, 'latest'],
      }),
    });
    const payload = await upstream.json();
    return json({ ...payload, _meta: { chain, rpc } }, upstream.ok ? 200 : upstream.status);
  }
  if (chain === 'btc' || chain === 'bitcoin') {
    const upstream = await fetch(`https://mempool.space/api/address/${encodeURIComponent(address)}`, {
      headers: { accept: 'application/json' },
    });
    const headers = corsHeaders({ 'content-type': upstream.headers.get('content-type') || 'application/json; charset=utf-8' });
    return new Response(upstream.body, { status: upstream.status, headers });
  }
  if (chain === 'sol' || chain === 'solana') {
    const upstream = await fetch('https://solana-rpc.publicnode.com', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getBalance', params: [address] }),
    });
    const headers = corsHeaders({ 'content-type': upstream.headers.get('content-type') || 'application/json; charset=utf-8' });
    return new Response(upstream.body, { status: upstream.status, headers });
  }
  if (chain === 'eth-etherscan') {
    const endpoint = new URL('https://api.etherscan.io/api');
    endpoint.searchParams.set('module', 'account');
    endpoint.searchParams.set('action', 'balance');
    endpoint.searchParams.set('address', address);
    endpoint.searchParams.set('tag', 'latest');
    const upstream = await fetch(endpoint);
    const headers = corsHeaders({ 'content-type': upstream.headers.get('content-type') || 'application/json; charset=utf-8' });
    return new Response(upstream.body, { status: upstream.status, headers });
  }
  const upstream = await fetch(`https://api.blockcypher.com/v1/btc/main/addrs/${encodeURIComponent(address)}/balance`);
  const headers = corsHeaders({ 'content-type': upstream.headers.get('content-type') || 'application/json; charset=utf-8' });
  return new Response(upstream.body, { status: upstream.status, headers });
}

export async function handleFetch(request, env) {
  const url = new URL(request.url);
  if (request.method === 'OPTIONS' && url.pathname !== '/notify') {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }
  if (url.pathname === '/notify') return handleNotify(request, env);
  if (url.pathname === '/proxy') return handleProxy(request, url);
  if (url.pathname === '/' || url.pathname === '') {
    if (request.method === 'GET' || request.method === 'HEAD') return handleSimple(url);
  }
  return json({ error: 'Not found' }, 404);
}

export default {
  async fetch(request, env) {
    return handleFetch(request, env);
  },
};
