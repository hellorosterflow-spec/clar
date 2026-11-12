import assert from 'node:assert/strict';
import test from 'node:test';
import { handleFetch } from './index.js';
import { resetNotifyLimits } from './notify.js';

const ORIGIN = 'https://hellorosterflow-spec.github.io';
const WORKER = 'https://clar-balance-proxy.clar67462993.workers.dev';
const SECRET = 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

function notifyRequest(body, origin = ORIGIN) {
  return new Request(`${WORKER}/notify`, {
    method: 'POST',
    headers: {
      origin,
      'content-type': 'application/json',
      'cf-connecting-ip': '203.0.113.10',
    },
    body: JSON.stringify(body),
  });
}

test('proxy keeps the allowlist and does not require a notify secret', async () => {
  resetNotifyLimits();
  const missing = await handleFetch(new Request(`${WORKER}/proxy`), {});
  assert.equal(missing.status, 400);
  assert.deepEqual(await missing.json(), { error: 'Missing url query parameter' });

  let called = false;
  const original = globalThis.fetch;
  globalThis.fetch = async () => {
    called = true;
    return new Response('no');
  };
  try {
    const blocked = await handleFetch(new Request(`${WORKER}/proxy?url=${encodeURIComponent('https://example.com')}`), {});
    assert.equal(blocked.status, 403);
    assert.equal(called, false);
    const info = await handleFetch(new Request(`${WORKER}/`), {});
    const payload = await info.json();
    assert.equal(payload.name, 'clar-balance-proxy');
    assert.ok(payload.allowlistedHosts.includes('ethereum-rpc.publicnode.com'));
  } finally {
    globalThis.fetch = original;
  }
});

test('refuses notify from other origins and without funds', async () => {
  resetNotifyLimits();
  const logs = [];
  const originalLog = console.log;
  const originalError = console.error;
  const originalFetch = globalThis.fetch;
  console.log = (...args) => logs.push(args.join(' '));
  console.error = (...args) => logs.push(args.join(' '));
  let resend = 0;
  globalThis.fetch = async (url) => {
    const target = String(url);
    if (target.includes('api.resend.com')) {
      resend += 1;
      return new Response('{}', { status: 200 });
    }
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x0' });
    return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
  };
  try {
    const foreign = await handleFetch(notifyRequest({ to: 'person@example.com', privateKey: SECRET, assetCount: 1 }, 'https://evil.example'), {
      RESEND_API_KEY: 'test-key',
      RESEND_FROM: 'Key Screener <alerts@example.com>',
    });
    assert.equal(foreign.status, 403);
    const empty = await handleFetch(notifyRequest({ to: 'person@example.com', privateKey: SECRET, assetCount: 1 }), {
      RESEND_API_KEY: 'test-key',
      RESEND_FROM: 'Key Screener <alerts@example.com>',
    });
    assert.equal(empty.status, 422);
    assert.equal((await empty.json()).error, 'no-funds');
    assert.equal(resend, 0);
    assert.equal(logs.some((line) => line.includes(SECRET)), false);
  } finally {
    console.log = originalLog;
    console.error = originalError;
    globalThis.fetch = originalFetch;
  }
});

test('sends only after the worker sees funds, and does not log the key', async () => {
  resetNotifyLimits();
  const logs = [];
  const originalLog = console.log;
  const originalError = console.error;
  const originalFetch = globalThis.fetch;
  console.log = (...args) => logs.push(args.join(' '));
  console.error = (...args) => logs.push(args.join(' '));
  const sent = [];
  const cache = new Map();
  globalThis.fetch = async (url, init) => {
    const target = String(url);
    if (target.includes('api.resend.com')) {
      sent.push(JSON.parse(init.body));
      return new Response(JSON.stringify({ id: 'email_1' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const requestBody = init?.body ? JSON.parse(init.body) : {};
    if (target.includes('token-balances')) {
      return new Response('[]', { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (requestBody.method === 'eth_getTransactionCount') {
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x0' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    assert.equal(String(requestBody.params || '').includes(SECRET), false);
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0xde0b6b3a7640000' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  const env = {
    RESEND_API_KEY: 'test-key',
    RESEND_FROM: 'Key Screener <alerts@example.com>',
    NOTIFY_CACHE: cache,
  };
  try {
    const response = await handleFetch(notifyRequest({
      to: 'person@example.com',
      privateKey: SECRET,
      assetCount: 1,
      assets: [{ chain: 'Fake', symbol: 'NO', balance: '9' }],
    }), env);
    assert.equal(response.status, 200);
    assert.equal(sent.length, 1);
    assert.deepEqual(sent[0].to, ['person@example.com']);
    assert.equal(sent[0].text.includes(SECRET), true);
    assert.match(sent[0].text, /Număr de active: [1-9]/);
    assert.equal(sent[0].text.includes('Fake'), false);
    assert.equal(logs.some((line) => line.includes(SECRET)), false);
    assert.equal(logs.some((line) => line.includes('person@example.com')), false);

    const again = await handleFetch(notifyRequest({
      to: 'person@example.com',
      privateKey: SECRET,
      assetCount: 1,
    }), env);
    assert.equal((await again.json()).duplicate, true);
    assert.equal(sent.length, 1);
  } finally {
    console.log = originalLog;
    console.error = originalError;
    globalThis.fetch = originalFetch;
  }
});

test('rate limits notify posts', async () => {
  resetNotifyLimits();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error('upstream should not be called');
  };
  try {
    for (let index = 0; index < 10; index += 1) {
      const response = await handleFetch(notifyRequest({ to: 'not-an-email', privateKey: SECRET, assetCount: 1 }), {});
      assert.equal(response.status, 400);
    }
    const limited = await handleFetch(notifyRequest({ to: 'person@example.com', privateKey: SECRET, assetCount: 1 }), {});
    assert.equal(limited.status, 429);
    assert.equal((await limited.json()).error, 'rate-limited');
  } finally {
    globalThis.fetch = originalFetch;
    resetNotifyLimits();
  }
});

test('reports missing email configuration without sending', async () => {
  resetNotifyLimits();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (String(url).includes('api.resend.com')) throw new Error('should not send');
    const requestBody = init?.body ? JSON.parse(init.body) : {};
    if (String(url).includes('token-balances')) return new Response('[]', { status: 200 });
    if (requestBody.method === 'eth_getTransactionCount') {
      return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x0' }), { status: 200 });
    }
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: '0x1' }), { status: 200 });
  };
  try {
    const response = await handleFetch(notifyRequest({ to: 'person@example.com', privateKey: SECRET, assetCount: 1 }), {});
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error, 'delivery-not-configured');
  } finally {
    globalThis.fetch = originalFetch;
    resetNotifyLimits();
  }
});
