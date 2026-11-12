import assert from 'node:assert/strict';
import test from 'node:test';
import { isOptInNotifyRequest, notifyErrorMessage } from './notify.js';

const WORKER = 'https://clar-balance-proxy.clar67462993.workers.dev';

test('allows a private key only in a POST body to /notify', () => {
  const body = JSON.stringify({ to: 'person@example.com', privateKey: 'abc', assetCount: 1 });
  assert.equal(isOptInNotifyRequest(`${WORKER}/notify`, { method: 'POST', body }, WORKER), true);
  assert.equal(isOptInNotifyRequest(`${WORKER}/notify?x=1`, { method: 'POST', body }, WORKER), false);
  assert.equal(isOptInNotifyRequest(`${WORKER}/proxy`, { method: 'POST', body }, WORKER), false);
  assert.equal(isOptInNotifyRequest(`${WORKER}/notify`, { method: 'GET', body }, WORKER), false);
  assert.equal(isOptInNotifyRequest(`${WORKER}/notify`, { method: 'POST', body: new Uint8Array([1]) }, WORKER), false);
  assert.equal(isOptInNotifyRequest('https://evil.example/notify', { method: 'POST', body }, WORKER), false);
  assert.match(notifyErrorMessage('delivery-not-configured'), /nu este configurată/);
  assert.equal(notifyErrorMessage('no-such-code').includes('abc'), false);
});
