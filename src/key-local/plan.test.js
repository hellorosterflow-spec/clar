import assert from 'node:assert/strict';
import test from 'node:test';
import { planCheck } from './plan.js';
import { containsSecret, redact, registerSecrets, clearRegisteredSecrets } from './privacy.js';

const HARDHAT = 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const ADDRESS = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

test('leaves a public address and an all-zero hash on the existing path', () => {
  assert.equal(planCheck('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266').intercept, false);
  assert.equal(planCheck(`bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`).intercept, false);
  assert.equal(planCheck(`0x${'00'.repeat(32)}`).intercept, false);
  assert.equal(planCheck('not-a-key').intercept, false);
});

test('plans a pasted EVM key as a local address plus the existing hash classification', () => {
  const plan = planCheck(`0x${HARDHAT}`);
  assert.equal(plan.intercept, true);
  assert.equal(plan.foundCount, 1);
  assert.match(plan.submissionText, new RegExp(ADDRESS));
  assert.match(plan.submissionText, new RegExp(HARDHAT));
  assert.equal(plan.maskedText.includes(HARDHAT), false);
  assert.match(plan.maskedText, new RegExp(ADDRESS));
  assert.equal(plan.entries[0].mask.includes(HARDHAT), false);
  assert.equal(plan.entries[0].addresses[0].address, ADDRESS);
});

test('keeps a typed public address beside a derived one', () => {
  const plan = planCheck(`0x0000000000000000000000000000000000000001\n${HARDHAT}`);
  assert.equal(plan.intercept, true);
  assert.match(plan.submissionText, /0x0000000000000000000000000000000000000001/);
  assert.match(plan.submissionText, new RegExp(ADDRESS));
  assert.equal(plan.maskedText.includes(HARDHAT), false);
});

test('file keys contribute addresses without echoing the secret', () => {
  const plan = planCheck('0x0000000000000000000000000000000000000001', [{
    format: 'evm-hex',
    hex: HARDHAT,
    token: HARDHAT,
    fromText: false,
  }]);
  assert.equal(plan.intercept, true);
  assert.match(plan.submissionText, new RegExp(ADDRESS));
  assert.equal(plan.submissionText.includes(HARDHAT), false);
  assert.equal(plan.hashEchoCount, 0);
});

test('redacts registered secrets and ignores public addresses', () => {
  clearRegisteredSecrets();
  const plan = planCheck(HARDHAT);
  registerSecrets(plan.secrets);
  assert.equal(containsSecret(`https://example.test/tx/${HARDHAT}`), true);
  assert.equal(containsSecret(`https://example.test/address/${ADDRESS}`), false);
  const redacted = redact(`{"k":"${HARDHAT}"}`);
  assert.equal(redacted.includes(HARDHAT), false);
  assert.match(redacted, /0xac09…ff80/);
  clearRegisteredSecrets();
});
