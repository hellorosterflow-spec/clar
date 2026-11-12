/**
 * Opt-in email for a funded key. The address comes from the visitor.
 * Nothing here chooses a recipient on their behalf.
 */

const ERRORS = {
  'delivery-not-configured': 'Trimiterea de email nu este configurată pe server. Istoricul local a fost salvat.',
  'delivery-failed': 'Serviciul de email a refuzat mesajul. Istoricul local a fost salvat.',
  'no-funds': 'Serverul nu a confirmat fonduri, așa că emailul nu a fost trimis. Istoricul local a fost salvat.',
  'rate-limited': 'Prea multe emailuri într-un interval scurt. Istoricul local a fost salvat.',
  'invalid-email': 'Adresa de email nu este validă. Istoricul local a fost salvat.',
  'invalid-key': 'Cheia nu a putut fi citită pentru email. Istoricul local a fost salvat.',
  forbidden: 'Serverul a refuzat trimiterea din acest site. Istoricul local a fost salvat.',
  'check-failed': 'Verificarea de pe server a eșuat, așa că emailul nu a fost trimis. Istoricul local a fost salvat.',
};

export function isOptInNotifyRequest(url, init, workerBase) {
  const worker = String(workerBase || '').trim().replace(/\/+$/, '');
  if (!worker) return false;
  let parsed;
  try {
    parsed = new URL(url, 'https://hellorosterflow-spec.github.io');
  } catch {
    return false;
  }
  let expected;
  try {
    expected = new URL(`${worker}/notify`);
  } catch {
    return false;
  }
  if (parsed.origin !== expected.origin) return false;
  const path = parsed.pathname.replace(/\/+$/, '') || '/';
  const expectedPath = expected.pathname.replace(/\/+$/, '') || '/';
  if (path !== expectedPath) return false;
  if (parsed.search || parsed.hash) return false;
  if (String(init?.method || 'GET').toUpperCase() !== 'POST') return false;
  return typeof init?.body === 'string';
}

export function notifyErrorMessage(code) {
  return ERRORS[code] || 'Emailul nu a putut fi trimis. Istoricul local a fost salvat.';
}

export async function sendFundedNotice({ to, privateKey, assetCount, assets, addresses, signal, workerBase, fetchImpl }) {
  const worker = String(workerBase || (typeof window !== 'undefined' ? window.CLAR_WORKER_URL : '') || '')
    .trim()
    .replace(/\/+$/, '');
  if (!worker) {
    const error = new Error(notifyErrorMessage('delivery-not-configured'));
    error.code = 'delivery-not-configured';
    throw error;
  }
  const fetchFn = fetchImpl || fetch;
  const response = await fetchFn(`${worker}/notify`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      to,
      privateKey,
      assetCount,
      assets,
      addresses,
    }),
    signal,
  });
  let payload = {};
  try {
    payload = await response.json();
  } catch {
    payload = {};
  }
  if (!response.ok || payload.ok === false) {
    const code = typeof payload.error === 'string' && ERRORS[payload.error] ? payload.error : 'delivery-failed';
    const error = new Error(notifyErrorMessage(code));
    error.code = code;
    throw error;
  }
  return payload;
}
