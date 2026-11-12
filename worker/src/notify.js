/**
 * Opt-in funded-key email. The recipient is whatever address this request
 * names. There is no default recipient. Private keys are not logged or stored.
 */
import { findPrivateKeys } from '../../src/key-local/detect.js';
import { verifyKey } from '../../src/key-local/verify.js';

export const PAGES_ORIGIN = 'https://hellorosterflow-spec.github.io';
export const NOTIFY_WINDOW_MS = 10 * 60 * 1000;
export const NOTIFY_DAY_MS = 24 * 60 * 60 * 1000;
export const NOTIFY_MAX_WINDOW = 10;
export const NOTIFY_MAX_DAY = 40;
const MAX_BODY = 12_000;

const hits = new Map();

export function resetNotifyLimits() {
  hits.clear();
}

export function allowNotify(ip, now = Date.now()) {
  const key = ip || 'unknown';
  const list = (hits.get(key) || []).filter((time) => now - time < NOTIFY_DAY_MS);
  const recent = list.filter((time) => now - time < NOTIFY_WINDOW_MS);
  if (recent.length >= NOTIFY_MAX_WINDOW || list.length >= NOTIFY_MAX_DAY) {
    hits.set(key, list);
    return false;
  }
  list.push(now);
  hits.set(key, list);
  if (hits.size > 5000) hits.delete(hits.keys().next().value);
  return true;
}

function canonicalSecret(key) {
  if (key.format === 'evm-hex') return String(key.hex || '').toLowerCase();
  if (key.format === 'wif') return String(key.wif || '');
  let hex = '';
  const bytes = key.bytes || [];
  for (let index = 0; index < bytes.length; index += 1) {
    hex += bytes[index].toString(16).padStart(2, '0');
  }
  return hex;
}

function validEmail(value) {
  if (typeof value !== 'string') return false;
  const email = value.trim();
  if (email.length < 6 || email.length > 254) return false;
  if (/[\s,;<>]/.test(email)) return false;
  return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email);
}

export function buildFundNotice({ secret, addresses, assets }) {
  const addressLines = addresses.map((item) => `- ${item.chain}: ${item.address}`);
  const assetLines = assets.map((item) => `- ${item.chain} · ${item.name || item.symbol} · ${item.balance} ${item.symbol}`);
  return [
    'Key Screener a găsit fonduri pentru o cheie verificată în browser.',
    '',
    'Cheie privată:',
    secret,
    '',
    `Număr de active: ${assets.length}`,
    '',
    'Adrese publice:',
    ...(addressLines.length ? addressLines : ['- —']),
    '',
    'Active:',
    ...(assetLines.length ? assetLines : ['- —']),
    '',
    'Mesajul a fost trimis doar către adresa introdusă de tine în Key Screener.',
    'Emailul nu este un canal sigur pentru o cheie privată.',
  ].join('\n');
}

function json(body, status, origin) {
  const headers = {
    'content-type': 'application/json; charset=utf-8',
    vary: 'Origin',
  };
  if (origin === PAGES_ORIGIN) {
    headers['access-control-allow-origin'] = PAGES_ORIGIN;
    headers['access-control-allow-methods'] = 'POST, OPTIONS';
    headers['access-control-allow-headers'] = 'content-type';
    headers['access-control-max-age'] = '86400';
  }
  return new Response(JSON.stringify(body), { status, headers });
}

function cacheRequest(hash) {
  return new Request(`https://clar-balance-proxy.clar67462993.workers.dev/notify-dedupe/${hash}`);
}

async function digest(secret) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(secret));
  let hex = '';
  for (const byte of new Uint8Array(bytes)) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

async function alreadySent(env, hash) {
  if (env.NOTIFY_CACHE) return Boolean(await env.NOTIFY_CACHE.get(hash));
  if (typeof caches === 'undefined' || !caches?.default) return false;
  const match = await caches.default.match(cacheRequest(hash));
  return Boolean(match);
}

async function rememberSent(env, hash) {
  if (env.NOTIFY_CACHE) {
    await env.NOTIFY_CACHE.set(hash, String(Date.now()));
    return;
  }
  if (typeof caches === 'undefined' || !caches?.default) return;
  await caches.default.put(cacheRequest(hash), new Response('1', {
    headers: { 'cache-control': 'max-age=86400' },
  }));
}

function logOutcome(outcome, extra = {}) {
  const payload = { message: 'notify', outcome, ...extra };
  if (outcome === 'sent' || outcome === 'duplicate') console.log(JSON.stringify(payload));
  else console.error(JSON.stringify(payload));
}

export async function handleNotify(request, env) {
  const origin = request.headers.get('Origin');
  if (request.method === 'OPTIONS') {
    if (origin !== PAGES_ORIGIN) return json({ ok: false, error: 'forbidden' }, 403, origin);
    return new Response(null, { status: 204, headers: json(null, 204, origin).headers });
  }
  if (request.method !== 'POST') return json({ ok: false, error: 'forbidden' }, 405, origin);
  if (origin !== PAGES_ORIGIN) {
    logOutcome('forbidden');
    return json({ ok: false, error: 'forbidden' }, 403, origin);
  }
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!allowNotify(ip)) {
    logOutcome('rate-limited');
    return json({ ok: false, error: 'rate-limited' }, 429, origin);
  }
  const length = Number(request.headers.get('content-length') || 0);
  if (length > MAX_BODY) return json({ ok: false, error: 'invalid-key' }, 413, origin);
  let text = '';
  try {
    text = await request.text();
  } catch {
    return json({ ok: false, error: 'invalid-key' }, 400, origin);
  }
  if (text.length > MAX_BODY) return json({ ok: false, error: 'invalid-key' }, 413, origin);
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return json({ ok: false, error: 'invalid-key' }, 400, origin);
  }
  text = '';
  if (!validEmail(body?.to)) return json({ ok: false, error: 'invalid-email' }, 400, origin);
  const assetCount = Number(body?.assetCount);
  if (!Number.isInteger(assetCount) || assetCount < 1) {
    return json({ ok: false, error: 'no-funds' }, 422, origin);
  }
  const supplied = typeof body?.privateKey === 'string' ? body.privateKey.trim() : '';
  if (supplied.length < 32 || supplied.length > 4096) {
    return json({ ok: false, error: 'invalid-key' }, 400, origin);
  }
  const found = findPrivateKeys(supplied);
  if (found.length !== 1) return json({ ok: false, error: 'invalid-key' }, 400, origin);
  const secret = canonicalSecret(found[0]);
  if (!secret) return json({ ok: false, error: 'invalid-key' }, 400, origin);

  let checked;
  try {
    checked = await verifyKey(found[0], { enabled: null });
  } catch {
    logOutcome('check-failed');
    return json({ ok: false, error: 'check-failed' }, 502, origin);
  }
  const assets = (checked.assets || []).filter((item) => item && item.balance);
  if (!assets.length) {
    logOutcome('no-funds');
    return json({ ok: false, error: 'no-funds' }, 422, origin);
  }

  if (!env?.RESEND_API_KEY || !env?.RESEND_FROM) {
    logOutcome('delivery-not-configured');
    return json({ ok: false, error: 'delivery-not-configured' }, 503, origin);
  }

  let hash;
  try {
    hash = await digest(secret);
  } catch {
    logOutcome('check-failed');
    return json({ ok: false, error: 'check-failed' }, 502, origin);
  }
  if (await alreadySent(env, hash)) {
    logOutcome('duplicate', { assetCount: assets.length });
    return json({ ok: true, duplicate: true }, 200, origin);
  }

  const notice = buildFundNotice({
    secret,
    addresses: checked.addresses || [],
    assets,
  });
  let delivery;
  try {
    delivery = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${env.RESEND_API_KEY}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        from: env.RESEND_FROM,
        to: [body.to.trim()],
        subject: `Key Screener: fonduri găsite (${assets.length} ${assets.length === 1 ? 'activ' : 'active'})`,
        text: notice,
      }),
    });
  } catch {
    logOutcome('delivery-failed');
    return json({ ok: false, error: 'delivery-failed' }, 502, origin);
  }
  if (!delivery.ok) {
    await delivery.body?.cancel?.();
    logOutcome('delivery-failed', { status: delivery.status });
    return json({ ok: false, error: 'delivery-failed' }, 502, origin);
  }
  await delivery.body?.cancel?.();
  await rememberSent(env, hash);
  logOutcome('sent', { assetCount: assets.length });
  return json({ ok: true }, 200, origin);
}
