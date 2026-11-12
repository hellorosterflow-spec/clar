/**
 * Keeps key material from leaving the browser or being written into storage.
 * The only request allowed to carry a private key is the visitor's opt-in
 * POST to the Worker's /notify path. IndexedDB is not covered here; the scan
 * history uses it on purpose and stays on this device.
 */
import { isOptInNotifyRequest } from './notify.js';

const masks = new Map();

export function clearRegisteredSecrets() {
  masks.clear();
}

export function registerSecrets(pairs) {
  for (const pair of pairs) {
    if (!pair || typeof pair.secret !== 'string' || pair.secret.length < 32) continue;
    masks.set(pair.secret, pair.mask || '••••');
  }
}

export function knownSecrets() {
  return [...masks.keys()];
}

export function containsSecret(value) {
  if (value == null || masks.size === 0) return false;
  const text = typeof value === 'string' ? value : String(value);
  for (const secret of masks.keys()) {
    if (text.includes(secret)) return true;
  }
  return false;
}

export function redact(value) {
  let text = typeof value === 'string' ? value : String(value);
  const secrets = [...masks.keys()].sort((a, b) => b.length - a.length);
  for (const secret of secrets) {
    if (!text.includes(secret)) continue;
    text = text.split(secret).join(masks.get(secret));
  }
  return text;
}

function blockedResponse() {
  return Promise.reject(new Error('Cererea a fost blocată local: conține material de cheie privată.'));
}

function scrubNode(root) {
  if (masks.size === 0 || !root) return;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const textNodes = [];
  while (walker.nextNode()) textNodes.push(walker.currentNode);
  for (const node of textNodes) {
    const parent = node.parentElement;
    if (!parent || parent.closest('#clar-key-panel')) continue;
    if (parent.tagName === 'SCRIPT' || parent.tagName === 'STYLE') continue;
    if (!node.nodeValue || !containsSecret(node.nodeValue)) continue;
    const next = redact(node.nodeValue);
    if (next !== node.nodeValue) node.nodeValue = next;
  }
  if (!root.querySelectorAll) return;
  for (const element of root.querySelectorAll('[href], [title]')) {
    if (element.closest('#clar-key-panel')) continue;
    const href = element.getAttribute('href');
    if (href && containsSecret(href)) {
      const links = element.closest('.txhash-links');
      if (links) links.remove();
      else element.setAttribute('href', '#');
    }
    const title = element.getAttribute('title');
    if (title && containsSecret(title)) element.removeAttribute('title');
  }
}

export function installPrivacyGuards() {
  if (installPrivacyGuards.installed) return;
  installPrivacyGuards.installed = true;

  const originalFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input?.url || '';
    const body = init && typeof init.body === 'string' ? init.body : '';
    const worker = typeof window.CLAR_WORKER_URL === 'string' ? window.CLAR_WORKER_URL : '';
    if (isOptInNotifyRequest(url, init, worker)) return originalFetch(input, init);
    if (containsSecret(url) || containsSecret(body)) return blockedResponse();
    return originalFetch(input, init);
  };

  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function openGuarded(method, url, ...rest) {
    this.__clarUrl = url == null ? '' : String(url);
    return originalOpen.call(this, method, url, ...rest);
  };
  XMLHttpRequest.prototype.send = function sendGuarded(body) {
    const asText = typeof body === 'string' ? body : '';
    if (containsSecret(this.__clarUrl) || containsSecret(asText)) {
      throw new Error('Cererea a fost blocată local: conține material de cheie privată.');
    }
    return originalSend.call(this, body);
  };

  if (typeof navigator !== 'undefined' && typeof navigator.sendBeacon === 'function') {
    const originalBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = (url, data) => {
      const asText = typeof data === 'string' ? data : '';
      if (containsSecret(String(url)) || containsSecret(asText)) return false;
      return originalBeacon(url, data);
    };
  }

  const originalWindowOpen = window.open.bind(window);
  window.open = (url, ...rest) => {
    if (url != null && containsSecret(String(url))) return null;
    return originalWindowOpen(url, ...rest);
  };

  for (const storage of [window.localStorage, window.sessionStorage]) {
    const originalSet = storage.setItem.bind(storage);
    storage.setItem = (key, value) => originalSet(key, redact(value == null ? '' : String(value)));
  }

  const originalPush = history.pushState.bind(history);
  const originalReplace = history.replaceState.bind(history);
  const guardHistory = (original) => (state, title, url) => {
    try {
      if (url != null && containsSecret(String(url))) return;
      if (state != null && containsSecret(JSON.stringify(state))) return;
    } catch {
      /* unstringifiable state still goes through; it cannot embed our strings */
    }
    return original(state, title, url);
  };
  history.pushState = guardHistory(originalPush);
  history.replaceState = guardHistory(originalReplace);

  document.addEventListener('click', (event) => {
    const link = event.target instanceof Element ? event.target.closest('a[href]') : null;
    if (!link) return;
    const href = link.getAttribute('href') || '';
    if (!containsSecret(href)) return;
    event.preventDefault();
    event.stopPropagation();
  }, true);

  let scheduled = false;
  const observer = new MutationObserver(() => {
    if (scheduled || masks.size === 0) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      scrubNode(document.body);
    });
  });
  observer.observe(document.documentElement, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: ['href', 'title'],
  });
  scrubNode(document.body);
}
