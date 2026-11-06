/**
 * When window.CLAR_WORKER_URL is set, rewrite clar's known upstream API hosts
 * through the Cloudflare Worker /proxy endpoint so browser CORS works.
 * Explorer /tx and /address HTML links are left alone (not API hosts used by fetch).
 */
(function () {
  'use strict';

  var ALLOWED_HOSTS = {
    'ethereum-rpc.publicnode.com': true,
    'base-rpc.publicnode.com': true,
    'arbitrum-one-rpc.publicnode.com': true,
    'optimism-rpc.publicnode.com': true,
    'polygon-bor-rpc.publicnode.com': true,
    'bsc-rpc.publicnode.com': true,
    'solana-rpc.publicnode.com': true,
    'eth.blockscout.com': true,
    'base.blockscout.com': true,
    'arbitrum.blockscout.com': true,
    'polygon.blockscout.com': true,
    'explorer.optimism.io': true,
    'mempool.space': true,
    // Optional / legacy hosts from the user's Worker sketch (not used by clar UI today):
    'api.etherscan.io': true,
    'api.blockcypher.com': true,
    'api.mainnet-beta.solana.com': true,
  };

  var originalFetch = window.fetch.bind(window);

  function resolveUrl(input) {
    if (typeof input === 'string') return input;
    if (input && typeof input.url === 'string') return input.url;
    return null;
  }

  function shouldProxy(absoluteUrl) {
    try {
      var u = new URL(absoluteUrl);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
      return !!ALLOWED_HOSTS[u.hostname];
    } catch (e) {
      return false;
    }
  }

  window.fetch = function clarProxiedFetch(input, init) {
    var workerBase = typeof window.CLAR_WORKER_URL === 'string' ? window.CLAR_WORKER_URL.trim() : '';
    if (!workerBase) {
      return originalFetch(input, init);
    }

    var raw = resolveUrl(input);
    if (!raw) {
      return originalFetch(input, init);
    }

    var absolute;
    try {
      absolute = new URL(raw, window.location.href).toString();
    } catch (e) {
      return originalFetch(input, init);
    }

    if (!shouldProxy(absolute)) {
      return originalFetch(input, init);
    }

    var proxied =
      workerBase.replace(/\/+$/, '') +
      '/proxy?url=' +
      encodeURIComponent(absolute);

    if (typeof input === 'string') {
      return originalFetch(proxied, init);
    }

    // Request object: rebuild so method/headers/body are preserved against the new URL.
    try {
      var rebuilt = new Request(proxied, input);
      return originalFetch(rebuilt, init);
    } catch (e) {
      return originalFetch(proxied, init);
    }
  };
})();
