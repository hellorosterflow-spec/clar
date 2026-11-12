# clar

Static GitHub Pages site for a read-only wallet checker (EVM, BNB, Bitcoin, Solana, and transaction hashes). The published page is titled Key Screener. There is no wallet connection and no way to sign or send a transaction.

Balance lookups go through the Cloudflare Worker URL in `config.js`. Worker source for that proxy, plus the opt-in `/notify` email route, lives in `worker/`. A normal balance check still sends only public addresses. A private key leaves the browser only when the visitor turns on email alerts and types their own address.

## Private keys stay in the browser

The page can derive a public address from a key you paste, or from a key you placed in a file you upload, and then run the existing balance check on that address.

- Supported key material: 64-character hex (with or without `0x`) for EVM, Bitcoin WIF (compressed and uncompressed), and a Solana 64-byte secret key as hex or a JSON byte array.
- Files: TXT, CSV, JSON, LOG, MD, and HTML up to 1 GB. Text files are read in 1 MB chunks and are never loaded as one string, with a progress indicator, pause, and cancel. There is no cap on how many keys in that file are checked: each well-formed key is verified in order, then dropped unless it has funds. PDF and DOCX are limited to 100 MB, because those formats are opened as a whole in the browser. PDF text is extracted in the browser with PDF.js. DOCX is unzipped locally.
- Scan progress is stored in IndexedDB on this device (`clar-key-screener`), keyed by file name, size, and a hash of the first and last chunk. Uploading the same file again continues from the last finished line. "Reia de la început" clears that position. A closed tab or a locked phone does not discard the position.
- A 64-character hex string is still classified as a transaction hash by the existing checker. If it is also a valid EVM private key, the public address is derived locally and checked as well. Explorer links for that string are removed so the string is not sent out of the browser.
- Seed phrases (mnemonics) are not derived. Adding BIP-39 and the derivation paths would pull in a large wordlist for a format the page does not need in order to check a pasted key.
- The private key, WIF, seed, and file bytes are not put in the page URL and are not written to `localStorage` / `sessionStorage`. Requests that would contain key material are blocked, except a POST to `{CLAR_WORKER_URL}/notify` when the visitor opted in. Only the derived public address is looked up, the same way a typed public address already is.
- Keys that actually have funds are kept in IndexedDB on this device, with the time, the public addresses, the private key, and the balances. The history can be reviewed and cleared. Clearing it does not delete scan progress. Email, if enabled, is sent only to the address typed in the form (empty by default) and only after the Worker confirms funds. The same key is not emailed again on resume.

## Build

GitHub Pages serves the files at the repository root, including `assets/key-local.js`, `assets/pdfjs-parser.js`, and `assets/pdf.worker.min.js`. After changing `src/key-local/`, rebuild those files and commit them:

```bash
npm install
npm run test:keys
npm run build:keys
```

## Worker

`wrangler.jsonc` targets the existing `clar-balance-proxy` Worker. Deploying it replaces the live script, so review the proxy routes before publishing. `/proxy` and `GET /?address&chain` stay, and `POST /notify` is new.

Email delivery needs two Worker secrets. Neither belongs in git:

```bash
npx wrangler secret put RESEND_API_KEY
npx wrangler secret put RESEND_FROM
```

`RESEND_FROM` is the verified From address, for example `Key Screener <alerts@example.com>`. Resend can deliver to an arbitrary recipient only after that domain is verified. The account has no Cloudflare zone, so Cloudflare Email Workers cannot be the From domain. Until both secrets exist, `/notify` returns `delivery-not-configured` and the on-site history still saves.

`/notify` accepts only `Origin: https://hellorosterflow-spec.github.io`, one recipient per request, and only after the Worker itself sees a non-zero balance. It rate-limits by IP (10 requests in 10 minutes, 40 in 24 hours, in the isolate) and does not log the private key.
