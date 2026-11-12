# clar

Static GitHub Pages site for a read-only wallet checker (EVM, BNB, Bitcoin, Solana, and transaction hashes). There is no wallet connection and no way to sign or send a transaction.

Balance lookups go through the Cloudflare Worker URL in `config.js`. The Worker is not part of this repository, and it still receives only public addresses.

## Private keys stay in the browser

The page can derive a public address from a key you paste, or from a key you placed in a file you upload, and then run the existing balance check on that address.

- Supported key material: 64-character hex (with or without `0x`) for EVM, Bitcoin WIF (compressed and uncompressed), and a Solana 64-byte secret key as hex or a JSON byte array.
- Files: PDF, TXT, CSV, JSON, LOG, MD, HTML, and DOCX, up to 40 MB. Large files are read in chunks, with a progress indicator and a cancel button. PDF text is extracted in the browser with PDF.js. DOCX is unzipped locally.
- A 64-character hex string is still classified as a transaction hash by the existing checker. If it is also a valid EVM private key, the public address is derived locally and checked as well. Explorer links for that string are removed so the string is not sent out of the browser.
- Seed phrases (mnemonics) are not derived. Adding BIP-39 and the derivation paths would pull in a large wordlist for a format the page does not need in order to check a pasted key.
- The private key, WIF, seed, and file bytes are not sent to the Worker, stored in `localStorage` / `sessionStorage`, or put in the page URL. Requests that would contain key material are blocked in the page. Only the derived public address is looked up, the same way a typed public address already is.

## Build

GitHub Pages serves the files at the repository root, including `assets/key-local.js`, `assets/pdfjs-parser.js`, and `assets/pdf.worker.min.js`. After changing `src/key-local/`, rebuild those files and commit them:

```bash
npm install
npm run test:keys
npm run build:keys
```
