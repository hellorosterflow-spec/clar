# clar

Static GitHub Pages site for a read-only public wallet checker (EVM, BNB, Bitcoin, Solana, and transaction hashes). No wallet connect and no private keys.

The site files live at the repository root so Pages can publish the default branch (`/`). Balance lookups go through the Cloudflare Worker URL in `config.js`. The Worker itself is not part of this repository.
