An independent JavaScript implementation of Kinfold v0, written from `spec/PROTOCOL.md` alone. `kinfold.mjs` uses only WebCrypto (`crypto.subtle`, `crypto.getRandomValues`), so it also runs unchanged in a browser.

Run `node verify.mjs [path/to/kinfold-v0.json]` with Node 22 or later. Without an argument it checks `../../spec/vectors/kinfold-v0.json`. No npm install is needed.

It prints a pass count per group, lists every failure, and exits with status 1 if anything fails.
