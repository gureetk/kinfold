An independent JavaScript implementation of Kinfold v0, written from `spec/PROTOCOL.md` alone. `kinfold.mjs` uses only WebCrypto, so it also runs unchanged in a browser.

From the repository root, run `node reference/js/verify.mjs spec/vectors/kinfold-v0.json` with Node 22 or later. No npm install is needed. A relative path also resolves against the repository root, and with no argument the script checks the vectors in the repo.

It prints a pass count per group, lists every failure, and exits with status 1 if anything fails.
