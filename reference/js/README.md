An independent JavaScript implementation of Kinfold v0 (draft 0.3), written from `spec/PROTOCOL.md` alone. `kinfold.mjs` uses only WebCrypto, so it also runs unchanged in a browser.

From the repository root, run `node reference/js/verify.mjs spec/vectors/kinfold-v0.json` with Node 22 or later. No npm install is needed. A relative path also resolves against the repository root, and with no argument the script checks the vectors in the repo.

It prints a pass count per group (about 5,000 checks), lists every failure, and exits with status 1 if anything fails. Besides checking every vector as a client and as a server, it rebuilds each main-log entry, envelope, link message and push byte for byte from the seeds, and tests things the vector file can't hold: fresh random round trips, a client that is missing an epoch secret or holds a wrong one throughout the main log, payloads held while private state is frozen, and both sides of every payload limit.

**Ed25519.** `verifyRaw` makes the three byte checks of §3.3 itself and only then calls WebCrypto. They are needed: on Node 22, WebCrypto alone accepts 17 of the 23 edge-case signatures that every implementation must refuse, among them every small-order public key. The script prints that count for the platform it runs on.
