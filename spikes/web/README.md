# Spike 5 in a browser: the test vectors on WebCrypto

The page runs `reference/js/verify.mjs`, unchanged, against `spec/vectors/kinfold-v0.json` with the browser's own WebCrypto, and shows what it prints:

- a count for every group of vectors, and every failure;
- how many of the 23 Ed25519 signatures that every implementation must refuse WebCrypto would accept on its own, without the byte checks of PROTOCOL.md §3.3.

`verify.mjs` is written for Node. An import map in `index.html` stands in for the three Node modules it imports (`shims/`), fetching files from the page's own origin.

## Running it

A browser gives a page WebCrypto only over https, or from localhost on the same device. On a Mac, from the repository's root:

```sh
python3 spikes/web/serve.py
```

Then open <http://localhost:8000/spikes/web/> in Safari and in Firefox. The server answers that computer only, and serves the repository's files as they are. "Copy the results" puts the browser's name and the whole output on the clipboard.

On an iPhone, the spike app runs the same page in a web view, which uses the WebKit and WebCrypto that Safari uses on that phone.

## So far

| Browser | Checks | WebCrypto alone accepts |
| --- | --- | --- |
| Chrome 153, headless, on Linux | 4,989, all passed | 17 of the 23, as Node 22 does |
