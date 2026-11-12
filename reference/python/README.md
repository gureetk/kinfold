# Python reference implementation

The protocol in about 1,000 lines, written to be read next to `spec/PROTOCOL.md`: `encoding.py` (§2), `crypto.py` (§3, including RFC 9180 HPKE), `identity.py` (§4, §11, §13), `log.py` (§5–6), `envelope.py` (§7–8) and `rendezvous.py` (§9, §10, §12).

It exists to define and generate the test vectors. It is not for production: it makes no constant-time promises beyond the underlying library's, and keeps secrets in ordinary Python objects.

```sh
pip install --require-hashes -r requirements.txt                       # pyca/cryptography and its dependencies
python3 check_vectors.py ../../spec/vectors/kinfold-v0.json             # 423 checks
python3 gen_vectors.py OUT.json RFC9180-test-vectors.json               # deterministic
```

`log.apply(state, entry, secrets)` is the entire member-log rule set: pass `secrets=None` for what a server can check, or the epoch secrets for the full client rules.
