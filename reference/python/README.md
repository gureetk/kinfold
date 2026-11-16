# Python reference implementation

The protocol in about 2,300 lines, written to be read next to `spec/PROTOCOL.md`:

| Module | Spec |
| --- | --- |
| `encoding.py` | §2 encoding, §7.4 padding |
| `crypto.py` | §3, including strict Ed25519 verification and RFC 9180 HPKE |
| `identity.py` | §4 certificates, identity chains and key bundles; §11 safety codes; §13 server identity, setup codes, login and moves |
| `log.py` | §5–6 the member log and its state hash |
| `envelope.py` | §7–8 envelopes, payload limits and who may send what |
| `rendezvous.py` | §9 invites and joining; §10 linking and recovery kits; §12 share links |
| `push.py` | §14 watch grants, pushes and the relay signature |

It exists to define and generate the test vectors. It is not for production: it makes no constant-time promises beyond the underlying library's, and keeps secrets in ordinary Python objects.

```sh
pip install --require-hashes -r requirements.txt                       # pyca/cryptography and its dependencies
python3 check_vectors.py ../../spec/vectors/kinfold-v0.json             # 1,938 checks
python3 gen_vectors.py OUT.json RFC9180-test-vectors.json               # deterministic
```

`log.apply(state, entry, secrets)` is the entire member-log rule set: pass `secrets=None` for what a server can check, or the epoch secrets the client holds for the full client rules. `envelope.open_envelope` is what a receiver does with an envelope and `envelope.server_check` what a server does before storing one.

`check_vectors.py` uses only the parse, verify and open paths, plus a few tests that aren't in the vector file: both sides of every payload limit, a wrong epoch secret throughout the main log, and a device with frozen private state. `gen_vectors.py` also builds, with its own small Ed25519 arithmetic, the signatures that no library would produce.
