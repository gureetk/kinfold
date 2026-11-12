# Kinfold

A free, self-hosted family location app: native Android and iOS apps and a small Go server, with end-to-end encryption, so the server that relays your family's locations can't read them. Built to feel familiar to people coming from Life360.

> **Status: Phase 0 (foundations).** The protocol spec, test vectors and a reference implementation are here. The apps and server don't exist yet.
>
> Not affiliated with other apps that use the name Kinfold.

## What's here

| Path | What | License |
| --- | --- | --- |
| [`spec/PROTOCOL.md`](spec/PROTOCOL.md) | Protocol v0 (draft): identities, member log, roles and teen rules, envelopes, invites, device linking, safety codes, share links, login | CC BY 4.0 |
| [`spec/API.md`](spec/API.md) | HTTP API sketch | CC BY 4.0 |
| [`spec/vectors/`](spec/vectors/) | Test vectors every implementation must pass | CC0 1.0 |
| [`reference/python/`](reference/python/) | Reference implementation, vector generator and checker | Apache-2.0 |
| [`reference/js/`](reference/js/) | Independent WebCrypto implementation (written from the spec alone) | Apache-2.0 |
| [`reference/go/`](reference/go/) | Go standard-library checker for everything a server enforces (public mode); the seed of the server's protocol package | Apache-2.0 |
| `server/` | Go server — Phase 1 | AGPL-3.0-or-later |
| `apps/android`, `apps/ios`, `core/` | Apps and the shared Kotlin Multiplatform core — Phase 1 | GPL-3.0-or-later with an app-store permission (draft) |

Full license texts are in [`LICENSES/`](LICENSES/); [`REUSE.toml`](REUSE.toml) maps every path to its license. The app-store permission is a draft awaiting legal review.

## Checking the vectors

```sh
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r reference/python/requirements.txt
.venv/bin/python reference/python/check_vectors.py spec/vectors/kinfold-v0.json
node reference/js/verify.mjs spec/vectors/kinfold-v0.json      # Node 22
(cd reference/go && go run . ../../spec/vectors/kinfold-v0.json)  # Go 1.24+
```

CI runs all three, and checks that the vectors regenerate byte for byte.

## Design in one paragraph

Each person has an identity key that vouches for their devices. Each circle has a hash-chained log of signed membership entries; roles, guardians, teen rules and pauses are encrypted inside it, so the server enforces only what it can see (structure, signatures and who is an admin) and every member's phone enforces the rest identically. Locations travel in envelopes encrypted once per message and wrapped with HPKE for each recipient device, padded so the server can't tell a position from an SOS. See the spec for details and its threat model.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) (DCO sign-off, no CLA) and [SECURITY.md](SECURITY.md) (private disclosure). The name and logo are covered by [TRADEMARK.md](TRADEMARK.md), not the code licenses.
