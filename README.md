# Kinfold

A free, self-hosted family location app: native Android and iOS apps and a small Go server, with end-to-end encryption, so the server that relays your family's locations can't read them. Built to feel familiar to people coming from Life360.

> **Status: Phase 1 has begun.** The protocol spec (draft 0.3), the HTTP API draft, test vectors and three implementations that agree on them are here, along with a server that answers the API's accounts, member logs, envelopes, live stream, silence watches, invites, device linking, share links, push through the iOS relay and Web Push, map regions and address search, and keeps its data in SQLite. The shared Kotlin core has begun, with the encoding and the platform cryptography behind the spec's byte checks; the rest of it, the rest of the server and the apps don't exist yet.
>
> Not affiliated with other apps that use the name Kinfold.

## What's here

| Path | What | License |
| --- | --- | --- |
| [`spec/PROTOCOL.md`](spec/PROTOCOL.md) | Protocol v0 (draft 0.3): identities and device kinds, the member log, roles and teen rules, envelopes and payloads, invites, device linking, recovery kits, safety codes, share links, login, silence watches and push | CC BY 4.0 |
| [`spec/API.md`](spec/API.md) | HTTP API v0 (draft 0.3): the endpoints that carry those objects, with errors, limits and the relay | CC BY 4.0 |
| [`spec/vectors/`](spec/vectors/) | Test vectors every implementation must pass | CC0 1.0 |
| [`reference/python/`](reference/python/) | Reference implementation, vector generator and checker | Apache-2.0 |
| [`reference/js/`](reference/js/) | Independent WebCrypto implementation (written from the spec alone) | Apache-2.0 |
| [`reference/go/`](reference/go/) | Go standard-library checker for everything a server enforces (public mode); the seed of the server's protocol package | Apache-2.0 |
| [`reference/platforms/`](reference/platforms/) | The Ed25519 edge cases run through platform libraries: the JDK, Tink, Conscrypt and Bouncy Castle (in CI), and CryptoKit (a script for a Mac) | Apache-2.0 |
| [`server/`](server/) | Go server (Phase 1): so far, the protocol's public rules and the HTTP API for accounts, member logs, envelopes, the stream, silence watches, invites, device linking, share links, push, map regions and search | AGPL-3.0-or-later |
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

CI runs all three, and checks that the vectors regenerate byte for byte. It also runs the Ed25519 edge cases through the JVM's libraries ([`reference/platforms/`](reference/platforms/)).

## Design in one paragraph

Each person has an identity key that vouches for their devices, and can replace it without losing their account. Each circle has a hash-chained log of signed membership entries. What a device may write there is fixed by its kind, so a browser session can read a circle but can't change who is in it or anyone's rules. Roles, guardians, teen rules and pauses are encrypted inside the log, so the server enforces only what it can see (structure, signatures, device kinds and who is an admin) and every member's phone enforces the rest identically. Locations travel in envelopes encrypted once per message and wrapped with HPKE for each recipient device, padded so the server can't tell a position from an SOS. See the spec for details and its threat model.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) (DCO sign-off, no CLA) and [SECURITY.md](SECURITY.md) (private disclosure). The name and logo are covered by [TRADEMARK.md](TRADEMARK.md), not the code licenses.
