# Server (Phase 1)

The Go server will live here: accounts, devices, circles, member log, envelope store, live relay, silence watches, invites, share links, map tiles and the search proxy. Go standard library plus SQLite, with five or fewer direct dependencies.

Its protocol obligations are the public rules: PROTOCOL.md §6.3 steps 1–9 for log appends, §7.5 for envelopes, §13 for its identity and login, and §14 for silence watches and pushes, all checked against `spec/vectors` in public mode. The HTTP API is in `spec/API.md`.

License: AGPL-3.0-or-later.

## Running it

```sh
go build -trimpath -o kinfold ./cmd/kinfold
./kinfold serve --url https://kinfold.example.org --data /var/lib/kinfold    # plain HTTP on 127.0.0.1:8080, behind a TLS proxy
./kinfold setup --data /var/lib/kinfold                                     # the setup code for the first phone
```

`serve` keeps its key in `server.key` and opens the admin socket `admin.sock` in the data directory, both readable only by its user. Give it `--tls-cert` and `--tls-key` to serve TLS 1.3 itself. It refuses to answer anything but `/healthz` while the kernel reports the clock unsynchronized (`--no-clock-check` skips the check). **This build keeps everything else in memory**: accounts, circles and envelopes are gone when it stops. SQLite comes next.

## HTTP API

`internal/api` implements `spec/API.md` §1 to §7 except the WebSocket stream, and §9: discovery and health, accounts, devices and login, circles and the member log (with the repair path), envelopes and the inbox, and invites. `internal/admin` and `cmd/kinfold` implement the part of §16 a first device needs (setup codes and registration tokens) plus settings, operators and repair mode.

- Storage sits behind `internal/store`, a transactional interface: every check and the write it guards run in one transaction. `internal/store/memstore` implements it in memory, with an undo log so that a failed transaction leaves nothing behind.
- The clock is injected (`internal/clock`); tests set it.
- Nothing is logged about requests: no bodies, tokens, IDs, positions or addresses.

## Protocol packages

Built with Go 1.27 and the standard library alone; `go.mod` has no requirements.

| Package | What it enforces |
| --- | --- |
| `internal/wire` | The encodings of PROTOCOL.md §2: integers, vectors, strict base64url, API frames, padding (§7.4) |
| `internal/kcrypto` | Cipher suite 0x0001 (§3): labelled hashes, the KDF, strict Ed25519 (§3.3), the X25519 key check and HPKE (§3.5), from `crypto/ed25519`, `crypto/hkdf` and `crypto/hpke` |
| `internal/identity` | Device certificates, identity chains and key bundles (§4); the server's identity document, setup codes, move notices and login signatures (§13) |
| `internal/memberlog` | Log appends in public mode: §6.3 steps 1–9 with the public effects, and the clock check of §6.7 (`bad_time`, with repair mode) |
| `internal/envelope` | The checks of §7.5 before an envelope is stored, including circle coverage, `stale_head` and idempotent posts |
| `internal/watch` | Silence-watch grants (§14.1) |
| `internal/push` | Signed, padded and sealed pushes (§14.2) and the relay signature (§14.4) |

None of them reads a clock: every check that depends on time takes the server's time as an argument, so tests can set it.

A circle's public state holds no list of entry hashes. Envelope checks ask the store where a hash sits in the log (`envelope.Heads`), so appending stays cheap however long a log grows.

## Tests

```sh
go test ./...                                                      # every server-side vector group
KINFOLD_PYTHON=../.venv/bin/python go test ./...                    # plus the differential and end-to-end runs
go test -run '^$' -fuzz '^FuzzApply$' -fuzztime 1m ./internal/memberlog
```

- **Vectors.** Each package checks its groups of `spec/vectors/kinfold-v0.json`: primitives, the RFC 9180 case, the Ed25519 and X25519 edge cases, identities, the main log and all 153 cases in public mode with their public state, every envelope's `server_error` and the repost sequence, watch grants, pushes and the relay signature, the setup code, moves and login.
- **HPKE.** `crypto/hpke` can't take a fixed ephemeral key, so a sealed push can't be rebuilt byte for byte, which `spec/vectors/README.md` makes optional. Instead the tests check that the Push bytes are exact, that the vectors' sealed pushes open with the standard library, and that pushes sealed here open with the device's key.
- **Clock.** `bad_time` can't be in the vectors. Tests check created_at against an injected clock on both sides of each 10-minute boundary, in normal and repair mode, and the time limits of envelopes and grants to the millisecond.
- **Fuzzing.** Every parser has a native fuzz target: base64url, frames, padding, certificates, bundles, chains, the server's own structures, log entries (with `Apply` on three states), envelopes and watch grants.
- **API.** `internal/api` replays the vectors' whole main log through HTTP, each entry from a session of its author's device at its own `created_at`, then posts the vectors' envelopes and checks every inbox. It also tests `bad_time` through the API with the clock injected, sessions and login, rate limits, body limits, API revisions, the unsynchronized clock, repair mode, a removed device's read access, invites with their limits, waiting reads and inviters who leave, and refused requests counting against the limits. `internal/admin` is tested on its own: setup codes, tokens, settings, repair mode and operators.
- **End to end.** `internal/e2e` drives a server with two clients built on the Python reference: register from a setup code, create a circle, invite and join, then send an envelope each way and fetch and open it.
- **Differential run.** `internal/difftest` feeds the same inputs to these packages and to the Python reference (`reference/python`) and compares outcomes, reason codes and the whole public state. Most inputs are entries, envelopes and grants built and signed with the vectors' keys, so that they reach the rules behind the signature checks; accepted entries become states for later inputs. `KINFOLD_DIFF_N` and `KINFOLD_DIFF_SEED` set its size and seed.

CI (`.github/workflows/server.yml`) builds, checks formatting, vets, runs the tests with the race detector and the Python reference (so the differential and end-to-end runs are included), fuzzes each target briefly, and runs `staticcheck` and `govulncheck`.
