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

`serve` keeps everything in the data directory, readable only by its user: its key (`server.key`), the SQLite database (`kinfold.db`, with the `-wal` and `-shm` files SQLite keeps next to it) and the admin socket (`admin.sock`). Give it `--tls-cert` and `--tls-key` to serve TLS 1.3 itself. It refuses to answer anything but `/healthz` while the kernel reports the clock unsynchronized (`--no-clock-check` skips the check). At start and then every hour it deletes what has run out (API.md §15) and logs how many of each kind, nothing more.

## HTTP API

`internal/api` implements `spec/API.md` §1 to §7 except the WebSocket stream, and §9: discovery and health, accounts, devices and login, circles and the member log (with the repair path), envelopes and the inbox, and invites. `internal/admin` and `cmd/kinfold` implement the part of §16 a first device needs (setup codes and registration tokens) plus settings, operators and repair mode.

- Storage sits behind `internal/store`, a transactional interface: every check and the write it guards run in one transaction (see Storage).
- The clock is injected (`internal/clock`); tests set it.
- Nothing is logged about requests: no bodies, tokens, IDs, positions or addresses.

## Storage

`internal/store` has two implementations, and `internal/store/storetest` holds the tests both must pass: every record type, circles and their logs, inbox paging, replay records, invites, sweeps, and transactions that fail or panic halfway.

- **`internal/store/sqlstore`** is what the server runs on. SQLite in WAL mode, so reads see a snapshot and never wait for a write. One connection writes, and `synchronous=FULL` puts every write on disk before the server acknowledges it. The schema is in `schema.sql`, with its version in `PRAGMA user_version`; a database from a newer server is refused, not changed.
- A circle's public state isn't stored. It is replayed from the circle's log, the signed record it comes from, and kept in memory once replayed. A log that no longer verifies is an error, never a state. Its own tests reopen the file, read snapshots while writes land, write from many goroutines at once, and tamper with a stored entry.
- **`internal/store/memstore`** keeps everything in memory, with an undo log, for tests: `KINFOLD_STORE=memory` runs the API tests on it.

## Dependencies

| Module | Version | License | Why |
| --- | --- | --- | --- |
| `github.com/ncruces/go-sqlite3` | v0.37.0 | MIT | The SQLite driver, the one direct dependency. Pure Go, so builds need no C compiler and stay reproducible. SQLite runs compiled to WebAssembly and translated to Go: all its memory is one bounds-checked slice, so a memory bug in SQLite's C can't reach the server's own memory. |
| `github.com/ncruces/go-sqlite3-wasm/v6` | v6.5.35401 | MIT-0; SQLite is public domain | SQLite 3.54.1, translated |
| `github.com/ncruces/julianday` | v1.0.0 | MIT | Date conversions in the driver |
| `golang.org/x/sys` | v0.49.0 | BSD-3-Clause | File locks and shared memory for SQLite's WAL |

`go.sum` pins each one by hash, checked against the Go checksum database; `golang.org/x/text` appears there only because the driver's own tests use it, and isn't built into the server. CI runs `go mod verify` and `govulncheck`.

## Protocol packages

These use the standard library alone.

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
- **Storage.** See Storage above. `internal/api` runs on SQLite, and once more on memory in CI. A test sweeps a closed circle away through the API's retention.
- **Differential run.** `internal/difftest` feeds the same inputs to these packages and to the Python reference (`reference/python`) and compares outcomes, reason codes and the whole public state. Most inputs are entries, envelopes and grants built and signed with the vectors' keys, so that they reach the rules behind the signature checks; accepted entries become states for later inputs. `KINFOLD_DIFF_N` and `KINFOLD_DIFF_SEED` set its size and seed.

CI (`.github/workflows/server.yml`) verifies the modules against `go.sum`, builds, checks formatting, vets, runs the tests with the race detector and the Python reference (so the differential and end-to-end runs are included), runs the API tests again on the in-memory store, fuzzes each target briefly, and runs `staticcheck` and `govulncheck`.
