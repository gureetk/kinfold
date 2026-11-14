# Server (Phase 1)

The Go server will live here: accounts, devices, circles, member log, envelope store, live relay, silence watches, invites, share links, map tiles and the search proxy. Go standard library plus SQLite, with five or fewer direct dependencies.

Its protocol obligations are the public rules: PROTOCOL.md §6.3 steps 1–9 for log appends, §7.5 for envelopes, §13 for its identity and login, and §14 for silence watches and pushes, all checked against `spec/vectors` in public mode. The HTTP API is in `spec/API.md`.

License: AGPL-3.0-or-later.

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
KINFOLD_PYTHON=../.venv/bin/python go test ./internal/difftest     # plus the differential run
go test -run '^$' -fuzz '^FuzzApply$' -fuzztime 1m ./internal/memberlog
```

- **Vectors.** Each package checks its groups of `spec/vectors/kinfold-v0.json`: primitives, the RFC 9180 case, the Ed25519 and X25519 edge cases, identities, the main log and all 153 cases in public mode with their public state, every envelope's `server_error` and the repost sequence, watch grants, pushes and the relay signature, the setup code, moves and login.
- **HPKE.** `crypto/hpke` can't take a fixed ephemeral key, so a sealed push can't be rebuilt byte for byte, which `spec/vectors/README.md` makes optional. Instead the tests check that the Push bytes are exact, that the vectors' sealed pushes open with the standard library, and that pushes sealed here open with the device's key.
- **Clock.** `bad_time` can't be in the vectors. Tests check created_at against an injected clock on both sides of each 10-minute boundary, in normal and repair mode, and the time limits of envelopes and grants to the millisecond.
- **Fuzzing.** Every parser has a native fuzz target: base64url, frames, padding, certificates, bundles, chains, the server's own structures, log entries (with `Apply` on three states), envelopes and watch grants.
- **Differential run.** `internal/difftest` feeds the same inputs to these packages and to the Python reference (`reference/python`) and compares outcomes, reason codes and the whole public state. Most inputs are entries, envelopes and grants built and signed with the vectors' keys, so that they reach the rules behind the signature checks; accepted entries become states for later inputs. `KINFOLD_DIFF_N` and `KINFOLD_DIFF_SEED` set its size and seed.

CI (`.github/workflows/server.yml`) builds, checks formatting, vets, runs the tests with the differential run, fuzzes each target briefly, and runs `staticcheck` and `govulncheck`.
