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

`serve` keeps everything in the data directory, readable only by its user: its key (`server.key`), its Web Push key (`vapid.key`, not made with `--no-webpush`), the SQLite database (`kinfold.db`, with the `-wal` and `-shm` files SQLite keeps next to it), the map files (`tiles/`) and the admin socket (`admin.sock`). Give it `--tls-cert` and `--tls-key` to serve TLS 1.3 itself. Behind a reverse proxy, name the proxy with `--trusted-proxy`, such as `--trusted-proxy 127.0.0.1,::1` for one on the same machine: on its connections the server takes each client's address from `X-Forwarded-For`, which Caddy sets by default, for the per-address limits of API.md §3, and it ignores that header from anyone else. Without it, every client counts as the proxy, so one client could use up a limit for all of them, and the server says so when it starts. `kinfold limits` shows the rate limits of API.md §3, and `kinfold limits set NAME N` changes one at once and for later starts. `--relay` names the iOS relay (API.md §14); `--push-hosts` lists Web Push hosts allowed on private addresses, `--push-hosts-only` refuses every other, and `--no-webpush` takes no Web Push registrations at all. It refuses to answer anything but `/healthz` while the kernel reports the clock unsynchronized (`--no-clock-check` skips the check). At start and then every minute it deletes what has run out (API.md §15), drops a circle's oldest envelopes while they hold more than 512 MB (§3), logs how many of each kind, nothing more, and runs the silence check (§8).

### Backups

`kinfold backup /safe/place/kinfold.tar` writes a tar archive: a snapshot of the database, taken while the server runs, and the server's keys. It leaves out the map files, which come from your own copies. The archive holds the server key, so keep it as safe. To restore, stop the server, then run `kinfold restore /safe/place/kinfold.tar --data /var/lib/kinfold`. It checks the archive and its database before it replaces anything, and the server then starts in repair mode, so phones can post again what the backup lacks (API.md §6). `kinfold status` shows when the last backup was made, with the server's health.

### Maps

Phones download a whole region and draw it themselves (API.md §13). Cut one from the [Protomaps](https://docs.protomaps.com/basemaps/downloads) build with the `pmtiles` command line, which fetches only the parts it needs, then hand it to the server, which copies it in:

```sh
pmtiles extract https://build.protomaps.com/YYYYMMDD.pmtiles bc.pmtiles --bbox=-139.1,48.2,-114.0,60.0
./kinfold region add bc bc.pmtiles --name "British Columbia" --data /var/lib/kinfold
pmtiles extract https://build.protomaps.com/YYYYMMDD.pmtiles coarse.pmtiles --bbox=-139.1,48.2,-114.0,60.0 --maxzoom=13
./kinfold coarse set coarse.pmtiles --data /var/lib/kinfold                 # for the share viewer
```

`kinfold region list` shows what is on offer. Adding a region under an ID it already has replaces it.

### Search

Address search is an add-on: a [Photon](https://github.com/komoot/photon) instance with a country or region index, run beside the server on the loopback interface with its request log off. `--search http://127.0.0.1:2322` points the server at it. Without it, the server offers no search, and apps drop pins instead.

## HTTP API

`internal/api` implements `spec/API.md` §1 to §13: discovery and health, accounts, devices and login, circles and the member log (with the repair path), envelopes, the inbox and the WebSocket stream, silence watches, invites, the mailboxes for linking devices, share links with their viewer page, push through the iOS relay and Web Push, map regions and address search. `internal/admin` and `cmd/kinfold` implement the part of §16 a first device needs (setup codes and registration tokens) plus settings, operators, repair mode, the map files, and the operator's view of accounts, devices and circles: IDs, kinds, counts and days, with nicknames only the operator sees, and removing a device or an account.

- Storage sits behind `internal/store`, a transactional interface: every check and the write it guards run in one transaction (see Storage).
- A device may also upload on its stream (`stream_post`): each post goes through the same code as the upload call, checked against the session that opened the stream, and is answered in order with what the call would have said.
- The stream holds no records in memory. A stored envelope wakes its recipients' streams, and each reads its records from the store after its own cursor, so it can't skip one, send one twice or grow a queue behind a slow connection. Log frames keep only the latest per circle, and events are capped. Shutting down closes every stream with 4000 first, since `http.Server.Shutdown` leaves upgraded connections alone.
- Silence watches are checked once a minute (`CheckSilences`), against the server's clock, and only a circle envelope from the watched device resets one. A grant replaces another only if it was issued later, and a watch the watched account ended can't come back through a grant issued before the ending (API.md §8).
- Pushes are built, signed and sealed inside the transaction that calls for them, and sent after it commits, in the background, at most 16 at a time, and never to a device with a stream open. A Web Push endpoint must be https and resolve to public addresses only, unless the operator lists its host (`--push-hosts`).
- Web Push (RFC 8291 and RFC 8292) is built from the standard library's ECDH, HKDF, AES-GCM and ECDSA; RFC 8291's own example checks it byte for byte. Each send resolves the host and checks its addresses again, then connects to an address it checked, over a connection of its own. A failed push is logged without the endpoint or the host's address.
- The share-link viewer (`internal/api/viewer`) is one static page and two scripts, served with a content security policy that keeps it to this server. `share.js` derives the link's ID and key from the address's fragment and opens updates on WebCrypto alone; `viewer.js` shows the position as text until the map (§13) exists.
- Map files live in `internal/tiles`: each is copied in, its PMTiles header checked against its size, and stored under its SHA-256, with `index.json` naming the regions. A replaced file is deleted at once; a download under way keeps reading it. A region is served whole or from an offset to its end, never in parts, with a write deadline that allows 32 KiB a second.
- A search goes to Photon's `/api` with the text, language, limit and bias, and nothing about who asked. Neither the text nor an error that would quote it is logged. A language the index lacks is dropped and the search tried again.
- Link mailboxes live in memory: they last minutes, and a restart only means linking again. `SweepLinks` forgets those that have ended, every minute.
- The clock is injected (`internal/clock`); tests set it.
- Nothing is logged about requests: no bodies, tokens, IDs, positions or addresses.

## Storage

`internal/store` has two implementations, and `internal/store/storetest` holds the tests both must pass: every record type, circles and their logs, inbox paging, replay records, invites, sweeps, and transactions that fail or panic halfway.

- **`internal/store/sqlstore`** is what the server runs on. SQLite in WAL mode, so reads see a snapshot and never wait for a write. One connection writes, and `synchronous=FULL` puts every write on disk before the server acknowledges it. The schema is in `schema/`, one script per version, and `PRAGMA user_version` records where a database is: an older one is upgraded a version at a time, each in a transaction, and one from a newer server is refused, not changed.
- A circle's public state isn't stored. It is replayed from the circle's log, the signed record it comes from, and kept in memory once replayed. A log that no longer verifies is an error, never a state. Its own tests reopen the file, read snapshots while writes land, write from many goroutines at once, and tamper with a stored entry.
- **`internal/store/memstore`** keeps everything in memory, with an undo log, for tests: `KINFOLD_STORE=memory` runs the API tests on it.

## Dependencies

| Module | Version | License | Why |
| --- | --- | --- | --- |
| `github.com/ncruces/go-sqlite3` | v0.37.0 | MIT | The SQLite driver, the first direct dependency. Pure Go, so builds need no C compiler and stay reproducible. SQLite runs compiled to WebAssembly and translated to Go: all its memory is one bounds-checked slice, so a memory bug in SQLite's C can't reach the server's own memory. |
| `github.com/ncruces/go-sqlite3-wasm/v6` | v6.5.35401 | MIT-0; SQLite is public domain | SQLite 3.54.1, translated |
| `github.com/ncruces/julianday` | v1.0.0 | MIT | Date conversions in the driver |
| `golang.org/x/sys` | v0.49.0 | BSD-3-Clause | File locks and shared memory for SQLite's WAL |
| `github.com/coder/websocket` | v1.8.15 | ISC | The stream (API.md §7), the second direct dependency. No dependencies of its own; every method but reading is safe from several goroutines; compression is off unless asked for, which suits a stream of encrypted, padded records. |

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

- **Vectors.** Each package checks its groups of `spec/vectors/kinfold-v0.json`: primitives, the RFC 9180 case, the Ed25519 and X25519 edge cases, identities, the main log and all 154 cases in public mode with their public state, every envelope's `server_error` and the repost sequence, watch grants, pushes and the relay signature, the setup code, moves and login.
- **HPKE.** `crypto/hpke` can't take a fixed ephemeral key, so a sealed push can't be rebuilt byte for byte, which `spec/vectors/README.md` makes optional. Instead the tests check that the Push bytes are exact, that the vectors' sealed pushes open with the standard library, and that pushes sealed here open with the device's key.
- **Clock.** `bad_time` can't be in the vectors. Tests check created_at against an injected clock on both sides of each 10-minute boundary, in normal and repair mode, and the time limits of envelopes and grants to the millisecond.
- **Fuzzing.** Every parser has a native fuzz target: base64url, frames, padding, certificates, bundles, chains, the server's own structures, log entries (with `Apply` on three states), envelopes, watch grants and PMTiles headers.
- **API.** `internal/api` replays the vectors' whole main log through HTTP, each entry from a session of its author's device at its own `created_at`, then posts the vectors' envelopes and checks every inbox. It also tests `bad_time` through the API with the clock injected, sessions and login, rate limits, body limits, API revisions, the unsynchronized clock, repair mode, a removed device's read access, invites with their limits, waiting reads and inviters who leave, and refused requests counting against the limits. `internal/admin` is tested on its own: setup codes, tokens, settings, repair mode and operators.
- **End to end.** `internal/e2e` drives a server with two clients built on the Python reference: register from a setup code, create a circle, invite and join, then send an envelope each way and fetch and open it.
- **Push.** Against a fake relay: `Kinfold-Wake: notify` and `locate`, each push's relay signature checked and opened with the device's key from the vectors (type, body, server signature), no push to a device on its stream, a dead token dropped and `push_dropped` on the next stream, the silence wake-up and alert, the wake limit refusing the upload, and what a registration may hold, address rules included.
- **Web Push.** The encryption against RFC 8291's example, both ways. Against a fake push host on TLS: the headers, the VAPID token (claims and signature), the message opened as a subscription opens it and then with the device's key, `locate` looking like `notify`, a connection per push, and a 410 ending the registration. A host that resolves to a private address at send time gets no connection, and what the log says about a failure names no endpoint or address.
- **Maps.** The header checks against hand-broken archives and `FuzzParseHeader`; the library copying, replacing, removing, refusing and reopening, with what it leaves on disk each time. Over a real listener: the list, whole and resumed downloads, `If-Range` and `If-None-Match`, every other kind of range refused for phones and browsers alike, HEAD, the coarse archive in any range without a session, and a download that finishes on the old file while its region is replaced. `internal/admin` adds and removes regions and the coarse archive.
- **Backups.**
  - A snapshot taken while the store stays open.
  - The archive's contents, opened again.
  - The data directory left clean.
  - Refusals: an existing file, a relative path, and the memory store.
  - `kinfold restore` in `cmd/kinfold`: the database and keys back with repair mode on, and nothing changed by four kinds of bad archive or while a server runs.
  - The operators' status and the operator's health report, before and after a backup, with a relay that answers and one that's gone.
- **Addresses.** What a per-address limit counts: the connection's address, and behind a named proxy the client's from `X-Forwarded-For`, read from the right; what a client writes there itself, a header from anyone but the proxy, entries with ports or in nonsense; IPv4-mapped and zoned addresses, and IPv6 by /64. Through the API, login challenges straight to the server and through the proxy. `cmd/kinfold` parses `--trusted-proxy` and refuses a prefix that would trust everyone.
- **Settings.** Rate limits set by name, in force at once and kept for the next start, then back to their defaults, with unknown names and bad values refused. Closed ranges on a region for web devices once the operator allows them, never for phones, and the `web_tile_ranges` feature.
- **Operator.** Over the vectors' family: the account list (days only), the circle and its counts, nicknames that devices never see. A device removed on the server has its stream closed at once and its session refused, and its account, still in the circle, stays. `internal/admin` removes an account in no circle with its device and session, and the store tests cover nicknames, the lists, and a version 1 database upgraded with an account and a device in it.
- **Search.** Against a fake Photon:
  - what the add-on is sent, and how its GeoJSON becomes names, addresses and positions, with broken entries skipped;
  - who may search, and every field it refuses;
  - an unknown language dropped;
  - an add-on that fails, answers nonsense or too much, or is gone;
  - the per-device limit, and a server without the add-on.
- **Share links.** Making, updating, reading and ending a link, who may do each, the checks on an update, the 5-second and 5-link limits, a waiting viewer, the page's headers and the `share_view` event. `TestViewerScript` runs `viewer/share_test.mjs` under Node when it is installed (CI has it): `share.js` against the vectors' `share_link` group, and what it must refuse.
- **Linking.** The vectors' three exchanges go through the mailbox slot by slot, response signatures included; then the order of slots, one writer per slot, other accounts, bytes the server can tell are wrong, a waiting read, the end of a mailbox, and direction 2's switch and limit. `FuzzLinkMessage` fuzzes the check of the clear parts.
- **Watches.** The vectors' grants, then grants signed in the tests: who may register, renew and end a watch, the silence counted from registration and from the last circle envelope (a direct one doesn't count), the wake-up wait and a single alert, signed for its recipient, `watch_ended` for each reason. When the watched account ends a watch, no grant issued before then brings it back, not even one the watcher held back with a later `not_after`; the server keeps the ending for 35 days, through a new grant, a renewal, the watcher's own delete and the new watch running out, and then forgets it.
- **Stream.** Tests on a real listener, against the WebSocket client of the same library: records waiting and live, cursors shared with the inbox, log frames and the `removed` event, `join_request`, notices, and every way a stream ends (replaced, logged out, deregistered, rate limited, idle, session over, restarting), with the intervals shortened.
- **Posting on the stream.**
  - A post stored and delivered to a recipient's stream at once.
  - Posting twice with the first answer.
  - Every refusal of the upload call, as a result: the sender, the wake, malformed, a bad signature with the circle's `seq` and `head`, another circle, and an unsynchronized clock.
  - A post larger than the WebSocket library's default limit.
  - 429 with `retry_after`.
  - The messages that close the stream with 1008 or 1009.
- **Storage.** See Storage above. `internal/api` runs on SQLite, and once more on memory in CI. A test sweeps a closed circle away through the API's retention, and another holds a circle to its size: the oldest envelope dropped, the newer kept, and the dropped one not stored again when posted twice. Both stores trim each circle on its own, and leave one at its limit alone.
- **Differential run.** `internal/difftest` feeds the same inputs to these packages and to the Python reference (`reference/python`) and compares outcomes, reason codes and the whole public state. Most inputs are entries, envelopes and grants built and signed with the vectors' keys, so that they reach the rules behind the signature checks; accepted entries become states for later inputs. `KINFOLD_DIFF_N` and `KINFOLD_DIFF_SEED` set its size and seed.

CI (`.github/workflows/server.yml`) verifies the modules against `go.sum`, builds, checks formatting, vets, runs the tests with the race detector and the Python reference (so the differential and end-to-end runs are included), runs the API tests again on the in-memory store, fuzzes each target briefly, and runs `staticcheck` and `govulncheck`.
