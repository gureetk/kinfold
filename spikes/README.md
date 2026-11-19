# Spikes (Phase 1)

Five risk spikes, each testing something that could change the design before any feature is built on it:

1. **iOS:** background location, heartbeats and location push. Does the iPhone keep the family's map current, and answer wake-ups, with the app in the background or not running?
2. **Android without Google push, in Doze.** Does a foreground service with one WebSocket to the server keep Android phones current, and reachable for an alert, across manufacturers?
3. **The core inside iOS's extensions.** Does the Kotlin core fit in a notification service extension and a location push service extension?
4. **Map regions from local files.** Does MapLibre Native draw a downloaded region from storage, offline, on both platforms?
5. **The vectors on the last crypto stacks:** CryptoKit on an iPhone, and WebCrypto in Safari and Firefox.

Each ends with a written result in `results/`: what was built, how it was measured, the numbers, the verdict against the targets below, and what it changes.

| Measure | Target |
| --- | --- |
| Battery cost of sharing | Under 5% on a typical day |
| Age of a moving person's position | Under 2 minutes, 95% of the time |
| Place alert delay | Under 60 seconds, 95% of the time |
| SOS delivery with both phones online | Under 10 seconds |
| False silence alerts | Fewer than one per phone per week |

The code here is for measuring, not for shipping, and none of it is an app feature. It may be rough, but the project's rules hold: no coordinates, keys or addresses in any log; every dependency justified, pinned and verified; no Google Play services.

License: GPL-3.0-or-later with the app-store permission in `LICENSES/LicenseRef-Kinfold-AppStore-Exception.txt`, as for `apps/`.

## Layout

- `harness/`: the other family member, a command line on the JVM (below).

One Gradle build covers the JVM and Android code here (`settings.gradle.kts`). It builds the shared core from `../core`, so a spike always runs the core of its own commit, and `gradle/verification-metadata.xml` holds the SHA-256 of every artifact that build uses, the core's among them. It needs what the core needs: JDK 21, Gradle 9.9.1 and an Android SDK with platform 36.

## The harness

A member of the test circle that stays online for as long as the spikes run. It is built on the core's client layer, like the apps will be, and talks to the server only by HTTPS. It:

- sets itself up from a setup code (`kinfold setup` on the server) and creates the test circle;
- prints invite codes for the phones, and lets in whoever uses them;
- registers the silence watches the phones grant it (PROTOCOL.md §14.1), and logs every silence alert the server sends;
- asks each phone for a live update with `locate` (a `sig` with `live_req`, API.md §7), and sends the circle an alert with `notify`, on a schedule;
- logs what comes back: how old each position is when it arrives, how far the phone moved since the last one, how long each phone took to answer a live-view request, when each phone showed an alert (the spike apps answer an alert with a `spike_ack`), and whether each phone was moving, once a minute.

Positions stay in the harness's memory. Its logs, JSON lines in `logs/` under its data directory, hold times, delays, distances and device IDs, and never a position. Its keys, in the same directory, can read the test circle: keep the directory private, and delete it after the spikes.

The harness registers as a phone, since it stands in for a family member's phone.

### Running it

```sh
gradle :harness:installDist                       # in spikes/: harness/build/install/kinfold-harness
kinfold-harness setup KFS0…                       # once: the setup code from kinfold setup
kinfold-harness invite                            # for each phone: an invite code to paste into the spike app
kinfold-harness run                               # for as long as the spikes run
kinfold-harness status                            # the circle's devices, its watches and the open invites
kinfold-harness report --since 7d                 # the logs, summed up against the targets
```

Every command takes `--data DIR` (default `./harness-data`). `run` takes `--locate-every 30m`, `--alert-every 3h`, `--alert evt|sos` and `--ping 60s`; `0` turns a schedule off. The server limits `locate` to 6 an hour for each sender and recipient (API.md §3). Invites carry a registration token only when the server's operator has run `kinfold settings --member-tokens on`.

The natural place for it is the server's own machine, which is always on; it needs Java 21 and outbound HTTPS to the server. As a systemd service, with the installed files in `/opt/kinfold-harness` and its data in `/var/lib/kinfold-harness`, owned by a user of its own:

```ini
[Unit]
Description=Kinfold spikes harness
After=network-online.target
Wants=network-online.target

[Service]
User=kinfold-harness
ExecStart=/opt/kinfold-harness/bin/kinfold-harness run --data /var/lib/kinfold-harness --quiet
Restart=always
RestartSec=10
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/kinfold-harness

[Install]
WantedBy=multi-user.target
```

### Testing it

From `core/`, against a server built from `../server` and started on 127.0.0.1:

```sh
KINFOLD_TEST_DIR=../spikes KINFOLD_TEST_TASKS=:harness:test ./test-with-server.sh
```

`HarnessTest` has a phone join through the harness's invite, grant it a watch, name itself, move, and answer a live-view request and an alert, then checks that the log holds all of it and no position. CI runs it in the `spikes` workflow.

| Dependency | Why |
| --- | --- |
| The shared core, from `../core` | The client layer and the platform's cryptography (Tink) |
| kotlinx-coroutines-core 1.11.0 | The harness's loops; the version the core uses |
| Kotlin Gradle plugin 2.4.21 (JVM) | Builds the harness |
| kotlin-test with JUnit 4, tests only | Runs the test |
