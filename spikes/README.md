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
- `android/`: the Android spike app, with spike 2 (below).
- `ios/`: the Xcode project, with the iOS spike app and the host that runs the core's tests on an iPhone ([its README](ios/README.md)).
- `web/`: spike 5's page, which runs the JavaScript checks in a browser.

One Gradle build covers the JVM and Android code here (`settings.gradle.kts`). It builds the shared core from `../core`, so a spike always runs the core of its own commit, and `gradle/verification-metadata.xml` holds the SHA-256 of every artifact that build uses, the core's among them. It needs what the core needs: JDK 21, Gradle 9.9.1 and an Android SDK with platform 37.0. The metadata holds the Linux build of aapt2, Android's resource compiler, which CI uses; building the app on macOS or Windows needs that system's build of it added in the same way.

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

`invite` and `status` work beside a running `run`, which alone writes the circle's log; `invite --wait` lets the phone in itself, so use it only while `run` is stopped. Every command takes `--data DIR` (default `./harness-data`). `run` takes `--locate-every 30m`, `--alert-every 3h`, `--alert evt|sos` and `--ping 60s`; `0` turns a schedule off. The server limits `locate` to 6 an hour for each sender and recipient (API.md §3). Invites carry a registration token only when the server's operator has run `kinfold settings --member-tokens on`.

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

## Spike 2's Android app

`android/`, the app `ca.gureet.kinfold.spike`, so that it never collides with the real app. It runs on Android 10 and later, without Google Play services, in plain Android views. One screen joins the test circle with an invite from the harness, asks for what sharing needs, starts and stops sharing, tunes the stream's ping, and exports the log.

**Sharing** is a foreground service of type `location`, started from the app and again after a reboot or an update of the app:

- **Location** comes from Android's own location service: its fused provider on Android 12 and later where the phone has one, GPS and network otherwise. A small engine (`Motion`, after plan §9's adaptive modes) chooses how often:
  - **moving:** a fix every 30 seconds, each uploaded;
  - **driving,** above about 25 km/h: a fix every 10 seconds, uploaded together once a minute (`prev`);
  - **still,** after three minutes within about 50 metres: no fixes at all, and the significant-motion sensor wakes the engine;
  - **live,** for a minute after a live-view request (`sig` with `live_req`): a fix every 5 seconds, each uploaded.
- **The stream** (API.md §7) stays open, with WebSocket pings at the interval chosen on the screen (1, 4, 10 or 20 minutes) and the backoff of API.md §7; uploads go over it (`stream_post`) while it is open, and by HTTPS otherwise.
- **The watchdog** is an alarm every 15 minutes that Android delivers even in Doze. It logs the phone's state, sends a heartbeat (`hb`) if nothing has gone up for 25 minutes, which keeps the server hearing from a still phone well inside its 35 minutes, restarts a stream that has been down for 10 minutes, and starts the service again if it was stopped, from Android 13's task manager say. Android lets it do that from the background only for an app exempt from battery optimization, so the screen asks for the exemption.
- **Alerts** (`evt`, `sos`) show as notifications, and the app answers each with a `spike_ack` to the sender, saying when it opened and showed it and whether it came on the stream.
- **The silence watch:** the phone grants the harness a watch of 60 minutes, for a week, and renews it after five days.

Its keys sit in the app's private files, unsealed, and no backup or transfer to a new phone takes them; the real app seals them with the Keystore (plan §8).

**The log** is JSON lines, a file per UTC day in the format of the harness's, exported in one file through the share sheet. Each line has `t`, the phone's trusted time, and `e`: `service`, `stream`, `engine`, `mode`, `motion`, `fix` (age, accuracy, speed, distance moved), `upload` (type, stream or HTTPS, how long it took), `keepalive` (battery, Doze, power saving, the exemption, the standby bucket, background restrictions, the network, and how late the alarm was), `live_req`, `alert`, `watch`, `doze`, `saver`, `screen`, `net`, `exit` (why Android ended the process, from Android 11), `restart`, `refused` and `failed`. Never a coordinate.

### Installing it

On each phone: install the APK (allow installing from the app that opens it), open **Kinfold spike**, then:

1. on the server machine, `kinfold-harness invite`; paste its code into the app and tap **Join the test circle**;
2. tap 1 to 4 in turn: notifications, location, location all the time (in Android's settings, choose **Allow all the time**), and no battery optimization for the app;
3. tap **Start sharing**;
4. under **App info**, lift any restriction the manufacturer puts on the app's battery use or background activity, and note what had to change.

### Testing it

The `spikes` workflow builds the app, runs its unit tests (`Motion`, `AppStorage`), and runs `android/emulator-test.sh` in Android 10 and 16 emulators. That script runs against a server built from `../server` and the harness: the app joins with an invite, names itself, grants the watch and shares while the emulator walks north; it answers a live-view request and acknowledges an alert, awake and then in deep Doze. Locally, with an emulator running:

```sh
adb reverse tcp:8443 tcp:8443
KINFOLD_TEST_DIR=. KINFOLD_TEST_CMD=android/emulator-test.sh ../core/test-with-server.sh   # in spikes/
```

The script builds a test build of the app, `-Pkinfold.cacert=FILE`, which trusts only the test server's certificate and takes its invite from adb. A build without that property, the one for the phones, trusts the system's certificates and takes invites only on its screen.

## Dependencies

| Dependency | Why |
| --- | --- |
| The shared core, from `../core` | The client layer, OkHttp's transport on Android, and the platform's cryptography (Tink) |
| kotlinx-coroutines-core 1.11.0 | The harness's loops and the app's work; the version the core uses |
| Kotlin Gradle plugin 2.4.21 (JVM) | Builds the harness, and compiles the app's Kotlin |
| Android Gradle plugin 9.5.1 (`com.android.application`), with aapt2 | Builds the app. From Google's Maven repository, which the build asks only for Android's own groups |
| kotlin-test with JUnit 4, tests only | Runs the tests |
