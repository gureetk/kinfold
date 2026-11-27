# Kinfold for Android

The Android app, `ca.gureet.kinfold`: Kotlin, Jetpack Compose with Material 3, on the shared core in `../../core`. It runs on Android 10 and later, without Google Play services. This is the walking skeleton: the real app, kept minimal.

License: GPL-3.0-or-later with the app-store permission in `LICENSES/LicenseRef-Kinfold-AppStore-Exception.txt` (draft).

## What it does

**Getting in.** The first phone sets up from the server's setup code (`kinfold setup` prints it as a QR code and as text beginning `KFS0`): scanned with the app's own camera scanner, or typed. It creates the family's circle, and its person becomes an admin. Every other phone joins with an invite:

1. an admin taps **Invite**, and the phone shows the invite as a QR code, good once for 24 hours (PROTOCOL.md §9.1);
2. the new phone scans it and shows the terms on offer before sending anything: the family's name and the inviter's as the invite gives them, and that the person joins as an adult. Invites with a teen's rules are refused, since this version doesn't keep those rules yet;
3. both phones show the same 60-digit safety code (§11). The admin compares them and taps **Let them in**, or **Decline**.

Codes come only from the app's scanner or the keyboard, never from a link or another app. Invites are QR codes only until the project has a link origin (§9.1).

**Sharing** is spike 2's design (`spikes/README.md`), now in the app:

- a foreground service of type `location`, started by the person and again after a reboot or an update, with a notification saying the location is shared;
- Android's own location service: its fused provider on Android 12 and later where the phone has one, GPS and network otherwise. An engine (`share/Motion.kt`, after plan §9's modes) chooses how often: every 30 seconds while moving; every 10 seconds while driving, uploaded together once a minute (`prev`); nothing while still, with the significant-motion sensor to wake it; every 5 seconds for a live-view request;
- one stream to the server (API.md §7), pinging every 4 minutes, which uploads go over while it is open (HTTPS otherwise). When the phone changes networks, the stream starts again on the new one at once, rather than waiting minutes for a ping to go unanswered on a connection that died quietly;
- a watchdog alarm every 15 minutes that Android delivers in Doze: it sends a heartbeat (`hb`) after 25 minutes without an upload, restarts a stream that has been down for 10 minutes, and starts the service again if it was stopped.

**Live-view requests.** **Refresh** on someone asks their phones for updates every few seconds for two minutes (`sig` with `live_req`, waking an iPhone's location extension where it has no stream). A phone answers at most one request a minute from each person, only while sharing, and lists every request it got under Settings › Who asked for live updates (§8.2).

**Silence watches.** The app asks once whether the family may be told when this phone goes quiet. If the person agrees, it grants each other adult a watch of 60 minutes, for a week at a time and renewed after five days (§14.1); turning it off in Settings ends every watch on the phone at once. A phone that receives a grant registers it, and shows the server's silence alert as a notification.

**Profiles.** The person's name goes to the circle in a `profile`, encrypted like everything else, whenever someone joins and at least every six days (§8.6). The server never sees a name.

**The map** (`map/`) shows each person's latest position as a dot with their initials, with their name and how long ago beside it. MapLibre Native draws it from files on the phone and nothing else: the world map inside the app (`../maps`), drawn at every zoom so the map is never blank, and the family's region on top of it from zoom 7. The person downloads the region under More › Map of your area: the app lists what the server offers (API.md §13), downloads one region whole, resuming after a break with `Range` and `If-Range`, and keeps it only once its SHA-256 matches the list's. No style, tile or font is fetched while the map is drawn, so no server learns where anyone looks.

**Sharing health** (plan §17) lists every permission and setting sharing depends on, green or red, with a tap to fix each red one: location on, precise location, location all the time, notifications, no battery optimization for the app, background activity allowed (with a note on Samsung's sleeping apps), sharing on, the connection, and battery saver.

## What the phone keeps

In the app's private files, which no backup or transfer to a new phone takes (`res/xml/no_backup.xml`):

- the core's storage: the device's keys, the server it trusts, each circle's verified log and epoch secrets, its replay record, its place in the inbox and its sequence number;
- `app-family`: names from profiles, each person's latest position, the watches, and the live-view requests;
- `maps/region.pmtiles`: the downloaded region. It isn't sealed: anyone with a session on the server can download the same file.

The keys, the epoch secrets and `app-family` are sealed with AES-256-GCM under a key in Android's Keystore (StrongBox where the phone has one), bound to each file's name (`store/`). The key can't leave the phone, so a copy of the files is unreadable elsewhere. The rest is what the server holds already. Asking for the passcode before each use of the identity key (plan §8) waits for Phase 2: the core keeps that key with the device's own keys.

## The log

JSON lines, a file per UTC day, kept for 30 days, in the format of the harness's log, and exported as one file through the share sheet (Settings › Export the log). Each line has `t`, the phone's trusted time, and `e`. Never a coordinate, a key, a name or an address.

| `e` | What |
| --- | --- |
| `process`, `app`, `exit` | The process starting, the app opened and why, and why Android last ended the process (Android 11 and later) |
| `setup`, `circle`, `join`, `joined`, `invite`, `join_request`, `admitted`, `declined` | Getting in |
| `service`, `sharing`, `restart` | The sharing service and why it started or stopped |
| `connection`, `stream`, `net`, `start_failed` | The connection: the stream's state, its drops and reconnects, and the network |
| `engine`, `motion`, `fix`, `provider` | The location engine's mode, and each fix's age, accuracy, speed and distance moved |
| `upload` | What went up, by stream or HTTPS, and how long it took |
| `position` | A family member's position arriving: its age, how long it was in transit, its accuracy |
| `live_req`, `profile`, `watch`, `silence`, `log` | Live-view requests both ways, profiles, watches, silence alerts, and the circle's log growing |
| `keepalive`, `state`, `doze`, `saver`, `screen`, `export` | The phone's state: battery, Doze, power saving, the battery exemption, the standby bucket, background restrictions, the network, and how late the watchdog was |
| `region`, `map` | The region's download (its size and how far it got) and the map: when it is ready to draw, its style loading, and how many features it drew from the world map and from the region at which zoom level |
| `refused`, `failed`, `push_dropped`, `notice` | What went wrong. Error messages lose any URL, host name or IP address in them (`log/EventLog.kt`) |

## Building

JDK 21, Gradle 9.9.1, and an Android SDK with platforms 37.0 (for OkHttp, in the core) and 37.1 (for Compose) and build tools 36.0.0:

```sh
gradle assembleRelease    # build/outputs/apk/release/kinfold-android-release.apk
gradle testDebugUnitTest lintRelease
```

The APK carries MapLibre's native library for arm64 only, which every family phone runs; `-Pkinfold.abis=x86_64` builds one for an emulator instead (a comma-separated list for several). The map files come from `../maps/assets`, stored uncompressed so that MapLibre reads the world map in place.

`gradle/verification-metadata.xml` holds the SHA-256 of every artifact the build uses, the core's included, and Gradle refuses any that doesn't match. It holds the Linux build of aapt2, Android's resource compiler, which CI uses; building on macOS or Windows needs that system's build of it added the same way.

The release build isn't debuggable, so battery and timing are the app's own, and is signed with the build machine's debug key until the project has a key of its own. Android won't update an app signed with another key, so moving to a build from another machine means exporting the log, uninstalling and joining again.

## Installing

Install the APK (allow installing from the app that opens it) and open **Kinfold**. Then set up or join, and on the sharing health screen tap each red line: allow location, then **Allow all the time** in Android's settings, notifications, and no battery optimization. On Samsung phones, also keep Kinfold out of Settings › Battery › Background usage limits.

## Testing

`gradle testDebugUnitTest` runs the engine's tests (`Motion`), the storage's, sealing included, and the log's (`Addresses`). CI's `apps` workflow runs those and Android Lint, builds the release APK, and runs `emulator-test.sh` in Android 10 and 16 emulators against a server built from `../../server`, with the spikes' harness as the other member. On Android 10 the phone joins the harness's family; on Android 16 it sets up from the setup code, founds the family and lets the harness in. Either way it downloads the map region the server offers (the world map stands in for one) and draws the map from it, names itself, grants a watch and shares while the emulator walks north, answers live-view requests awake and in deep Doze, and keeps a log without a coordinate in it. Locally, with an emulator running:

```sh
adb reverse tcp:8443 tcp:8443
KINFOLD_TEST_DIR=. KINFOLD_TEST_CMD=./emulator-test.sh KINFOLD_TEST_ROLE=creator ../../core/test-with-server.sh
```

The script builds a test build, `-Pkinfold.cacert=FILE`, which trusts only the test server's certificate and takes its first steps from adb (`ui/TestDriver.kt`); its settings screen says TEST BUILD. A build without that property trusts the system's certificates, and the person does everything on the screen.

## Dependencies

| Dependency | Why |
| --- | --- |
| The shared core, from `../../core` | The protocol, the client layer, OkHttp's transport and Tink's cryptography |
| kotlinx-coroutines-core 1.11.0 | The app's own work; the version the core uses |
| Kotlin Gradle plugin 2.4.21, and its Compose compiler plugin | Compiles the app's Kotlin and its Compose code |
| Android Gradle plugin 9.5.1 (`com.android.application`), with aapt2 and Android Lint | Builds and checks the app. From Google's Maven repository, which the build asks only for Android's own groups |
| Compose BOM 2026.11.01: Compose 1.13.0 and Material 3 1.5.0, with what they bring from AndroidX | The UI |
| activity-compose 1.13.0 | Compose in an Activity, and the launchers that ask for permissions |
| MapLibre Native for Android 13.8.0, its OpenGL ES build (`android-sdk-opengl`, BSD-2-Clause) | Draws the map, on the phone, from PMTiles files. The OpenGL ES build rather than the default, Vulkan, because OpenGL ES runs on every phone Android 10 does and in the emulators CI tests in. It brings MapLibre's GeoJSON and Turf 6.0.1 (Apache-2.0) with Gson 2.10.1, its gestures 0.0.4 (BSD-2-Clause), Timber 5.0.1, and AndroidX fragment 1.8.9 with what it needs. It asks for OkHttp 4.12, and gets the core's 5.x; it would only use it to fetch from the network, which the app's style never asks of it |
| ZXing core 3.5.4 (Apache-2.0, no dependencies of its own) | Draws the invite's QR code and reads codes from the camera's frames, on the phone. The camera itself is Android's own API |
| kotlin-test with JUnit 4, tests only | Runs the tests |
