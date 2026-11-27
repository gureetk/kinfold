# Kinfold for iOS

The iOS app, `ca.gureet.kinfold`, and its two extensions: the walking skeleton, kept minimal, as the Android app is. SwiftUI, on iOS 17 and later, with the shared core as `KinfoldCore.xcframework` and MapLibre Native for the map. License: GPL-3.0-or-later with the app-store permission.

The core holds every rule (`core/`, package `app`): what the phone does with what comes in from the family, the location engine's decisions and what goes up, the stream to the server, and the ways in. This app gives it what only iOS has: storage, the location, the map, notifications and the screens.

## What it does

**Getting in.** The first phone sets up from the server's setup code (`kinfold setup` prints it as a QR code and as text beginning `KFS0`), scanned with the camera or pasted, and founds the family's circle. Every other phone joins with an invite: the inviter's phone shows it as a QR code; the new phone shows the terms on offer before sending anything (the family's name, the inviter's, and that the person joins as an adult; invites with a teen's rules are refused, as on Android), then the safety code, which both phones show. The inviter compares the codes, then taps **Allow** (PROTOCOL.md §9, §11).

**Sharing.** Core Location's live updates (`CLLocationUpdate.liveUpdates`), kept coming in the background by a `CLBackgroundActivitySession`, with significant-change monitoring as the safety net that starts the app again if iOS ended it. The core's engine decides what goes up, as on Android, and sends it: a `loc` with the fixes held back as its `prev`, or a heartbeat after 25 minutes without one. One stream to the server stays open while the app runs, and starts again when the phone changes network.

**Live-view requests.** **Refresh** on someone asks their phones for updates for two minutes. A phone answers at most one request a minute from each person, only while sharing, with a fix every 5 seconds, and lists every request under Settings (§8.2).

**Silence watches.** The app asks once whether the family may be told when this phone goes quiet; yes grants each other adult a 60-minute watch, renewed weekly (§14.1). A silence alert from the server is shown as a notification.

**Pushes,** for when iOS has suspended the app or ended it, and its stream with it (API.md §12). Once the phone is set up, the app gets Apple's tokens, one for alerts and, once location is allowed all the time, one for location pushes, and registers them with the server as an `apns` registration. The server's push is sealed to the phone and the same size whatever it holds, so Apple sees only that there was one. Two extensions open it, each in a process of its own, on the app's files, with the core (`IosExtension`):

- the notification extension (`Notifications/`, `ca.gureet.kinfold.notifications`) words the alert: a silence alert names the person from the family's records; anything else shows the app's fixed text (`push_fallback`);
- the location-push extension (`LocationPush/`, `ca.gureet.kinfold.location`) handles what the push holds, a live-view request or the server's wake-up before a silence alert, and answers with one fix if the person shares, or a heartbeat if Core Location gives none in 20 seconds.

Each logs how long it ran and the memory it used (`"e":"extension"`). The envelope sequence number is taken under a lock that the app and both extensions share (`FileStorage.next`, in the core), and the app reads the files again when an extension has changed them. A phone without a location-push token gets a background push instead, which the app handles itself.

**The map** shows each person's latest position, drawn by MapLibre from files on the phone only: the world map inside the app and the family's region, downloaded under More › Map of your area, resumed with `Range` and `If-Range` after a break, and kept only once its SHA-256 matches the server's list (API.md §13). The style, glyphs and world map come from `../maps`, copied into the app as `assets/`.

**The log** is the Android app's, written by the core line by line (one JSON object a line, a file per UTC day, 30 days): times, delays, distances, accuracies, states and IDs, never a coordinate, a key, a name or an address. Settings › Export the log hands the files to the share sheet.

## What the phone keeps

In the container of the app group `group.ca.gureet.kinfold`, which only the app and its extensions open, readable after the phone is first unlocked since it started, so that sharing works while it is locked:

- `Library/Application Support/kinfold/`, left out of backups: the core's files (`FileStorage`, in the core). The device's keys (`device`), the epoch secrets (`secrets-…`) and the app's records (`app-family`: names and the family's latest positions) are sealed with AES-256-GCM from CryptoKit, under a key in the Keychain that stays on this phone (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`), in the app group's access group so that the extensions can use it, bound to each file's name (`Shared/Sealer.swift`). The rest is what the server holds already.
- `Library/Application Support/logs/`: the log, which the app and the extensions write to.

The person's choices (sharing on or off, the answer on watches) are in the app group's settings, which the extensions read. In the app's own container:

- `Library/Application Support/maps/`: the region. It isn't sealed: anyone with a session on the server can download the same file.

## Building

On a Mac with Apple silicon, Xcode 26, JDK 21 and Gradle 9.9.1 on the `PATH`:

```sh
apps/ios/build-core.sh          # KinfoldCore.xcframework, after checking Kotlin/Native's own downloads
cp apps/ios/Config/Local.xcconfig.example apps/ios/Config/Local.xcconfig   # then put your team ID in it
open apps/ios/Kinfold.xcodeproj
```

Choose the iPhone and run the **Kinfold** scheme. The team ID stays out of the repository: git ignores `Local.xcconfig`. Run `build-core.sh` again after the core changes.

With automatic signing, Xcode registers what the entitlements files ask for under your team: the three bundle IDs (`ca.gureet.kinfold`, `.notifications` and `.location`), the app group `group.ca.gureet.kinfold` for all three, Push Notifications and Location Push for the app. If Signing & Capabilities shows the app group unticked for a target, tick it. A build run from Xcode gets Apple's sandbox tokens (`KINFOLD_PUSH_ENVIRONMENT` in `Config/Kinfold.xcconfig`), so the server needs a sandbox key: `kinfold serve … --apple-team TEAM_ID --apple-app ca.gureet.kinfold --apple-sandbox AuthKey_KEYID.p8`. The key stays on the server.

The iOS spike app (`spikes/ios`) is now `ca.gureet.kinfold.spikes`, so both can be on the iPhone.

## Testing

`simulator-test.sh` runs the app in the simulator against a server built from `../../server`, with the spikes' harness as the other member, as `../android/emulator-test.sh` does in an emulator: as the joiner, or as the creator that sets up and lets the harness in. Either way the phone downloads the region the server offers (the world map stands in for one) and draws the map from it, names itself, grants a watch, shares while the simulator walks north, and answers live-view requests in front and then in the background, with another app in front. Then it runs the extensions' core inside the app, on the app's files: the simulator starts an extension only for a push from Apple, which CI can't send. A push that isn't one must be dropped, a fix must go up without taking a sequence number the app took, and the app must read its files again and open its stream once more. Its log must hold no coordinate. The simulator trusts the test server's certificate through its own keychain, so the app under test is the family's own Debug build, which reads its first steps from launch arguments (`Kinfold/TestDriver.swift`, in Debug builds only). CI's `apps` workflow runs it on GitHub's macOS runners, after building the app for iPhones and the simulator.

## Dependencies

| What | Why |
| --- | --- |
| The core, as `KinfoldCore.xcframework` | Every rule of the protocol and the app, shared with Android |
| MapLibre Native for iOS 7.1.0 (BSD-2-Clause), through Swift Package Manager from `maplibre-gl-native-distribution` | Draws the map from PMTiles files on the phone. `Package.resolved` pins the package's commit, whose `Package.swift` pins the binary's SHA-256, which Swift Package Manager checks |

Everything else is Apple's: SwiftUI, Core Location, CryptoKit, the Security framework, AVFoundation and Core Image (QR codes), Network and UserNotifications. The extensions link the app's copy of the core; only the app embeds it.
