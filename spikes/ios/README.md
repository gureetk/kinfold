# The iOS spikes

An Xcode project with two apps, built on the shared core as `KinfoldCore.xcframework`:

- **Kinfold** (`ca.gureet.kinfold`), the iOS spike app, with a screen for each spike. Its bundle ID is the topic of the family server's Apple push key. Two screens so far:
  - **The core in this app.** The Kotlin core reaches CryptoKit through its Swift layer and gives two known answers: SHA-256 of "abc" (FIPS 180-2) and the public key of RFC 8032's first Ed25519 test, along with a signature that verifies.
  - **The test vectors in WebKit**, for spike 5. It runs `../web`'s page, with `reference/js` and the vectors, in the phone's WebKit, the engine Safari uses. The app carries the files and serves them to its web view under a scheme of its own on `localhost`, which WebKit counts as a secure context. Nothing comes from the network.
- **CoreTests** (`ca.gureet.kinfold.coretests`), the host for spike 5's iPhone run. Its program is the core's own test binary, which runs every test in `commonTest` and `iosTest` against CryptoKit, with the vectors and the spec in the app. It has no screen: Xcode's console shows what it prints, and it exits when the tests end.

The project file is written by hand rather than generated, and kept small: two targets, one shared `Config/Kinfold.xcconfig`, and two build phases that run `scripts/`. Xcode may tidy it when it saves; that is fine to commit.

License: GPL-3.0-or-later with the app-store permission, as for the rest of `spikes/`.

## What the Mac needs

- A Mac with Apple silicon, and Xcode 26.
- JDK 21 and Gradle 9.9.1 on the `PATH`. The repository has no Gradle wrapper.
- Your Apple team ID, in `Config/Local.xcconfig`. Git ignores that file, so the team stays out of the repository:

  ```sh
  cp spikes/ios/Config/Local.xcconfig.example spikes/ios/Config/Local.xcconfig
  ```

  Then replace the example ID in it with yours. Xcode shows it in Settings › Accounts. Don't choose a team in Signing & Capabilities: that writes the team into the project file.

## Building and running

From the repository's root:

```sh
spikes/ios/build-core.sh
```

It checks Kotlin/Native's own downloads (`core/kotlin-native-deps.sh`), then builds the XCFramework and the core's test binaries for the iPhone and the simulator. The first run takes several minutes. Run it again after the core changes.

Then open `spikes/ios/Kinfold.xcodeproj` in Xcode, choose the iPhone as the destination, and pick a scheme:

- **CoreTests** › Run. The console shows each test as it runs. It ends with `[  PASSED  ]` and the number of tests, or `[  FAILED  ]` with a list. Xcode shows the console with View › Debug Area › Activate Console. The app has no screen, so the iPhone stays on a blank launch screen while the tests run.
- **Kinfold** › Run. Open "The core in this app", then "The test vectors in WebKit". The page shows its verdict at the top, and "Copy the results" copies the whole output.

The first run from Xcode asks the iPhone for Developer Mode (Settings › Privacy & Security › Developer Mode), which takes a restart.

## In CI

The `spikes` workflow's `ios` job, on GitHub's macOS runners, runs `build-core.sh`, then builds both apps for iPhones and for the simulator without signing. It then runs both apps in the simulator. CoreTests runs the core's tests, which must pass. Kinfold, launched with `--checks`, runs the core check and the page by itself, prints what they found and exits. Both must pass.

In the simulator, WebKit's WebCrypto gives every verdict the vectors require, and its Ed25519 signatures never repeat, like CryptoKit's (PROTOCOL.md §3.3). `reference/js` checks the structures it signs again up to their signatures there, as the core's tests do on CryptoKit.
