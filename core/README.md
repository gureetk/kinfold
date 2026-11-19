# Shared core (Phase 1)

Kotlin Multiplatform: encoding, member-log validation (PROTOCOL.md §6), envelopes (§7), payloads (§8), invites, linking and recovery (§9–10), watch grants and pushes (§14), and the client that talks to a server over the HTTP API (`spec/API.md`), compiled into the Android app, the iOS app and the web map. Cryptographic primitives come from each platform through a small interface; this module never implements them itself. It does make the byte checks of §3.3 and §3.5 in front of them, so that every platform returns the same verdict on unusual keys and signatures.

Exit test: every group in `spec/vectors` passes on JVM, iOS and JS targets.

License: GPL-3.0-or-later with the app-store permission (draft).

## So far

- `wire`: the encoding of §2 (`Reader`, `Writer`, and `Bytes` for IDs, keys and hashes), base64url as §2 defines it, and the padding of §7.4, which checks the padded size before it unpads.
- `crypto`: the labels of §16.4; `Crypto`, the interface each platform implements; the byte checks of §3.3 and §3.5; and `Primitives`, which builds H, KDF, Sign and Verify (§3.3) on top. Every call WebCrypto makes asynchronous is a suspend function, and private keys are reached only through `SigningKey` and `HpkeKey`, so a platform can keep them in hardware.
- `TinkCrypto`, the `Crypto` of the JVM and Android, one source compiled against Tink on the JVM and tink-android on Android: Tink's own code for Ed25519, X25519, HKDF and HPKE, and the platform for SHA-2, AES-GCM and randomness. Verification names Tink's own Java code, as Appendix C requires, instead of whatever provider is installed; on a phone that could be Bouncy Castle or a Conscrypt of another version.
- `CryptoKitCrypto`, the `Crypto` of iOS: Apple's CryptoKit, through `src/iosMain/swift/KinfoldCryptoKit.swift`. CryptoKit can only be called from Swift, so that file wraps each primitive as a plain function of bytes behind an Objective-C interface; the build compiles it into a static library for each iOS target, and Kotlin/Native imports the header Swift writes for it (`src/iosMain/cinterop/cryptokit.def`). It is all the Swift the core has. CryptoKit adds randomness to every Ed25519 signature, so a signature doesn't repeat, though every one verifies (§3.3), and its HPKE takes no fixed ephemeral key (§3.5).
- `identity`: the device kinds and IDs of §4.2, device certificates, identity links and chains (§4.3), key bundles with their validity and currency (§4.4), and wraps (§4.6).
- `log`: the member log of §5 and §6. Entries and every body of §5.3; the encrypted details and the private structures inside them; the circle state, its state bytes and state hash; and `MemberLog.apply`, which runs the processing order of §6.3 with the public rules of §6.4, and for a client the private rules of §6.5 and guardian repair. Without epoch secrets it runs the server's public mode.
- `envelope`: envelopes (§7). `Envelope.seal` builds one for devices taken from the verified log; `Envelopes.open` runs every check of §7.6 for a receiving device and returns the payload, the reason it was refused, or that it must wait because the device's private state is frozen; `Envelopes.serverRefusal` is what a server checks before storing one (§7.5), which a sender can run on its own envelope. `SenderRules` holds who may send what (§8.2).
- `payload`: payloads (§8). `Json` reads a payload within the limits of §8.1 as it parses, so nothing too deep or too large is ever built, and refuses a key repeated within an object, as §8.1 allows; it also writes the compact JSON senders send, and reads a link response's JSON (§10.3), which isn't a payload, within the same limits except the number of items in an array, since a circle may have more than 256 epochs. `Approx` snaps a position to its grid cell (§8.3), and `EpochSecrets` keeps only the secrets in a `welcome` or `refresh` that match the log, reading each run from its `first` epoch (§8.5).
- `rendezvous`: what two devices exchange through the server without trusting it. Invites (§9): an `Invite` with its code and link, the join request the invitee posts, which `Joining.openRequest` checks as the inviter's device must (the certificate, its chain and kind, the bundle, the terms it commits to, and the consent), and the join result. Linking (§10.1–10.3): link codes in both directions, the offer, commit, nonce and request, which `Linking.openRequest` checks against its commit, the direction and the account before giving the 6-digit code, and the response, which `Linking.openResponse` checks as the new device must. Recovery kits (§10.4) and share links (§12). A refusal is a `RendezvousException` naming the check that failed; the spec gives these no codes, since only the device sees them.
- `SafetyCode` (§11), the 60 digits and the QR code two people compare, and `Codes`, the scannable text forms of §2.
- `server`: what a device checks of its server (§13). `ServerInfo.check` before it believes anything the server says, `ServerMove.check` before it follows a move to a new address or key, setup codes, the key's fingerprint for a device set up by typing an address, and both signatures of a login. A refusal is a `ServerException` naming the check.
- `push`: silence-watch grants (§14.1), issued by a phone or tablet and judged with `WatchGrant.isValidAt` as a server judges them before registering a watch, and as a guardian's app judges the grants a teen's phones send; pushes (§14.2), which `Pushes.open` opens or drops as a device must, with the reason kept for logs; and the iOS relay's signature (§14.4), which only a server and the relay use.
- `client`: a device's side of its server, which sends and receives what the packages above build and check. `Client` keeps what a device knows in a `Storage` the platform provides (its keys, the server it trusts, each circle's verified log and epoch secrets, its replay record and its place in the inbox) and talks to the server through a `Transport`, the narrow interface each platform implements, as `Crypto` is: one HTTPS exchange, or one WebSocket, over TLS 1.3. On top of `ServerApi`, one method per call of API.md, it sets a device up from a setup code or an invite, checks the server's identity and logs in (§13), catches up and verifies circles' logs (§6), creates circles, invites and admits members and joins circles (§9), seals, uploads and opens envelopes (§7), on the stream or by HTTP, issues and registers watch grants (§14.1), registers for push, and keeps the stream open with backoff (API.md §7). Time comes from the server (`TrustedClock`, §8.4). `JdkTransport` is the JVM's transport, on `java.net.http`, and `OkHttpTransport` Android's, on OkHttp; iOS doesn't have its own yet. Both speak TLS 1.3 only, which Android has from version 10, the oldest the core supports.
- The tests live in `commonTest`, so every target runs them, and read the vectors with a small JSON reader of their own. On Android they run twice: as host tests on the JVM, and as device tests on a phone or an emulator, from a test APK that carries the vectors and the spec. On iOS they run in the simulator, which reads the vectors and the spec where the repository is. Where a test signs something again and the vectors hold the bytes, it compares them byte for byte on a platform that signs deterministically; on one that doesn't, CryptoKit, it compares everything but the signature and checks that the signature verifies. They run the `primitives`, `hpke_rfc9180`, `ed25519`, `x25519`, `padding`, `identities`, `log`, `envelopes`, `welcomes`, `approx`, `safety_codes`, `invite`, `device_link`, `recovery_kits`, `share_link`, `setup`, `server_moves`, `auth`, `watch_grants` and `push` vectors, every group in the file: the log both as a client and in public mode, outcome by outcome and state by state, and every envelope as its recipients and a server see it. They also check that the labels and reason codes are exactly those of §16.4 and §16.5, each byte check of §3.3 against a platform that accepts every signature, each identity rule with an object signed correctly so that nothing else refuses it, a device with frozen private state, both sides of every payload limit, envelopes sealed here and opened with the vectors' keys, and each check of joining, linking, share links, the server's identity, login, grants and pushes with something that breaks it and nothing else. A server's record of posted envelopes, which makes posting idempotent, is the server's and isn't here. Two cross-checks run on the JVM only: base64url against the JDK's encoder, and the messages of RFC 9180 opened with Tink's own HPKE context. Two run on iOS only: that CryptoKit's signatures don't repeat, and that an HPKE seal made there opens there and nowhere else.

The JVM, Android and iOS targets pass every vector group. CI runs the Android tests in emulators running Android 10 (API 29, the oldest the core supports, and the first with TLS 1.3 of its own) and Android 16 (API 36), both without Google services, and the iOS tests in the newest iOS simulator on GitHub's macOS runners, where it also links the test binary for iPhones. Running the tests on an iPhone itself needs an app to host them, which comes with the iOS app.

## Building

```sh
gradle check                        # Gradle 9.9.1, JDK 21 and an Android SDK with platform 37.0 in ANDROID_HOME:
                                    # compiles, then runs the tests against spec/vectors on the JVM and as Android host tests
gradle connectedAndroidDeviceTest   # the same tests on the phones and emulators adb can see
gradle iosSimulatorArm64Test -Pkinfold.simulator="iPhone 17 Pro"
                                    # on a Mac with Xcode 26: the same tests in the iOS simulator named
./test-with-server.sh               # with Go, OpenSSL and curl as well: the JVM tests, the client's against a
                                    # server built from ../server and started on 127.0.0.1 with a throwaway certificate
adb reverse tcp:8443 tcp:8443 && KINFOLD_TEST_TASKS=connectedAndroidDeviceTest ./test-with-server.sh \
    -Pandroid.testInstrumentationRunnerArguments.class=ca.gureet.kinfold.core.ClientServerTest
                                    # the client's test on the phone or emulator adb sees, through OkHttp, with the
                                    # device's 127.0.0.1:8443 forwarded to the server on this computer
```

The client's test against a server (`ClientServerTest`, in `commonTest`) runs only through `test-with-server.sh`, which passes the server's URL, a setup code and its certificate as the Gradle properties `kinfold.server`, `kinfold.setup` and `kinfold.cacert`. The build hands them to the JVM tests as system properties and to the Android device tests as instrumentation arguments; without them the test is skipped, as it is on iOS, which has no transport yet. CI runs it in the `client` workflow, for changes to the core or the server: on the JVM, and in Android 8.0 and 16 emulators, where Android 8.0 takes its TLS 1.3 from Conscrypt.

The iOS targets exist only on a Mac, since Xcode compiles the Swift and holds the Apple SDKs; elsewhere the build is the JVM and Android one. iOS 17 is the oldest the core supports, as CryptoKit's HPKE needs it.

`build.gradle.kts` pins every dependency, and `gradle/verification-metadata.xml` holds the SHA-256 of every artifact the build uses, so Gradle refuses anything that doesn't match. After changing a dependency, regenerate the file from an empty Gradle cache, because a warm cache hides some of the artifacts a fresh build needs, and check the new hashes against the checksums Maven Central and Google's Maven repository publish:

```sh
GRADLE_USER_HOME="$(mktemp -d)" gradle --write-verification-metadata sha256 check assembleAndroidDeviceTest
```

On a Mac, add `iosSimulatorArm64Test linkDebugTestIosArm64` to cover the Kotlin/Native distribution, which only the iOS targets use.

Kotlin/Native then downloads its own LLVM and libffi from JetBrains, outside Gradle, and checks no hash; JetBrains publishes none. CI fetches them first and checks them against SHA-256s pinned in `.github/workflows/core.yml`, which two runners agreed on, puts them where Kotlin/Native looks before downloading, and fails if Kotlin/Native downloads anything itself.

| Dependency | Why |
| --- | --- |
| Kotlin Gradle plugin 2.4.21 | Builds Kotlin Multiplatform |
| Tink 1.24.0, JVM only | Ed25519, X25519, HKDF and HPKE from a vendor library, with the protobuf, Gson and annotation libraries it depends on |
| tink-android 1.24.0, Android only | The same Tink, built for Android with protobuf-lite |
| Android Gradle plugin 9.5.1 (`com.android.kotlin.multiplatform.library`) | Builds the Android target. It comes from Google's Maven repository, which the build asks only for Android's own groups |
| androidx.test runner 1.7.0, device tests only | Runs the tests on a phone or an emulator |
| OkHttp 5.5.1, Android only, with Okio 3.18.1, androidx.startup 1.2.0 (and androidx.tracing 1.0.0) and androidx.annotation 1.10.0 | The client's HTTPS and WebSocket on Android, which has no public WebSocket client of its own. Square's; since 2026 its project lives at lysine.dev, and it is still published as `com.squareup`. It needs `compileSdk` 37 |
| kotlinx-coroutines-core 1.11.0, with atomicfu | The client's cancellation, timeouts, delays and locks, which the standard library's bare coroutines lack. JetBrains', like the compiler |
| kotlin-test with JUnit 4.13.2, tests only | Runs the tests |
| Kotlin/Native 2.4.21 distribution, iOS only | The compiler and the Apple platform libraries for the iOS targets |
| Kotlin/Native's LLVM 21 and libffi 3.3, iOS only | The compiler's code generator, which Kotlin/Native downloads itself; CI checks them as above |

