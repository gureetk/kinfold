# Shared core (Phase 1)

Kotlin Multiplatform: encoding, member-log validation (PROTOCOL.md §6), envelopes (§7), payloads (§8), invites, linking and recovery (§9–10), watch grants and pushes (§14), compiled into the Android app, the iOS app and the web map. Cryptographic primitives come from each platform through a small interface; this module never implements them itself. It does make the byte checks of §3.3 and §3.5 in front of them, so that every platform returns the same verdict on unusual keys and signatures.

Exit test: every group in `spec/vectors` passes on JVM, iOS and JS targets.

License: GPL-3.0-or-later with the app-store permission (draft).

## So far

- `wire`: the encoding of §2 (`Reader`, `Writer`, and `Bytes` for IDs, keys and hashes), base64url as §2 defines it, and the padding of §7.4, which checks the padded size before it unpads.
- `crypto`: the labels of §16.4; `Crypto`, the interface each platform implements; the byte checks of §3.3 and §3.5; and `Primitives`, which builds H, KDF, Sign and Verify (§3.3) on top. Every call WebCrypto makes asynchronous is a suspend function, and private keys are reached only through `SigningKey` and `HpkeKey`, so a platform can keep them in hardware.
- `JvmCrypto`, the JVM's `Crypto`: Tink's own code for Ed25519, X25519, HKDF and HPKE, and the JDK for SHA-2, AES-GCM and randomness. Verification names Tink's own Java code, as Appendix C requires, instead of whatever provider is installed.
- `identity`: the device kinds and IDs of §4.2, device certificates, identity links and chains (§4.3), key bundles with their validity and currency (§4.4), and wraps (§4.6).
- `log`: the member log of §5 and §6. Entries and every body of §5.3; the encrypted details and the private structures inside them; the circle state, its state bytes and state hash; and `MemberLog.apply`, which runs the processing order of §6.3 with the public rules of §6.4, and for a client the private rules of §6.5 and guardian repair. Without epoch secrets it runs the server's public mode.
- `envelope`: envelopes (§7). `Envelope.seal` builds one for devices taken from the verified log; `Envelopes.open` runs every check of §7.6 for a receiving device and returns the payload, the reason it was refused, or that it must wait because the device's private state is frozen; `Envelopes.serverRefusal` is what a server checks before storing one (§7.5), which a sender can run on its own envelope. `SenderRules` holds who may send what (§8.2).
- `payload`: payloads (§8). `Json` reads a payload within the limits of §8.1 as it parses, so nothing too deep or too large is ever built, and refuses a key repeated within an object, as §8.1 allows; it also writes the compact JSON senders send, and reads a link response's JSON (§10.3), which isn't a payload, within the same limits except the number of items in an array, since a circle may have more than 256 epochs. `Approx` snaps a position to its grid cell (§8.3), and `EpochSecrets` keeps only the secrets in a `welcome` or `refresh` that match the log (§8.5).
- `rendezvous`: what two devices exchange through the server without trusting it. Invites (§9): an `Invite` with its code and link, the join request the invitee posts, which `Joining.openRequest` checks as the inviter's device must (the certificate, its chain and kind, the bundle, the terms it commits to, and the consent), and the join result. Linking (§10.1–10.3): link codes in both directions, the offer, commit, nonce and request, which `Linking.openRequest` checks against its commit, the direction and the account before giving the 6-digit code, and the response, which `Linking.openResponse` checks as the new device must. Recovery kits (§10.4) and share links (§12). A refusal is a `RendezvousException` naming the check that failed; the spec gives these no codes, since only the device sees them.
- `SafetyCode` (§11), the 60 digits and the QR code two people compare, and `Codes`, the scannable text forms of §2.
- `server`: what a device checks of its server (§13). `ServerInfo.check` before it believes anything the server says, `ServerMove.check` before it follows a move to a new address or key, setup codes, the key's fingerprint for a device set up by typing an address, and both signatures of a login. A refusal is a `ServerException` naming the check.
- `push`: silence-watch grants (§14.1), issued by a phone or tablet and judged with `WatchGrant.isValidAt` as a server judges them before registering a watch, and as a guardian's app judges the grants a teen's phones send; pushes (§14.2), which `Pushes.open` opens or drops as a device must, with the reason kept for logs; and the iOS relay's signature (§14.4), which only a server and the relay use.
- The tests live in `commonTest`, so every target runs them, and read the vectors with a small JSON reader of their own. They run the `primitives`, `hpke_rfc9180`, `ed25519`, `x25519`, `padding`, `identities`, `log`, `envelopes`, `approx`, `safety_codes`, `invite`, `device_link`, `recovery_kits`, `share_link`, `setup`, `server_moves`, `auth`, `watch_grants` and `push` vectors, every group in the file: the log both as a client and in public mode, outcome by outcome and state by state, and every envelope as its recipients and a server see it. They also check that the labels and reason codes are exactly those of §16.4 and §16.5, each byte check of §3.3 against a platform that accepts every signature, each identity rule with an object signed correctly so that nothing else refuses it, a device with frozen private state, both sides of every payload limit, envelopes sealed here and opened with the vectors' keys, and each check of joining, linking, share links, the server's identity, login, grants and pushes with something that breaks it and nothing else. A server's record of posted envelopes, which makes posting idempotent, is the server's and isn't here. Two cross-checks run on the JVM only: base64url against the JDK's encoder, and the messages of RFC 9180 opened with Tink's own HPKE context.

Only the JVM target exists so far, and it passes every vector group. Android and iOS come next, iOS with CryptoKit behind a thin Swift layer.

## Building

```sh
gradle check    # Gradle 9.9.1 and JDK 21: compiles, then runs the tests against spec/vectors
```

`build.gradle.kts` pins every dependency, and `gradle/verification-metadata.xml` holds the SHA-256 of every artifact the build uses, so Gradle refuses anything that doesn't match. After changing a dependency, regenerate the file from an empty Gradle cache, because a warm cache hides some of the artifacts a fresh build needs, and check the new hashes against the checksums Maven Central publishes:

```sh
GRADLE_USER_HOME="$(mktemp -d)" gradle --write-verification-metadata sha256 check
```

| Dependency | Why |
| --- | --- |
| Kotlin Gradle plugin 2.4.21 | Builds Kotlin Multiplatform |
| Tink 1.24.0, JVM only | Ed25519, X25519, HKDF and HPKE from a vendor library, with the protobuf, Gson and annotation libraries it depends on |
| kotlin-test with JUnit 4.13.2, tests only | Runs the tests |

