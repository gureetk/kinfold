# Shared core (Phase 1)

Kotlin Multiplatform: encoding, member-log validation (PROTOCOL.md §6), envelopes (§7), payloads (§8), invites, linking and recovery (§9–10), watch grants and pushes (§14), compiled into the Android app, the iOS app and the web map. Cryptographic primitives come from each platform through a small interface; this module never implements them itself. It does make the byte checks of §3.3 and §3.5 in front of them, so that every platform returns the same verdict on unusual keys and signatures.

Exit test: every group in `spec/vectors` passes on JVM, iOS and JS targets.

License: GPL-3.0-or-later with the app-store permission (draft).

## So far

- `wire`: the encoding of §2 (`Reader`, `Writer`, and `Bytes` for IDs, keys and hashes), base64url as §2 defines it, and the padding of §7.4, which checks the padded size before it unpads.
- `crypto`: the labels of §16.4; `Crypto`, the interface each platform implements; the byte checks of §3.3 and §3.5; and `Primitives`, which builds H, KDF, Sign and Verify (§3.3) on top. Every call WebCrypto makes asynchronous is a suspend function, and private keys are reached only through `SigningKey` and `HpkeKey`, so a platform can keep them in hardware.
- `JvmCrypto`, the JVM's `Crypto`: Tink's own code for Ed25519, X25519, HKDF and HPKE, and the JDK for SHA-2, AES-GCM and randomness. Verification names Tink's own Java code, as Appendix C requires, instead of whatever provider is installed.
- The tests run the `primitives`, `hpke_rfc9180`, `ed25519`, `x25519` and `padding` vectors, check that the labels and reason codes are exactly those of §16.4 and §16.5, and check each byte check of §3.3 against a platform that accepts every signature.

Only the JVM target exists so far. Android and iOS come next, iOS with CryptoKit behind a thin Swift layer.

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
| Gson 2.13.2, tests only | Reads the vectors; one of Tink's own dependencies, at the version Tink uses |

