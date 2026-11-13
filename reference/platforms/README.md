# Platform crypto checks

PROTOCOL.md §3.3 makes every implementation run three byte checks before it calls its platform's Ed25519 code, and trusts a platform library only once it has returned the required verdict on every edge case in the vectors (`ed25519.signatures`, 28 signatures). These programs run those edge cases through the libraries an app could use, with and without the byte checks in front. What they found is in PROTOCOL.md Appendix C.

## JVM and Android libraries (`jvm/`)

The JDK's own code (SunEC), Tink's own code, Conscrypt (BoringSSL, the library behind Android's platform provider) and Bouncy Castle, through its JCA provider and its lightweight API. The program exits with status 1 unless the first three are fit to sit behind the byte checks and Bouncy Castle fails in exactly the way a verifier that multiplies by the cofactor fails. CI runs it.

```sh
cd reference/platforms/jvm
gradle run --args="$PWD/../../../spec/vectors/kinfold-v0.json"    # Gradle 9.9.1, Java 21
```

The versions are pinned in `build.gradle.kts`, and `gradle/verification-metadata.xml` holds the SHA-256 of every artifact the build uses, so Gradle refuses anything that doesn't match. After changing a dependency, regenerate the file from an empty Gradle cache, because a warm cache hides some of the artifacts a fresh build needs:

```sh
GRADLE_USER_HOME="$(mktemp -d)" gradle --write-verification-metadata sha256 installDist
```

## CryptoKit (`cryptokit/`)

A single Swift script for a Mac with Xcode or the Command Line Tools. From the repository root:

```sh
swift reference/platforms/cryptokit/ed25519.swift spec/vectors/kinfold-v0.json
```

It prints CryptoKit's verdict on each signature, alone and behind the byte checks, and exits with status 0 when CryptoKit may sit behind the checks.
