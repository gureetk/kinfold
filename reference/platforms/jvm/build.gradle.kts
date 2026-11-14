// SPDX-License-Identifier: Apache-2.0
plugins {
    kotlin("jvm") version "2.4.21"
    application
}

// Each library is pinned, and gradle/verification-metadata.xml holds the SHA-256 of every
// artifact the build uses. Gradle refuses any artifact whose hash doesn't match.
dependencies {
    implementation("com.google.crypto.tink:tink:1.24.0") // Tink's own Ed25519 code
    implementation("org.conscrypt:conscrypt-openjdk-uber:2.9.0") // BoringSSL, as in Android's platform provider
    implementation("org.bouncycastle:bcprov-jdk18on:1.87") // shown to be unfit
    implementation("com.google.code.gson:gson:2.13.2") // reads the vectors; already a Tink dependency
}

application { mainClass.set("Ed25519CheckKt") }
