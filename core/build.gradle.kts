// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
plugins {
    kotlin("multiplatform") version "2.4.21"
}

// Each library is pinned, and gradle/verification-metadata.xml holds the SHA-256 of every
// artifact the build uses. Gradle refuses any artifact whose hash doesn't match.
kotlin {
    jvm()

    compilerOptions {
        allWarningsAsErrors.set(true)
    }

    sourceSets {
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
        jvmMain.dependencies {
            // Ed25519, X25519, HKDF and HPKE from Tink's own code (PROTOCOL.md Appendix C)
            implementation("com.google.crypto.tink:tink:1.24.0")
        }
        jvmTest.dependencies {
            // Reads the vectors; already a dependency of Tink, at the version Tink asks for
            implementation("com.google.code.gson:gson:2.13.2")
        }
    }
}

tasks.named<Test>("jvmTest") {
    systemProperty("kinfold.vectors", layout.projectDirectory.file("../spec/vectors/kinfold-v0.json").asFile.path)
}
