// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
plugins {
    kotlin("multiplatform") version "2.4.21"
    id("com.android.kotlin.multiplatform.library") version "9.5.1"
}

// The device tests read the vectors and the spec as Java resources of the test APK.
val copyVectors = tasks.register<Copy>("copyVectors") {
    from("../spec/vectors/kinfold-v0.json", "../spec/PROTOCOL.md")
    into(layout.buildDirectory.dir("vectors"))
}

// Each library is pinned, and gradle/verification-metadata.xml holds the SHA-256 of every
// artifact the build uses. Gradle refuses any artifact whose hash doesn't match.
kotlin {
    jvm()

    android {
        namespace = "ca.gureet.kinfold.core"
        compileSdk = 36
        minSdk = 26
        withHostTest {}
        // The device tests run commonTest on a phone or an emulator, against the platform's own libraries.
        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
    }

    compilerOptions {
        allWarningsAsErrors.set(true)
    }

    sourceSets {
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
        // One TinkCrypto for both, compiled against each platform's Tink
        jvmMain {
            kotlin.srcDir("src/tinkMain/kotlin")
            dependencies {
                // Ed25519, X25519, HKDF and HPKE from Tink's own code (PROTOCOL.md Appendix C)
                implementation("com.google.crypto.tink:tink:1.24.0")
            }
        }
        androidMain {
            kotlin.srcDir("src/tinkMain/kotlin")
            dependencies {
                // The same Tink, built for Android with protobuf-lite
                implementation("com.google.crypto.tink:tink-android:1.24.0")
            }
        }
        getByName("androidDeviceTest") {
            // The vectors and the spec, packed into the test APK
            resources.srcDir(copyVectors)
            dependencies {
                // Runs JUnit tests on the device
                implementation("androidx.test:runner:1.7.0")
            }
        }
    }
}

val vectorsFile = layout.projectDirectory.file("../spec/vectors/kinfold-v0.json").asFile.path

tasks.withType<Test>().configureEach {
    systemProperty("kinfold.vectors", vectorsFile)
}
