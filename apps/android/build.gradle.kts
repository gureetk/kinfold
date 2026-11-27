// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
import java.util.Base64

plugins {
    id("com.android.application") version "9.5.1"
    // The Android plugin compiles Kotlin itself; this pins the Kotlin compiler it uses to the core's.
    kotlin("jvm") version "2.4.21" apply false
    // Compose's compiler plugin, which ships with Kotlin and has its version
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.21"
}

android {
    namespace = "ca.gureet.kinfold"
    // Android 17's API in its first minor release (37.1), which Compose 1.13 asks to be compiled
    // against; OkHttp, inside the core, asks for 37
    compileSdk {
        version = release(37) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "ca.gureet.kinfold"
        // Android 10, the first with TLS 1.3 of its own, and the oldest the core supports
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1"
        // A build for the emulator test only (emulator-test.sh): it trusts the test server's own
        // certificate, given as -Pkinfold.cacert, and takes its first steps from the intent that
        // starts it. A build without the property trusts the system's certificates, and the
        // person does everything on the screen.
        val testCa = providers.gradleProperty("kinfold.cacert").orNull?.let { Base64.getEncoder().encodeToString(File(it).readBytes()) } ?: ""
        buildConfigField("String", "TEST_CA", "\"$testCa\"")
        // MapLibre's native library, for the phones' processors only (13 MB each); an emulator
        // test adds its own with -Pkinfold.abis=x86_64.
        ndk {
            abiFilters += (providers.gradleProperty("kinfold.abis").orNull ?: "arm64-v8a").split(',')
        }
    }

    // The map's style, glyphs and world map, which both apps carry (../maps).
    sourceSets {
        getByName("main") {
            assets.srcDir("../maps/assets")
        }
    }

    // MapLibre reads a PMTiles archive in pieces, which an archive compressed inside the APK can't give.
    androidResources {
        noCompress += "pmtiles"
    }

    buildFeatures {
        buildConfig = true
        compose = true
    }

    buildTypes {
        // What goes on the phones: not debuggable, so that battery and timing are the app's own,
        // and signed with the build machine's debug key until the project has a key of its own.
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = true
    }
}

kotlin {
    compilerOptions {
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    // The shared core, from ../../core (settings.gradle.kts): the client layer, OkHttp's transport
    // and Tink's cryptography
    implementation("ca.gureet.kinfold:core")
    // Coroutines for the app's own work, the version the core uses
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    // Jetpack Compose with Material 3, the app's UI, at the versions this bill of materials names
    implementation(platform("androidx.compose:compose-bom:2026.11.01"))
    implementation("androidx.compose.material3:material3")
    // Compose inside an Activity, and the launchers that ask for permissions
    implementation("androidx.activity:activity-compose:1.13.0")
    // The map, drawn from the world map inside the app and the region downloaded from the server,
    // both PMTiles archives on the phone. The OpenGL ES build, which every phone and emulator draws.
    implementation("org.maplibre.gl:android-sdk-opengl:13.8.0")
    // QR codes, drawn and read on the phone: the invite, and the server's setup code
    implementation("com.google.zxing:core:3.5.4")
    // kotlin.test on JUnit 4, the runner Android's host tests use
    testImplementation(kotlin("test-junit"))
}
