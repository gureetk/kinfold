// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
import java.util.Base64

plugins {
    id("com.android.application")
}

android {
    namespace = "ca.gureet.kinfold.spike"
    // Android 17's API, which OkHttp, inside the core, asks to be compiled against
    compileSdk = 37

    defaultConfig {
        // Its own ID, so that it never collides with the real app
        applicationId = "ca.gureet.kinfold.spike"
        // The oldest Android the core supports
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "spike 2"
        // A build for an emulator test only (emulator-test.sh): it trusts the test server's own
        // certificate, given as -Pkinfold.cacert, and takes an invite from the intent that starts it.
        // A build without the property trusts the system's certificates and takes invites by hand.
        val testCa = providers.gradleProperty("kinfold.cacert").orNull?.let { Base64.getEncoder().encodeToString(File(it).readBytes()) } ?: ""
        buildConfigField("String", "TEST_CA", "\"$testCa\"")
    }

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        // What goes on the phones: not debuggable, so that battery and timing are the app's own,
        // and signed with the build machine's debug key, since nobody installs it from a store.
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

kotlin {
    compilerOptions {
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    // The shared core, from ../core (settings.gradle.kts): the client layer, OkHttp's transport
    // and Tink's cryptography
    implementation("ca.gureet.kinfold:core")
    // Coroutines for the app's own work, the version the core uses
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    // TLS 1.3 on Android 8 and 9, which have none of their own; used only below Android 10
    implementation("org.conscrypt:conscrypt-android:2.9.0")
    // kotlin.test on JUnit 4, the runner Android's host tests use
    testImplementation(kotlin("test-junit"))
}
