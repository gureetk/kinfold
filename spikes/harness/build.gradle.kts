// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
plugins {
    kotlin("jvm") version "2.4.21"
    application
}

kotlin {
    compilerOptions {
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    // The shared core, from ../core (settings.gradle.kts): the client layer and Tink's cryptography
    implementation("ca.gureet.kinfold:core")
    // Coroutines for the harness's own loops, the version the core uses
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    testImplementation(kotlin("test"))
}

application {
    mainClass.set("ca.gureet.kinfold.spike.harness.MainKt")
    applicationName = "kinfold-harness"
}

tasks.test {
    // A running server for the harness's own test (../../core/test-with-server.sh starts one).
    for (name in listOf("kinfold.server", "kinfold.setup", "kinfold.cacert")) {
        providers.gradleProperty(name).orNull?.let { systemProperty(name, it) }
    }
}
