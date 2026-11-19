// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFramework
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFrameworkConfig
import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest
import java.util.Base64

plugins {
    kotlin("multiplatform") version "2.4.21"
    id("com.android.kotlin.multiplatform.library") version "9.5.1"
}

val vectorsFile: String = layout.projectDirectory.file("../spec/vectors/kinfold-v0.json").asFile.canonicalPath
val protocolFile: String = layout.projectDirectory.file("../spec/PROTOCOL.md").asFile.canonicalPath

// The device tests read the vectors and the spec as Java resources of the test APK.
val copyVectors = tasks.register<Copy>("copyVectors") {
    from(vectorsFile, protocolFile)
    into(layout.buildDirectory.dir("vectors"))
}

// The iOS targets build only on a Mac: Xcode compiles the CryptoKit layer, and the Apple SDKs
// live there. Elsewhere they are left out, and the build is the JVM and Android one.
val onMac = System.getProperty("os.name").startsWith("Mac")

// Each library is pinned, and gradle/verification-metadata.xml holds the SHA-256 of every
// artifact the build uses. Gradle refuses any artifact whose hash doesn't match.
kotlin {
    jvm()

    android {
        namespace = "ca.gureet.kinfold.core"
        // Android 17's API, which OkHttp asks to be compiled against
        compileSdk = 37
        // Android 10, the first with TLS 1.3 of its own
        minSdk = 29
        withHostTest {}
        // The device tests run commonTest on a phone or an emulator, against the platform's own libraries.
        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
            // The server for the client layer's test on a device (test-with-server.sh, with `adb reverse`
            // so that the device's 127.0.0.1 is the computer's): its URL, a setup code, and its
            // certificate's PEM in base64url, since the device can't read the file.
            for (name in listOf("kinfold.server", "kinfold.setup")) {
                providers.gradleProperty(name).orNull?.let { instrumentationRunnerArguments[name] = it }
            }
            providers.gradleProperty("kinfold.cacert").orNull?.let {
                instrumentationRunnerArguments["kinfold.cacert"] = Base64.getUrlEncoder().withoutPadding().encodeToString(File(it).readBytes())
            }
        }
    }

    // iPhones, and the simulator on Apple silicon. iOS 17 is the oldest with CryptoKit's HPKE.
    // Xcode links the core as KinfoldCore.xcframework: assembleKinfoldCoreReleaseXCFramework.
    if (onMac) {
        val xcf = XCFramework("KinfoldCore")
        iosArm64 {
            cryptoKit(sdk = "iphoneos", target = "arm64-apple-ios17.0")
            coreFramework(xcf)
        }
        iosSimulatorArm64 {
            cryptoKit(sdk = "iphonesimulator", target = "arm64-apple-ios17.0-simulator")
            coreFramework(xcf)
        }
    }

    compilerOptions {
        allWarningsAsErrors.set(true)
    }

    sourceSets {
        commonMain.dependencies {
            // What a client on a network needs beyond the standard library's bare coroutines:
            // cancellation, timeouts, delays and locks (the client layer, src/commonMain/.../client)
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
        }
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
                // HTTPS and the WebSocket for the client layer: Android has no public WebSocket client
                implementation("com.squareup.okhttp3:okhttp:5.5.1")
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
        if (onMac) {
            iosTest {
                // Where the simulator's test process finds the vectors and the spec
                kotlin.srcDir(specFiles())
            }
        }
        // Calling Objective-C means pinning Kotlin arrays and passing pointers.
        matching { it.name.startsWith("ios") }.configureEach {
            languageSettings.optIn("kotlinx.cinterop.ExperimentalForeignApi")
            languageSettings.optIn("kotlinx.cinterop.BetaInteropApi")
        }
    }
}

tasks.withType<Test>().configureEach {
    systemProperty("kinfold.vectors", vectorsFile)
    // A running server for the client layer's tests on the JVM (test-with-server.sh starts one): its URL,
    // a setup code, and the certificate it serves. Without them those tests are skipped.
    for (name in listOf("kinfold.server", "kinfold.setup", "kinfold.cacert")) {
        providers.gradleProperty(name).orNull?.let { systemProperty(name, it) }
    }
}

// The simulator to test on, by name or UDID, as -Pkinfold.simulator=...; Kotlin's default otherwise.
// The server for the client layer's test (test-with-server.sh) goes to the test process as
// KINFOLD_SERVER, KINFOLD_SETUP and KINFOLD_CACERT: simctl hands it the variables that start with
// SIMCTL_CHILD_, without the prefix.
tasks.withType<KotlinNativeSimulatorTest>().configureEach {
    providers.gradleProperty("kinfold.simulator").orNull?.let { device.set(it) }
    // Kotlin runs the tests outside the simulator's own services by default, and then the system
    // can't check a server's certificate. The client's test runs in a simulator booted beforehand,
    // as part of it: -Pkinfold.simulator.booted=true.
    if (providers.gradleProperty("kinfold.simulator.booted").orNull == "true") standalone.set(false)
    for (name in listOf("kinfold.server", "kinfold.setup", "kinfold.cacert")) {
        providers.gradleProperty(name).orNull?.let { environment("SIMCTL_CHILD_" + name.uppercase().replace('.', '_'), it) }
    }
}

/**
 * Compiles the CryptoKit layer (src/iosMain/swift) for one iOS target, and imports it into
 * Kotlin through the Objective-C header that Swift writes for it.
 */
fun KotlinNativeTarget.cryptoKit(sdk: String, target: String) {
    val dir = layout.buildDirectory.dir("cryptokit/$name")
    val source = layout.projectDirectory.file("src/iosMain/swift/KinfoldCryptoKit.swift")
    val swift = tasks.register<Exec>("cryptoKit" + name.replaceFirstChar { it.uppercase() }) {
        description = "Compiles the CryptoKit layer for $target."
        inputs.file(source)
        outputs.dir(dir)
        val out = dir.get().asFile
        doFirst { out.mkdirs() }
        commandLine(
            "xcrun", "--sdk", sdk, "swiftc", "-parse-as-library", "-emit-library", "-static", "-O",
            "-module-name", "KinfoldCryptoKit", "-target", target,
            "-emit-objc-header", "-emit-objc-header-path", out.resolve("KinfoldCryptoKit-Swift.h").path,
            "-o", out.resolve("libKinfoldCryptoKit.a").path,
            source.asFile.path,
        )
    }
    val interop = compilations.getByName("main").cinterops.create("cryptokit") {
        definitionFile.set(layout.projectDirectory.file("src/iosMain/cinterop/cryptokit.def"))
        includeDirs(dir)
        extraOpts("-libraryPath", dir.get().asFile.path)
    }
    tasks.named(interop.interopProcessingTaskName) { dependsOn(swift) }
    binaries.all {
        // Kotlin/Native links for iOS 15 unless told otherwise; the Swift is built for 17.
        freeCompilerArgs += "-Xoverride-konan-properties=osVersionMin.${konanTarget.name}=17.0"
        // The toolchain's Swift libraries, besides the SDK's, for anything the Swift object asks for.
        linkerOpts("-L${xcodeToolchain()}/usr/lib/swift/$sdk")
    }
}

/**
 * The core as a framework for Xcode, one slice of the XCFramework [xcf]. It carries the CryptoKit
 * layer, and Swift sees the core's public API through its Objective-C header.
 */
fun KotlinNativeTarget.coreFramework(xcf: XCFrameworkConfig) = binaries.framework {
    baseName = "KinfoldCore"
    // Kotlin can't tell the framework's bundle ID from the core's packages.
    binaryOption("bundleId", "ca.gureet.kinfold.core")
    xcf.add(this)
}

/** Xcode's default toolchain, from the Xcode that xcode-select names. */
fun xcodeToolchain(): String =
    providers.exec { commandLine("xcode-select", "-p") }.standardOutput.asText.get().trim() +
        "/Toolchains/XcodeDefault.xctoolchain"

/** Writes SpecFiles.kt, which holds the paths of the vectors and the spec for the iOS tests. */
fun specFiles(): TaskProvider<Task> = tasks.register("specFiles") {
    val out = layout.buildDirectory.dir("generated/specFiles")
    val paths = listOf(vectorsFile, protocolFile)
    inputs.property("paths", paths)
    outputs.dir(out)
    doLast {
        fun literal(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$") + "\""
        val file = out.get().file("ca/gureet/kinfold/core/SpecFiles.kt").asFile
        file.parentFile.mkdirs()
        file.writeText(
            """
            |// Generated by build.gradle.kts: where the iOS tests find the spec's files.
            |package ca.gureet.kinfold.core
            |
            |internal object SpecFiles {
            |    const val VECTORS = ${literal(paths[0])}
            |    const val PROTOCOL = ${literal(paths[1])}
            |}
            |""".trimMargin(),
        )
    }
}
