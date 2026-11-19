#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
#
# Builds what the Xcode project takes from the core, on a Mac with Apple silicon, Xcode 26, JDK 21
# and Gradle 9.9.1: KinfoldCore.xcframework, which the Kinfold app links, and the core's test
# binaries for the iPhone and the simulator, which the CoreTests app runs. It checks Kotlin/Native's
# own downloads first. Run it before building in Xcode, and again after the core changes.
#
# Usage: spikes/ios/build-core.sh [more Gradle arguments]
set -eu

here=$(cd "$(dirname "$0")" && pwd)
"$here/../../core/kotlin-native-deps.sh"
cd "$here/../../core"
gradle --console=plain assembleKinfoldCoreReleaseXCFramework linkDebugTestIosArm64 linkDebugTestIosSimulatorArm64 "$@"
