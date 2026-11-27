#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
#
# Builds KinfoldCore.xcframework, which the app links, on a Mac with Apple silicon, Xcode 26, JDK 21
# and Gradle 9.9.1. It checks Kotlin/Native's own downloads first. Run it before building in Xcode,
# and again after the core changes.
#
# Usage: apps/ios/build-core.sh [more Gradle arguments]
set -eu

here=$(cd "$(dirname "$0")" && pwd)
"$here/../../core/kotlin-native-deps.sh"
cd "$here/../../core"
gradle --console=plain assembleKinfoldCoreReleaseXCFramework "$@"
