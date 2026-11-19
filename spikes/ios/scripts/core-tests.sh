#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
#
# A build phase of the CoreTests target: puts the core's test binary in the app as its program,
# with the vectors and the spec beside it, where the tests look for them on an iPhone. Xcode signs
# the app afterwards. build-core.sh makes the binaries.
set -eu

repo="$SRCROOT/../.."
case "$PLATFORM_NAME" in
    iphoneos) target=iosArm64 ;;
    iphonesimulator) target=iosSimulatorArm64 ;;
    *) echo "error: no core tests for $PLATFORM_NAME"; exit 1 ;;
esac
bin="$repo/core/build/bin/$target/debugTest/test.kexe"
if [ ! -f "$bin" ]; then
    echo "error: the core's test binary isn't built: run spikes/ios/build-core.sh"
    exit 1
fi
cp "$bin" "$TARGET_BUILD_DIR/$EXECUTABLE_PATH"
cp "$repo/spec/vectors/kinfold-v0.json" "$repo/spec/PROTOCOL.md" "$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH/"
