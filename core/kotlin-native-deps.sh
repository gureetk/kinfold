#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
#
# Kotlin/Native downloads its own LLVM and libffi from JetBrains the first time it builds for iOS,
# outside Gradle, and checks no hash; JetBrains publishes none. This script downloads them first,
# checks each against the SHA-256 below, which two of GitHub's macOS runners agreed on, and leaves
# them where Kotlin/Native looks before downloading anything. CI runs it before every iOS build.
#
# On a Mac with Apple silicon, run it once before building the core for iOS, and again whenever
# Kotlin's version changes. A copy that Kotlin/Native unpacked from a download nothing checked is
# removed, so that it unpacks the checked one instead.
set -eu

if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
    echo "The core's iOS build needs a Mac with Apple silicon." >&2
    exit 1
fi

deps="${KONAN_DATA_DIR:-$HOME/.konan}/dependencies"
mkdir -p "$deps/cache"

# fetch SHA256 PATH: the archive at https://download.jetbrains.com/kotlin/native/PATH
fetch() {
    name=$(basename "$2" .tar.gz)
    file="$deps/cache/$name.tar.gz"
    if [ -f "$file" ] && echo "$1  $file" | shasum -a 256 -c - > /dev/null 2>&1; then
        echo "$name: checked"
        return
    fi
    # Whatever is there didn't come from the checked archive.
    rm -rf "$file" "${deps:?}/$name"
    curl -fsSL -o "$file.part" "https://download.jetbrains.com/kotlin/native/$2"
    if ! echo "$1  $file.part" | shasum -a 256 -c - > /dev/null 2>&1; then
        rm -f "$file.part"
        echo "$name: the download doesn't match its pinned SHA-256; nothing was kept." >&2
        exit 1
    fi
    mv "$file.part" "$file"
    echo "$name: downloaded and checked"
}

# Kotlin 2.4.21's dependencies for the iOS targets, on a Mac with Apple silicon
fetch 62fd78f090353aa7b2c6601ad6f95bd7a0b0558b18f86978043cc878321b408a resources/llvm/21-aarch64-macos/llvm-21-aarch64-macos-essentials-97.tar.gz
fetch 8ca0102ad5b626e8b1699f311ab098354a90154ea3e44951f28ebdd256862ba9 libffi-3.3-1-macos-arm64.tar.gz
