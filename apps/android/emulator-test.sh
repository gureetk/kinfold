#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
#
# The Android app on an emulator, against a real server and the spikes' harness as the other
# family member. KINFOLD_TEST_ROLE picks how the phone gets in:
#
#   joiner   (the default) the harness sets up from the setup code and invites the phone, which
#            joins with the invite;
#   creator  the phone sets up from the setup code, founds the circle and invites the harness,
#            which joins; the phone lets it in.
#
# Either way the phone names itself, agrees to a silence watch, and shares while the emulator walks
# north; it downloads the map region the server offers (KINFOLD_TEST_REGION, which test-with-server.sh
# hands the server) and draws the map from it; it answers the harness's live-view requests, awake and
# then in deep Doze. The harness's log must show all of it, and the phone's own log must hold no
# coordinate.
#
# Run it through core/test-with-server.sh, which builds and starts the server, from apps/android/:
#
#   adb reverse tcp:8443 tcp:8443
#   KINFOLD_TEST_DIR=. KINFOLD_TEST_CMD=./emulator-test.sh ../../core/test-with-server.sh
#
# Needs one booted emulator that adb sees (the walk goes through its console), and what the server
# script needs. Arguments go to Gradle, which builds a test build of the app: one that trusts the
# test server's certificate and takes its first steps from adb.
set -eu

role=${KINFOLD_TEST_ROLE:-joiner}
pkg=ca.gureet.kinfold
work=$(mktemp -d)
data="$work/harness"
harness_pid=
walker_pid=
cleanup() {
    if [ -n "$walker_pid" ]; then kill "$walker_pid" 2> /dev/null || true; fi
    if [ -n "$harness_pid" ]; then kill "$harness_pid" 2> /dev/null || true; fi
    adb shell dumpsys deviceidle unforce > /dev/null 2>&1 || true
    adb shell dumpsys battery reset > /dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

here=$(cd "$(dirname "$0")" && pwd)
gradle --console=plain -p "$here" assembleRelease -Pkinfold.cacert="$KINFOLD_CACERT" -Pkinfold.abis=x86_64 "$@"
gradle --console=plain -p "$here/../../spikes" :harness:installDist "$@"
harness="$here/../../spikes/harness/build/install/kinfold-harness/bin/kinfold-harness"
apk="$here/build/outputs/apk/release/kinfold-android-release.apk"

journal() { cat "$data"/logs/*.jsonl 2> /dev/null || true; }
applog() { adb logcat -d -s kinfold:I 2> /dev/null || true; }

fail() {
    echo "FAILED: $1" >&2
    echo "The harness's log:" >&2
    journal >&2
    if [ -f "$work/harness.out" ]; then
        echo "The harness's output:" >&2
        cat "$work/harness.out" >&2
    fi
    echo "The app's log:" >&2
    adb logcat -d -s kinfold:I kinfold-test:I AndroidRuntime:E >&2 || true
    echo "MapLibre's and the graphics' lines:" >&2
    adb logcat -d 2> /dev/null | grep -i -E 'mbgl|maplibre|egl|gles' | tail -n 60 >&2 || true
    echo "What the screen shows:" >&2
    adb shell dumpsys window 2> /dev/null | grep -E 'mCurrentFocus|mFocusedApp|mShowingLockscreen|mDreamingLockscreen|KeyguardShowing|isKeyguardShowing' >&2 || true
    adb shell dumpsys activity activities 2> /dev/null | grep -E 'ResumedActivity|mLastPausedActivity' >&2 || true
    exit 1
}

# Waits up to $3 seconds for $4 (default 1) lines matching $2 in the log $1 (journal or applog).
await() {
    waited=0
    until [ "$($1 | grep -c -E "$2")" -ge "${4:-1}" ]; do
        waited=$((waited + 2))
        [ "$waited" -gt "$3" ] && fail "nothing in $3 s matching $2"
        sleep 2
    done
    echo "Seen after $waited s: $2"
}

run_harness() {
    "$harness" run --data "$data" --cacert "$KINFOLD_CACERT" --locate-every 90s --alert-every 0 --ping 20s --quiet > "$work/harness.out" 2>&1 &
    harness_pid=$!
}

# The phone: the test build, its permissions as a person would grant them, and the battery exemption.
# Some emulators refuse to clear a log; the test reads only its own lines anyway.
adb logcat -c || true
adb install -r -g "$apk"
adb shell pm grant "$pkg" android.permission.ACCESS_BACKGROUND_LOCATION 2> /dev/null || true
adb shell dumpsys deviceidle whitelist +"$pkg"
# The map is drawn only where the app shows: the screen on and unlocked until the test turns it off.
adb shell settings put system screen_off_timeout 1800000
adb shell input keyevent KEYCODE_WAKEUP
adb shell wm dismiss-keyguard

case "$role" in
joiner)
    "$harness" setup "$KINFOLD_SETUP" --data "$data" --cacert "$KINFOLD_CACERT"
    code=$("$harness" invite --data "$data" --cacert "$KINFOLD_CACERT" | grep -o 'KFI0[A-Za-z0-9_-]*' | head -n 1)
    [ -n "$code" ] || fail "no invite code from the harness"
    run_harness
    adb shell am start -n "$pkg/.ui.MainActivity" --es invite "$code" --es name "Test-phone" --ez watch true --ez share true --ez region true
    await journal '"e":"joined"' 120
    ;;
creator)
    adb shell am start -n "$pkg/.ui.MainActivity" --es setup "$KINFOLD_SETUP" --es circle "Test-family" --es name "Test-phone" \
        --ez admit true --ez watch true --ez share true --ez region true
    waited=0
    code=
    until [ -n "$code" ]; do
        code=$(adb logcat -d -s kinfold-test:I 2> /dev/null | grep -o 'KFI0[A-Za-z0-9_-]*' | head -n 1 || true)
        waited=$((waited + 2))
        [ "$waited" -gt 120 ] && fail "the phone made no invite"
        sleep 2
    done
    echo "The phone's invite after $waited s"
    "$harness" join "$code" --data "$data" --cacert "$KINFOLD_CACERT" --timeout 5m
    await journal '"e":"joined"' 10
    run_harness
    ;;
*)
    fail "KINFOLD_TEST_ROLE is joiner or creator"
    ;;
esac

# A walk north at about 3 m/s, a fix every 3 seconds.
(
    i=0
    while true; do
        adb emu geo fix -123.1207 "$(awk "BEGIN { printf \"%.6f\", 49.2827 + $i * 0.00008 }")" > /dev/null 2>&1 || true
        i=$((i + 1))
        sleep 3
    done
) &
walker_pid=$!

# The region, downloaded whole and checked, then the map drawn from it and from the world map
# inside the app, with features from both.
await applog '"e":"region".*"state":"done"' 180
await applog '"e":"map".*"state":"(rendered|idle)".*"region":true.*"world_features":[1-9][0-9]*.*"region_features":[1-9]' 120
await journal '"e":"profile"' 120
await journal '"e":"watch"' 120
await journal '"e":"loc".*"moved_m"' 180
await journal '"e":"loc".*"answer_ms"' 240

# Deep Doze: unplugged, screen off, forced idle. The next live-view request must still reach the
# phone on its stream.
asks=$(applog | grep -c '"e":"live_req".*"state":"received"' || true)
adb shell dumpsys battery unplug
adb shell input keyevent KEYCODE_SLEEP
adb shell dumpsys deviceidle force-idle
await applog '"e":"live_req".*"state":"received"' 200 $((asks + 1))
echo "In Doze: $(adb shell dumpsys deviceidle get deep | tr -d '\r')"

# The phone's log holds times, distances and states: never a coordinate. The walk would show as
# 49.2… and -123.1… in degrees, or as the payloads' whole numbers, 49… and -123… in 10^-7 degree.
# Only the lines themselves are checked, not logcat's prefix, whose clock (07:55:49.041) would match.
if applog | sed -n 's/^.* kinfold *: //p' | grep -E '"(lat|lon|latitude|longitude)"|49\.[0-9]{3}|-123\.[0-9]{3}|[:,[]49[0-9]{7}[],}]|[:,[]-123[0-9]{7}[],}]' > "$work/leak" 2>&1; then
    cat "$work/leak" >&2
    fail "the phone's log holds a coordinate"
fi

if adb logcat -d -b crash | grep -q "$pkg"; then
    adb logcat -d -b crash >&2
    fail "the app crashed"
fi
echo "The app's log:"
applog | tail -n 60
echo "The Android app passed on the emulator as the $role."
