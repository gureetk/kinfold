#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
#
# Spike 2's app on an emulator, against a real server and the harness. The app joins the harness's
# circle with an invite, names itself, grants the harness a watch and shares while the emulator
# walks north; it answers a live-view request, and shows an alert and acknowledges it, awake and
# then in deep Doze. The harness's log must show all of it.
#
# Run it through core/test-with-server.sh, which builds and starts the server, from spikes/:
#
#   adb reverse tcp:8443 tcp:8443
#   KINFOLD_TEST_DIR=. KINFOLD_TEST_CMD=android/emulator-test.sh ../core/test-with-server.sh
#
# Needs one booted emulator that adb sees (the walk goes through its console), and what the
# server script needs. Arguments go to Gradle, which builds a test build of the app: one that
# trusts the test server's certificate and takes the invite from adb.
set -eu

pkg=ca.gureet.kinfold.spike
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

gradle --console=plain :android:assembleRelease :harness:installDist -Pkinfold.cacert="$KINFOLD_CACERT" "$@"
harness=harness/build/install/kinfold-harness/bin/kinfold-harness

journal() { cat "$data"/logs/*.jsonl 2> /dev/null || true; }

# Waits up to $2 seconds for $3 (default 1) lines of the harness's log that match $1.
await() {
    waited=0
    until [ "$(journal | grep -c -E "$1")" -ge "${3:-1}" ]; do
        waited=$((waited + 2))
        if [ "$waited" -gt "$2" ]; then
            echo "FAILED: nothing in $2 s matching $1" >&2
            echo "The harness's log:" >&2
            journal >&2
            echo "The harness's output:" >&2
            cat "$work/harness.out" >&2
            echo "The app's log:" >&2
            adb logcat -d -s kinfold:I AndroidRuntime:E >&2 || true
            exit 1
        fi
        sleep 2
    done
    echo "Seen after $waited s: $1"
}

# The harness sets up, makes the invite, then runs: asking for a location every 90 seconds and
# sending an alert every 2 minutes.
"$harness" setup "$KINFOLD_SETUP" --data "$data" --cacert "$KINFOLD_CACERT"
code=$("$harness" invite --data "$data" --cacert "$KINFOLD_CACERT" | grep -o 'KFI0[A-Za-z0-9_-]*' | head -n 1)
[ -n "$code" ] || { echo "FAILED: no invite code" >&2; exit 1; }
"$harness" run --data "$data" --cacert "$KINFOLD_CACERT" --locate-every 90s --alert-every 2m --ping 20s --quiet > "$work/harness.out" 2>&1 &
harness_pid=$!

# The phone: the test build, its permissions as a person would grant them, and the battery exemption.
# Some emulators refuse to clear a log; the test reads only its own lines anyway.
adb logcat -c || true
adb install -r -g android/build/outputs/apk/release/android-release.apk
adb shell pm grant "$pkg" android.permission.ACCESS_BACKGROUND_LOCATION 2> /dev/null || true
adb shell dumpsys deviceidle whitelist +"$pkg"
adb shell am start -n "$pkg/.MainActivity" --es invite "$code" --ez share true

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

await '"e":"joined"' 120
await '"e":"profile"' 60
await '"e":"watch"' 60
await '"e":"loc".*"moved_m"' 180
await '"e":"loc".*"answer_ms"' 240
await '"e":"ack"' 240

# Deep Doze: unplugged, screen off, forced idle. The next alert must still get through.
acks=$(journal | grep -c '"e":"ack"')
adb shell dumpsys battery unplug
adb shell input keyevent KEYCODE_SLEEP
adb shell dumpsys deviceidle force-idle
await '"e":"ack"' 200 $((acks + 1))
echo "In Doze: $(adb shell dumpsys deviceidle get deep | tr -d '\r')"

if adb logcat -d -b crash | grep -q "$pkg"; then
    echo "FAILED: the app crashed" >&2
    adb logcat -d -b crash >&2
    exit 1
fi
echo "The app's log:"
adb logcat -d -s kinfold:I | tail -n 60
echo "Spike 2's app passed on the emulator."
