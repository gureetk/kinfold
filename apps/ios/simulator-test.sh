#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
#
# The iOS app in the simulator, against a real server and the spikes' harness as the other family
# member, as apps/android/emulator-test.sh runs the Android app. KINFOLD_TEST_ROLE picks how the
# phone gets in:
#
#   joiner   (the default) the harness sets up from the setup code and invites the phone, which
#            joins with the invite;
#   creator  the phone sets up from the setup code, founds the circle and invites the harness,
#            which joins; the phone lets it in.
#
# Either way the phone names itself, agrees to a silence watch, and shares while the simulator walks
# north; it downloads the map region the server offers (KINFOLD_TEST_REGION, which test-with-server.sh
# hands the server) and draws the map from it; it answers the harness's live-view requests, in front
# and then in the background. The harness's log must show all of it, and the phone's own log must
# hold no coordinate.
#
# Run it through core/test-with-server.sh, which builds and starts the server, from apps/ios/:
#
#   SIMULATOR=<udid> KINFOLD_TEST_APP=<path to the simulator's Kinfold.app> \
#     KINFOLD_TEST_DIR=. KINFOLD_TEST_CMD=./simulator-test.sh ../../core/test-with-server.sh
#
# The simulator trusts the test server's certificate through its own keychain (simctl keychain), so
# the app is the one the family runs, built for the simulator in Debug, which reads its first steps
# from launch arguments (Kinfold/TestDriver.swift). Arguments go to Gradle, which builds the harness.
set -eu

role=${KINFOLD_TEST_ROLE:-joiner}
sim=${SIMULATOR:?SIMULATOR is the UDID of the simulator to run in}
app=${KINFOLD_TEST_APP:?KINFOLD_TEST_APP is the Kinfold.app built for the simulator}
bundle=ca.gureet.kinfold
work=$(mktemp -d)
data="$work/harness"
harness_pid=
walker_pid=
cleanup() {
    if [ -n "$walker_pid" ]; then kill "$walker_pid" 2> /dev/null || true; fi
    if [ -n "$harness_pid" ]; then kill "$harness_pid" 2> /dev/null || true; fi
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

here=$(cd "$(dirname "$0")" && pwd)
gradle --console=plain -p "$here/../../spikes" :harness:installDist "$@"
harness="$here/../../spikes/harness/build/install/kinfold-harness/bin/kinfold-harness"

xcrun simctl boot "$sim" 2> /dev/null || true
xcrun simctl bootstatus "$sim" -b > /dev/null
xcrun simctl keychain "$sim" add-root-cert "$KINFOLD_CACERT"
xcrun simctl uninstall "$sim" "$bundle" 2> /dev/null || true
xcrun simctl install "$sim" "$app"
# As a person would grant it: the location, always.
xcrun simctl privacy "$sim" grant location-always "$bundle"
xcrun simctl location "$sim" set 49.2827,-123.1207
container=$(xcrun simctl get_app_container "$sim" "$bundle" data)

journal() { cat "$data"/logs/*.jsonl 2> /dev/null || true; }
applog() { cat "$container/Library/Application Support/logs/"*.jsonl 2> /dev/null || true; }

fail() {
    echo "FAILED: $1" >&2
    echo "The harness's log:" >&2
    journal >&2
    if [ -f "$work/harness.out" ]; then
        echo "The harness's output:" >&2
        cat "$work/harness.out" >&2
    fi
    echo "The app's log:" >&2
    applog >&2
    echo "The simulator's lines from the app:" >&2
    xcrun simctl spawn "$sim" log show --last 10m --style compact --predicate 'process == "Kinfold"' 2> /dev/null | tail -n 80 >&2 || true
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

launch() {
    xcrun simctl launch "$sim" "$bundle" -KinfoldTestName Test-iPhone -KinfoldTestWatch YES -KinfoldTestShare YES -KinfoldTestRegion YES "$@"
}

case "$role" in
joiner)
    "$harness" setup "$KINFOLD_SETUP" --data "$data" --cacert "$KINFOLD_CACERT"
    code=$("$harness" invite --data "$data" --cacert "$KINFOLD_CACERT" | grep -o 'KFI0[A-Za-z0-9_-]*' | head -n 1)
    [ -n "$code" ] || fail "no invite code from the harness"
    run_harness
    launch -KinfoldTestInvite "$code"
    await journal '"e":"joined"' 120
    ;;
creator)
    launch -KinfoldTestSetup "$KINFOLD_SETUP" -KinfoldTestCircle Test-family -KinfoldTestAdmit YES
    waited=0
    until [ -s "$container/Documents/test-invite.txt" ]; do
        waited=$((waited + 2))
        [ "$waited" -gt 120 ] && fail "the phone made no invite"
        sleep 2
    done
    code=$(grep -o 'KFI0[A-Za-z0-9_-]*' "$container/Documents/test-invite.txt" | head -n 1)
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
        xcrun simctl location "$sim" set "$(awk "BEGIN { printf \"%.6f\", 49.2827 + $i * 0.00008 }"),-123.1207" > /dev/null 2>&1 || true
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

# In the background: another app in front. Sharing keeps Kinfold running there, so the next
# live-view request must still reach the phone on its stream, and be answered.
asks=$(applog | grep -c '"e":"live_req".*"state":"received"' || true)
answers=$(journal | grep -c '"e":"loc".*"answer_ms"' || true)
xcrun simctl launch "$sim" com.apple.Preferences > /dev/null
await applog '"e":"live_req".*"state":"received"' 200 $((asks + 1))
await journal '"e":"loc".*"answer_ms"' 120 $((answers + 1))

# The engine sends no faster than the server takes: no upload was refused for its rate.
if applog | grep -q '"e":"upload".*rate_limited'; then
    fail "uploads went faster than the server allows"
fi

# The phone's log holds times, distances and states: never a coordinate. The walk would show as
# 49.2… and -123.1… in degrees, or as the payloads' whole numbers, 49… and -123… in 10^-7 degree.
if applog | grep -E '"(lat|lon|latitude|longitude)"|49\.[0-9]{3}|-123\.[0-9]{3}|[:,[]49[0-9]{7}[],}]|[:,[]-123[0-9]{7}[],}]' > "$work/leak" 2>&1; then
    cat "$work/leak" >&2
    fail "the phone's log holds a coordinate"
fi

if ls "$HOME"/Library/Logs/DiagnosticReports/Kinfold* > /dev/null 2>&1; then
    cat "$HOME"/Library/Logs/DiagnosticReports/Kinfold* >&2
    fail "the app crashed"
fi
echo "The app's log:"
applog | tail -n 60
echo "The iOS app passed in the simulator as the $role."
