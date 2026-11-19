#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
#
# Runs the core's tests on the JVM against a real server: builds the server from ../server, starts
# it on 127.0.0.1 with TLS on a throwaway certificate and member tokens on, prints a setup code,
# and passes the server's URL, the code and the certificate to Gradle, which hands them to the
# client layer's tests. Needs Go, OpenSSL, curl, JDK 21, Gradle 9.9.1 and an Android SDK.
#
# Usage: ./test-with-server.sh [more Gradle arguments]
#
# KINFOLD_TEST_DIR and KINFOLD_TEST_TASKS run other tests against the same kind of server: the
# spikes' harness, for one, with KINFOLD_TEST_DIR=../spikes KINFOLD_TEST_TASKS=:harness:test.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
dir=$(cd "${KINFOLD_TEST_DIR:-$here}" && pwd)
tasks=${KINFOLD_TEST_TASKS:-jvmTest}
port=${KINFOLD_TEST_PORT:-8443}
url="https://127.0.0.1:$port"
work=$(mktemp -d)
pid=
cleanup() {
    if [ -n "$pid" ]; then
        kill "$pid" 2> /dev/null || true
        wait "$pid" 2> /dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

(cd "$here/../server" && CGO_ENABLED=0 go build -trimpath -o "$work/kinfold" ./cmd/kinfold)

# A certificate for 127.0.0.1 that lives a day; the tests trust it and nothing else.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=127.0.0.1 \
    -addext subjectAltName=IP:127.0.0.1 -keyout "$work/key.pem" -out "$work/cert.pem" 2> /dev/null

"$work/kinfold" serve --url "$url" --listen "127.0.0.1:$port" --data "$work/data" \
    --tls-cert "$work/cert.pem" --tls-key "$work/key.pem" --no-clock-check > "$work/server.log" 2>&1 &
pid=$!

tries=0
until curl -fsS --cacert "$work/cert.pem" "$url/healthz" > /dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -gt 100 ]; then
        echo "The server didn't start:" >&2
        cat "$work/server.log" >&2
        exit 1
    fi
    sleep 0.2
done

"$work/kinfold" settings --member-tokens on --data "$work/data" > /dev/null
code=$("$work/kinfold" setup --data "$work/data" | grep -o 'KFS0[A-Za-z0-9_-]*' | head -n 1)
[ -n "$code" ] || { echo "No setup code" >&2; exit 1; }

cd "$dir"
status=0
# shellcheck disable=SC2086 # the tasks are words
gradle --console=plain $tasks -Pkinfold.server="$url" -Pkinfold.setup="$code" -Pkinfold.cacert="$work/cert.pem" "$@" || status=$?
if [ "$status" -ne 0 ]; then
    echo "The server's log:" >&2
    cat "$work/server.log" >&2
fi
exit "$status"
