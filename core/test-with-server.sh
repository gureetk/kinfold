#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
#
# Runs the core's tests on the JVM against a real server: builds the server from ../server, starts
# it on 127.0.0.1 with TLS on a throwaway certificate and member tokens on, prints a setup code,
# and passes the server's URL, the code and the throwaway authority that signed the certificate to
# Gradle, which hands them to the client layer's tests. Needs Go, OpenSSL, curl, JDK 21, Gradle 9.9.1 and an Android SDK. On a Mac,
# KINFOLD_TEST_TASKS=iosSimulatorArm64Test runs them in the iOS simulator; OpenSSL there means
# Homebrew's, since the system's LibreSSL makes keys differently.
#
# Usage: ./test-with-server.sh [more Gradle arguments]
#
# KINFOLD_TEST_DIR and KINFOLD_TEST_TASKS run other tests against the same kind of server: the
# spikes' harness, for one, with KINFOLD_TEST_DIR=../spikes KINFOLD_TEST_TASKS=:harness:test.
# KINFOLD_TEST_CMD runs a command instead of Gradle, in KINFOLD_TEST_DIR, with the server's URL,
# the setup code and the authority's certificate file in KINFOLD_SERVER, KINFOLD_SETUP and KINFOLD_CACERT.
# KINFOLD_TEST_REGION, a PMTiles file, makes the server offer it as the map region "test" (API.md §13).
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

# A certificate authority that lives a day, and a certificate for 127.0.0.1 that it signs. The tests
# trust the authority and nothing else. The server's certificate is laid out as Apple's systems
# require of a TLS server's: not an authority's, for serverAuth, with the address in subjectAltName.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj "/CN=Kinfold test CA" \
    -keyout "$work/ca-key.pem" -out "$work/ca.pem" 2> /dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=127.0.0.1 \
    -keyout "$work/key.pem" -out "$work/request.pem" 2> /dev/null
printf '%s\n' basicConstraints=critical,CA:FALSE keyUsage=critical,digitalSignature extendedKeyUsage=serverAuth \
    subjectAltName=IP:127.0.0.1 > "$work/server.ext"
openssl x509 -req -in "$work/request.pem" -CA "$work/ca.pem" -CAkey "$work/ca-key.pem" -CAcreateserial -days 1 -sha256 \
    -extfile "$work/server.ext" -out "$work/cert.pem" 2> /dev/null

"$work/kinfold" serve --url "$url" --listen "127.0.0.1:$port" --data "$work/data" \
    --tls-cert "$work/cert.pem" --tls-key "$work/key.pem" --no-clock-check > "$work/server.log" 2>&1 &
pid=$!

tries=0
until curl -fsS --cacert "$work/ca.pem" "$url/healthz" > /dev/null 2>&1; do
    tries=$((tries + 1))
    if [ "$tries" -gt 100 ]; then
        echo "The server didn't start:" >&2
        cat "$work/server.log" >&2
        exit 1
    fi
    sleep 0.2
done

"$work/kinfold" settings --member-tokens on --data "$work/data" > /dev/null
if [ -n "${KINFOLD_TEST_REGION:-}" ]; then
    "$work/kinfold" region add test "$KINFOLD_TEST_REGION" --name "Test region" --data "$work/data" > /dev/null
fi
code=$("$work/kinfold" setup --data "$work/data" | grep -o 'KFS0[A-Za-z0-9_-]*' | head -n 1)
[ -n "$code" ] || { echo "No setup code" >&2; exit 1; }

cd "$dir"
status=0
if [ -n "${KINFOLD_TEST_CMD:-}" ]; then
    KINFOLD_SERVER="$url" KINFOLD_SETUP="$code" KINFOLD_CACERT="$work/ca.pem" "$KINFOLD_TEST_CMD" "$@" || status=$?
else
    # shellcheck disable=SC2086 # the tasks are words
    gradle --console=plain $tasks -Pkinfold.server="$url" -Pkinfold.setup="$code" -Pkinfold.cacert="$work/ca.pem" "$@" || status=$?
fi
if [ "$status" -ne 0 ]; then
    echo "The server's log:" >&2
    cat "$work/server.log" >&2
fi
exit "$status"
