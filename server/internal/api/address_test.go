// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/gureetk/kinfold/server/internal/api"
)

// The per-address limits of API.md §3 behind a proxy, on login challenges: the client's
// address comes from X-Forwarded-For only on connections from the proxy the operator named,
// read from the right, and an IPv6 client counts by its /64.
func TestLimitsPerAddress(t *testing.T) {
	e := newEnv(t, api.Limits{ChallengesPerDevice: 1 << 20, ChallengesPerAddress: 2}, func(c *api.Config) {
		c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	})
	n := 0
	challenge := func(remote, forwardedFor string) *httptest.ResponseRecorder {
		n++
		body, _ := json.Marshal(map[string]string{"device_id": b64(bytes.Repeat([]byte{byte(n)}, 16))})
		return e.do(call{method: "POST", path: "/v1/auth/challenge", body: body, ctype: "application/json",
			remote: remote, header: map[string]string{"X-Forwarded-For": forwardedFor}})
	}
	ok := func(remote, forwardedFor string) {
		t.Helper()
		expect(t, challenge(remote, forwardedFor), http.StatusOK, "")
	}
	refused := func(remote, forwardedFor string) {
		t.Helper()
		expect(t, challenge(remote, forwardedFor), http.StatusTooManyRequests, "rate_limited")
	}

	// Straight to the server, the header changes nothing.
	ok("192.0.2.1:1000", "198.51.100.1")
	ok("192.0.2.1:1001", "198.51.100.2")
	refused("192.0.2.1:1002", "198.51.100.3")

	// Through the proxy each client counts on its own, whatever it wrote in the header itself.
	ok("127.0.0.1:2000", "198.51.100.7")
	ok("127.0.0.1:2001", "203.0.113.1, 198.51.100.7")
	refused("127.0.0.1:2002", "203.0.113.2, 198.51.100.7")
	ok("127.0.0.1:2003", "198.51.100.8")

	// A request the proxy names nobody for counts as the proxy's.
	ok("127.0.0.1:2004", "")
	ok("127.0.0.1:2005", "")
	refused("127.0.0.1:2006", "")

	// An IPv6 /64 is one client, through the proxy or not.
	ok("127.0.0.1:2007", "2001:db8::1")
	ok("127.0.0.1:2008", "2001:db8::2")
	refused("[2001:db8::3]:3000", "")
	ok("127.0.0.1:2009", "2001:db8:0:1::1")
}
