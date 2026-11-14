// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

var proxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8")}

func TestForwardedClient(t *testing.T) {
	for _, c := range []struct {
		name, peer string
		xff        []string
		trusted    []netip.Prefix
		want       string
	}{
		{"no proxies named", "127.0.0.1", []string{"198.51.100.7"}, nil, "127.0.0.1"},
		{"a peer that isn't a proxy", "192.0.2.1", []string{"198.51.100.7"}, proxies, "192.0.2.1"},
		{"a proxy that says nothing", "127.0.0.1", nil, proxies, "127.0.0.1"},
		{"a proxy", "127.0.0.1", []string{"198.51.100.7"}, proxies, "198.51.100.7"},
		{"a proxy on IPv6", "::1", []string{"198.51.100.7"}, proxies, "198.51.100.7"},
		{"a proxy on an IPv4-mapped address", "::ffff:127.0.0.1", []string{"198.51.100.7"}, proxies, "198.51.100.7"},
		{"what the client wrote itself", "127.0.0.1", []string{"203.0.113.1, 198.51.100.7"}, proxies, "198.51.100.7"},
		{"two proxies, two header lines", "127.0.0.1", []string{"203.0.113.1", "198.51.100.7, 10.1.2.3"}, proxies, "198.51.100.7"},
		{"only proxies", "127.0.0.1", []string{"10.0.0.5, 10.0.0.6"}, proxies, "10.0.0.5"},
		{"a port", "127.0.0.1", []string{"198.51.100.7:4711"}, proxies, "198.51.100.7"},
		{"an IPv6 address and a port", "127.0.0.1", []string{"[2001:db8::7]:4711"}, proxies, "2001:db8::7"},
		{"an IPv4-mapped client", "127.0.0.1", []string{" ::ffff:198.51.100.7 "}, proxies, "198.51.100.7"},
		{"an empty header", "127.0.0.1", []string{""}, proxies, "127.0.0.1"},
		{"nonsense", "127.0.0.1", []string{"unknown"}, proxies, "127.0.0.1"},
		{"nonsense from a proxy", "127.0.0.1", []string{"198.51.100.7, unknown"}, proxies, "127.0.0.1"},
		{"nonsense after a proxy", "127.0.0.1", []string{"unknown, 10.1.2.3"}, proxies, "10.1.2.3"},
		{"nonsense from the client", "127.0.0.1", []string{"unknown, 198.51.100.7"}, proxies, "198.51.100.7"},
	} {
		got := forwardedClient(netip.MustParseAddr(c.peer), c.xff, c.trusted)
		if got != netip.MustParseAddr(c.want) {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestAddressKey(t *testing.T) {
	for addr, want := range map[string]string{
		"198.51.100.7":     "198.51.100.7",
		"2001:db8::1":      "2001:db8::/64",
		"2001:db8::ffff:1": "2001:db8::/64",
		"2001:db8:0:1::1":  "2001:db8:0:1::/64",
	} {
		if got := addressKey(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s counts as %s, want %s", addr, got, want)
		}
	}
}

// The whole path from a request, X-Forwarded-For set on every one: a proxy's is believed,
// anyone else's isn't, and a RemoteAddr that isn't an address is used as it stands.
func TestClientAddress(t *testing.T) {
	s := &Server{cfg: Config{TrustedProxies: proxies}}
	for remote, want := range map[string]string{
		"127.0.0.1:1234":          "2001:db8:1::/64",
		"192.0.2.1:1234":          "192.0.2.1",
		"[2001:db8::1%eth0]:1234": "2001:db8::/64",
		"[::ffff:192.0.2.1]:1234": "192.0.2.1",
		"host:1234":               "host",
		"pipe":                    "pipe",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", "203.0.113.1, 2001:db8:1::5")
		if got := s.clientAddress(r); got != want {
			t.Errorf("from %s: %s, want %s", remote, got, want)
		}
	}
}
