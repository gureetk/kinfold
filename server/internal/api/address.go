// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// clientAddress names the client of a request for the per-address limits of API.md §3: the
// address the connection comes from or, when that is a trusted proxy (Config.TrustedProxies),
// the address the proxies were asked by. It is a key for the limiter and is never logged.
func (s *Server) clientAddress(r *http.Request) string {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			return host
		}
		return r.RemoteAddr
	}
	return addressKey(forwardedClient(peer.Addr(), r.Header.Values("X-Forwarded-For"), s.cfg.TrustedProxies))
}

// forwardedClient is the client behind a connection from peer. A proxy appends the address
// it was asked by to X-Forwarded-For, so the list is read from the right, through the
// trusted proxies, and the first address that isn't one is the client. Whatever stands to
// its left was written by the client or by proxies nobody named, and is ignored. From a
// peer that isn't trusted the header is ignored altogether, and an entry that can't be read
// ends the walk at the last trusted address.
func forwardedClient(peer netip.Addr, forwarded []string, trusted []netip.Prefix) netip.Addr {
	client := plain(peer)
	if !isTrusted(client, trusted) {
		return client
	}
	var hops []string
	for _, v := range forwarded {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, ok := parseHop(hops[i])
		if !ok {
			return client
		}
		client = a
		if !isTrusted(a, trusted) {
			break
		}
	}
	return client
}

// parseHop reads one entry of X-Forwarded-For: an address, or an address and a port as some
// proxies write it.
func parseHop(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return plain(a), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return plain(ap.Addr()), true
	}
	return netip.Addr{}, false
}

// plain drops an IPv6 zone and reads an IPv4-mapped IPv6 address as IPv4, so that one
// client has one spelling.
func plain(a netip.Addr) netip.Addr { return a.WithZone("").Unmap() }

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// addressKey is what an address counts as: an IPv4 address alone, an IPv6 address by its
// /64, which one machine or one home can hold whole and so walk through address by address.
func addressKey(a netip.Addr) string {
	if a.Is6() {
		p, err := a.Prefix(64)
		if err == nil {
			return p.String()
		}
	}
	return a.String()
}
