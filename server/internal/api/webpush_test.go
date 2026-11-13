// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gureetk/kinfold/server/internal/api"
	"github.com/gureetk/kinfold/server/internal/push"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// pushCall is one Web Push request as the push host got it.
type pushCall struct {
	path   string
	header http.Header
	body   []byte
}

// fakePushHost is a Web Push host (RFC 8030) on TLS, with httptest's certificate, which names
// example.com. It answers 201, or 410 at /dead, and counts connections and requests.
type fakePushHost struct {
	*httptest.Server
	calls           chan pushCall
	conns, requests atomic.Int32
}

func newFakePushHost(t *testing.T) *fakePushHost {
	h := &fakePushHost{calls: make(chan pushCall, 64)}
	h.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		h.calls <- pushCall{path: r.URL.Path, header: r.Header.Clone(), body: body}
		if r.URL.Path == "/dead" {
			w.WriteHeader(http.StatusGone)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	h.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			h.conns.Add(1)
		}
	}
	h.StartTLS()
	t.Cleanup(h.Close)
	return h
}

// roots trusts the host's certificate.
func (h *fakePushHost) roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(h.Certificate())
	return pool
}

func (h *fakePushHost) port() string {
	_, p, _ := net.SplitHostPort(h.Listener.Addr().String())
	return p
}

// next waits for the next request to the path, skipping others.
func (h *fakePushHost) next(t *testing.T, path string) pushCall {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case c := <-h.calls:
			if c.path == path {
				return c
			}
		case <-timeout:
			t.Fatalf("no push to %s", path)
		}
	}
}

// subscription is a phone's UnifiedPush subscription: its key and auth secret (RFC 8291).
type subscription struct {
	key  *ecdh.PrivateKey
	auth []byte
}

func newSubscription() subscription {
	key, _ := ecdh.P256().GenerateKey(rand.Reader)
	auth := make([]byte, 16)
	rand.Read(auth)
	return subscription{key, auth}
}

func (l *live) registerWebPush(d *device, endpoint string, s subscription) {
	l.t.Helper()
	expect(l.t, l.json("PUT", "/v1/push", map[string]any{"kind": "webpush", "endpoint": endpoint,
		"p256dh": b64(s.key.PublicKey().Bytes()), "auth": b64(s.auth)}, l.login(d)), http.StatusNoContent, "")
}

// checkVAPID checks a request's Authorization (RFC 8292): an ES256 JWT for the endpoint's
// origin, signed with the server's VAPID key, which k names, that expires within 24 hours and
// gives the server's URL as its contact.
func checkVAPID(t *testing.T, header string, key *ecdsa.PublicKey, aud string, now uint64) {
	t.Helper()
	jwt, k, ok := strings.Cut(strings.TrimPrefix(header, "vapid t="), ", k=")
	pub, _ := key.Bytes()
	if !ok || !strings.HasPrefix(header, "vapid t=") || k != b64(pub) {
		t.Fatalf("Authorization: %q", header)
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("a JWT of %d parts", len(parts))
	}
	head, err1 := wire.DecodeB64u(parts[0])
	body, err2 := wire.DecodeB64u(parts[1])
	sig, err3 := wire.DecodeB64u(parts[2])
	var h struct{ Typ, Alg string }
	var c struct {
		Aud string
		Exp uint64
		Sub string
	}
	if errors.Join(err1, err2, err3, json.Unmarshal(head, &h), json.Unmarshal(body, &c)) != nil || h.Alg != "ES256" || h.Typ != "JWT" {
		t.Fatalf("the JWT: %s %s", head, body)
	}
	if c.Aud != aud || c.Sub != url || c.Exp <= now/1000 || c.Exp > now/1000+24*60*60 {
		t.Fatalf("the JWT's claims: %s", body)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the JWT's signature")
	}
}

// Web Push (API.md §12): a push for a device without a stream goes to its subscription,
// encrypted for it (RFC 8291) and signed with the server's VAPID key (RFC 8292). Every push
// has the same headers and size, each goes over a connection of its own, and a 410 ends the
// registration.
func TestWebPush(t *testing.T) {
	host := newFakePushHost(t)
	vapid, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	resolve := func(_ context.Context, name string) ([]netip.Addr, error) {
		if name == "example.com" {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return nil, errors.New("no such host")
	}
	l := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) {
		c.Push.VAPID, c.Push.Resolve, c.Push.RootCAs = vapid, resolve, host.roots()
		c.Push.Hosts = []string{"example.com"} // a distributor on the home network
	})
	maya, alex := byLabel(l.devs, "maya/phone"), byLabel(l.devs, "alex/phone")
	sub := newSubscription()
	origin := "https://example.com:" + host.port()
	l.registerWebPush(maya, origin+"/maya", sub)

	f3 := envelopeNamed(t, "f3") // jordan/ha, a circle envelope to maya and others
	expect(t, l.postWake(f3, "notify"), http.StatusCreated, "")
	c := host.next(t, "/maya")
	for k, v := range map[string]string{"TTL": "3600", "Urgency": "high", "Content-Encoding": "aes128gcm",
		"Content-Type": "application/octet-stream"} {
		if got := c.header.Get(k); got != v {
			t.Errorf("%s: %q, want %q", k, got, v)
		}
	}
	checkVAPID(t, c.header.Get("Authorization"), &vapid.PublicKey, origin, l.clk.Now())
	sealed, err := api.OpenECE(c.body, sub.key, sub.auth)
	if err != nil {
		t.Fatalf("the subscription can't open the push: %v", err)
	}
	ptype, body := openSealed(t, l.srv.ServerKey(), maya, sealed, l.clk.Now())
	if ptype != push.Records || !bytes.Equal(body, push.RecordsBody([][]byte{push.Record(l.clk.Now(), f3)})) {
		t.Fatalf("a records push with the record: type %d", ptype)
	}

	// locate looks the same to the push host.
	expect(t, l.postWake(envelopeNamed(t, "f2"), "locate"), http.StatusCreated, "") // jordan/web, direct to maya
	c2 := host.next(t, "/maya")
	for _, k := range []string{"TTL", "Urgency", "Content-Encoding", "Content-Type"} {
		if c2.header.Get(k) != c.header.Get(k) {
			t.Errorf("%s differs: %q, %q", k, c2.header.Get(k), c.header.Get(k))
		}
	}
	if len(c2.body) != len(c.body) {
		t.Errorf("pushes of %d and %d bytes", len(c.body), len(c2.body))
	}

	// The push host says Alex's subscription is gone: the registration ends, and Alex's phone
	// hears of it when it next connects.
	l.registerWebPush(alex, origin+"/dead", newSubscription())
	expect(t, l.postWake(envelopeNamed(t, "f1"), "notify"), http.StatusCreated, "")
	host.next(t, "/dead")
	if !l.srv.FlushPushes(5 * time.Second) {
		t.Fatal("pushes still in flight")
	}
	ca, _, _ := l.open(alex, "")
	if ev := awaitEvent(t, ca); ev["type"] != "push_dropped" {
		t.Fatalf("push_dropped: %v", ev)
	}
	if conns, reqs := host.conns.Load(), host.requests.Load(); conns != reqs || reqs != 4 {
		t.Errorf("%d requests over %d connections; want 4 over 4", reqs, conns)
	}
}

// The address rules hold at send time (API.md §12): a host that resolved to a public address
// when the phone registered and resolves to a private one now gets no connection.
func TestWebPushRebinding(t *testing.T) {
	host := newFakePushHost(t)
	vapid, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var mu sync.Mutex
	addr, lookups := netip.MustParseAddr("203.0.113.9"), 0
	resolve := func(_ context.Context, name string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		if name != "rebind.example" {
			return nil, errors.New("no such host")
		}
		lookups++
		return []netip.Addr{addr}, nil
	}
	l := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) {
		c.Push.VAPID, c.Push.Resolve, c.Push.RootCAs = vapid, resolve, host.roots()
	})
	l.registerWebPush(byLabel(l.devs, "maya/phone"), "https://rebind.example:"+host.port()+"/maya", newSubscription())
	mu.Lock()
	addr, before := netip.MustParseAddr("127.0.0.1"), lookups
	mu.Unlock()

	expect(t, l.postWake(envelopeNamed(t, "f2"), "notify"), http.StatusCreated, "")
	if !l.srv.FlushPushes(5 * time.Second) {
		t.Fatal("pushes still in flight")
	}
	mu.Lock()
	defer mu.Unlock()
	if lookups == before {
		t.Fatal("the send didn't resolve the host again")
	}
	if n := host.conns.Load(); n != 0 {
		t.Fatalf("%d connections to a private address", n)
	}
}

// The discovery document says how the server pushes (API.md §4).
func TestPushDiscovery(t *testing.T) {
	vapid, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := vapid.PublicKey.Bytes()
	for _, tc := range []struct {
		name       string
		opt        func(*api.Config)
		features   []string
		relay, key any
	}{
		{"neither", func(*api.Config) {}, []string{"member_tokens", "web_devices"}, nil, nil},
		{"both", func(c *api.Config) { c.Push.Relay, c.Push.VAPID = "https://relay.example", vapid },
			[]string{"member_tokens", "relay", "web_devices", "webpush"}, "https://relay.example", b64(pub)},
	} {
		e := newEnv(t, generous, tc.opt)
		d := decode(t, e.do(call{method: "GET", path: "/.well-known/kinfold"}))
		var features []string
		for _, f := range d["features"].([]any) {
			features = append(features, f.(string))
		}
		slices.Sort(features)
		if !slices.Equal(features, tc.features) || d["relay"] != tc.relay || d["vapid_key"] != tc.key {
			t.Errorf("%s: features %v, relay %v, vapid_key %v", tc.name, features, d["relay"], d["vapid_key"])
		}
	}
}

// A registration for a route the operator has switched off since gets nothing (API.md §12).
func TestPushRouteOff(t *testing.T) {
	relay, host := newFakeRelay(t), newFakePushHost(t)
	vapid, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var cfg api.Config
	l := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) {
		c.Push.Relay, c.Push.VAPID, c.Push.Hosts, c.Push.RootCAs = relay.URL, vapid, []string{"127.0.0.1"}, host.roots()
		cfg = *c
	})
	maya, alex := byLabel(l.devs, "maya/phone"), byLabel(l.devs, "alex/phone")
	l.registerRelay(maya, "maya-notify", "")
	l.registerWebPush(alex, "https://127.0.0.1:"+host.port()+"/alex", newSubscription())

	cfg.Push.Relay, cfg.Push.VAPID = "", nil // the same data, served again with both routes off
	off := api.New(cfg)
	f1 := envelopeNamed(t, "f1") // to maya and alex, among others
	req := httptest.NewRequest("POST", "/v1/circles/"+b64(l.cid)+"/envelopes", bytes.NewReader(f1))
	req.Header.Set("Kinfold-Api", "1")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Kinfold-Wake", "notify")
	req.Header.Set("Authorization", "Bearer "+b64(l.login(l.devs[string(f1[20:36])])))
	rec := httptest.NewRecorder()
	off.ServeHTTP(rec, req)
	expect(t, rec, http.StatusCreated, "")
	if !off.FlushPushes(5 * time.Second) {
		t.Fatal("pushes still in flight")
	}
	relay.none(t, "maya-notify")
	if n := host.requests.Load(); n != 0 {
		t.Fatalf("%d Web Push requests", n)
	}
}
