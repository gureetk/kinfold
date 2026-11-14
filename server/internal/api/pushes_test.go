// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gureetk/kinfold/server/internal/api"
	"github.com/gureetk/kinfold/server/internal/kcrypto"
	"github.com/gureetk/kinfold/server/internal/push"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// relayCall is what a family's server sent the relay (API.md §14).
type relayCall struct {
	Capability, Sealed, Sig string
	SentAt                  uint64 `json:"sent_at"`
	Delivery                string
}

// fakeRelay accepts pushes, except for the capability "dead", which Apple has dropped.
type fakeRelay struct {
	*httptest.Server
	calls chan relayCall
}

func newFakeRelay(t *testing.T) *fakeRelay {
	r := &fakeRelay{calls: make(chan relayCall, 64)}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var c relayCall
		if req.URL.Path != "/v1/push" || json.NewDecoder(req.Body).Decode(&c) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.calls <- c
		if c.Capability == b64([]byte("dead")) {
			w.WriteHeader(http.StatusGone)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(r.Close)
	return r
}

// next waits for the relay's next call with this capability, skipping others.
func (r *fakeRelay) next(t *testing.T, capability string) relayCall {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case c := <-r.calls:
			if c.Capability == b64([]byte(capability)) {
				return c
			}
		case <-timeout:
			t.Fatalf("no push for %s", capability)
		}
	}
}

// none checks that no push for the capability comes within a moment.
func (r *fakeRelay) none(t *testing.T, capability string) {
	t.Helper()
	timeout := time.After(300 * time.Millisecond)
	for {
		select {
		case c := <-r.calls:
			if c.Capability == b64([]byte(capability)) {
				t.Fatalf("a push for %s", capability)
			}
		case <-timeout:
			return
		}
	}
}

// opened checks a relay call's signature and opens its push with the device's key from the
// vectors: the Push, checked against the server key, and its type and body.
func opened(t *testing.T, server []byte, d *device, c relayCall) (uint8, []byte) {
	t.Helper()
	capability, _ := wire.DecodeB64u(c.Capability)
	sealed, _ := wire.DecodeB64u(c.Sealed)
	sig, _ := wire.DecodeB64u(c.Sig)
	codes := map[string]uint8{"alert": push.Alert, "background": push.Background, "location": push.Location}
	if len(sealed) != push.SealedLen || !kcrypto.Verify(server, "relay-push", wire.Concat(capability, sealed, wire.U64(c.SentAt),
		[]byte{codes[c.Delivery]}), sig) {
		t.Fatalf("the relay call: %d bytes, signature", len(sealed))
	}
	return openSealed(t, server, d, sealed, c.SentAt)
}

// openSealed opens a sealed push with the device's key from the vectors, and checks the
// server's signature for that device.
func openSealed(t *testing.T, server []byte, d *device, sealed []byte, sentAt uint64) (uint8, []byte) {
	t.Helper()
	if len(sealed) != push.SealedLen {
		t.Fatalf("a sealed push of %d bytes", len(sealed))
	}
	var sk []byte
	for _, p := range tv.Obj(tv.Load(t)["identities"]) {
		for _, dv := range tv.Obj(tv.Obj(p)["devices"]) {
			if dd := tv.Obj(dv); tv.Str(dd["label"]) == d.label {
				for _, k := range tv.Arr(dd["deks"]) {
					if bytes.Equal(tv.Hex(tv.Obj(k)["key_id"]), sealed[:8]) {
						sk = tv.Hex(tv.Obj(k)["sk"])
					}
				}
			}
		}
	}
	if sk == nil {
		t.Fatalf("sealed to a key %x %s doesn't have", sealed[:8], d.label)
	}
	padded, err := kcrypto.Open(sealed[8:40], sk, push.Info(d.id, sealed[:8]), sealed[40:])
	if err != nil {
		t.Fatalf("the push doesn't open: %v", err)
	}
	p, ok := wire.Unpad(padded, push.PlainLen)
	if !ok {
		t.Fatal("the push's padding")
	}
	r := wire.NewReader(p)
	ver, ptype, at, body := r.U8(), r.U8(), r.U64(), r.Vec16()
	tbs := p[:r.Pos()]
	psig := r.Take(64)
	if !r.Done() || ver != 0 || at != sentAt || !kcrypto.Verify(server, "push-sig", wire.Concat(d.id, tbs), psig) {
		t.Fatal("the push: not signed by the server for this device")
	}
	return ptype, body
}

func (l *live) registerRelay(d *device, notify, locate string) {
	l.t.Helper()
	reg := map[string]any{"kind": "relay", "notify": b64([]byte(notify))}
	if locate != "" {
		reg["locate"] = b64([]byte(locate))
	}
	expect(l.t, l.json("PUT", "/v1/push", reg, l.login(d)), http.StatusNoContent, "")
}

func (l *live) postWake(raw []byte, wake string) *httptest.ResponseRecorder {
	sender := l.devs[string(raw[20:36])]
	return l.do(call{method: "POST", path: "/v1/circles/" + b64(l.cid) + "/envelopes", body: raw, ctype: "application/octet-stream",
		token: l.login(sender), header: map[string]string{"Kinfold-Wake": wake}})
}

func envelopeNamed(t *testing.T, name string) []byte {
	for _, c := range tv.Arr(tv.Obj(tv.Load(t)["envelopes"])["valid"]) {
		if cc := tv.Obj(c); tv.Str(cc["name"]) == name {
			return tv.Hex(cc["raw"])
		}
	}
	t.Fatalf("no envelope %s", name)
	return nil
}

// Kinfold-Wake: a records push to a recipient without a stream, as an alert for notify and a
// location push for locate; nothing to one with a stream; a dead registration is dropped and
// the device told.
func TestPushRelay(t *testing.T) {
	relay := newFakeRelay(t)
	l := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) { c.Push.Relay = relay.URL })
	maya, alex := byLabel(l.devs, "maya/phone"), byLabel(l.devs, "alex/phone")
	l.registerRelay(maya, "maya-notify", "maya-locate")

	f3 := envelopeNamed(t, "f3") // jordan/ha, a circle envelope to maya and others
	expect(t, l.postWake(f3, "notify"), http.StatusCreated, "")
	c := relay.next(t, "maya-notify")
	if c.Delivery != "alert" || c.SentAt != l.clk.Now() {
		t.Fatalf("notify: %+v", c)
	}
	ptype, body := opened(t, l.srv.ServerKey(), maya, c)
	if ptype != push.Records || !bytes.Equal(body, push.RecordsBody([][]byte{push.Record(l.clk.Now(), f3)})) {
		t.Fatalf("a records push with the record: type %d", ptype)
	}

	f2 := envelopeNamed(t, "f2") // jordan/web, a direct envelope to maya
	expect(t, l.postWake(f2, "locate"), http.StatusCreated, "")
	c = relay.next(t, "maya-locate")
	if ptype, _ := opened(t, l.srv.ServerKey(), maya, c); c.Delivery != "location" || ptype != push.Records {
		t.Fatalf("locate: %s, type %d", c.Delivery, ptype)
	}

	// With a stream open, the record goes there and no push is sent.
	l.open(maya, "")
	expect(t, l.postWake(envelopeNamed(t, "f14"), "notify"), http.StatusCreated, "")
	relay.none(t, "maya-notify")

	// Apple has dropped Alex's token: the registration ends, and Alex's phone hears of it
	// when it next connects.
	l.registerRelay(alex, "dead", "")
	expect(t, l.postWake(envelopeNamed(t, "f1"), "notify"), http.StatusCreated, "")
	relay.next(t, "dead")
	if !l.srv.FlushPushes(5 * time.Second) { // the drop is written after the relay answers
		t.Fatal("pushes still in flight")
	}
	ca, _, _ := l.open(alex, "")
	if ev := awaitEvent(t, ca); ev["type"] != "push_dropped" {
		t.Fatalf("push_dropped: %v", ev)
	}
}

// A silent device is woken by a location push where it can take one, and the watcher's
// phone gets the silence alert by push.
func TestPushSilence(t *testing.T) {
	relay := newFakeRelay(t)
	l := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) { c.Push.Relay = relay.URL })
	jordan, maya := byLabel(l.devs, "jordan/phone"), byLabel(l.devs, "maya/phone")
	l.registerRelay(maya, "maya-notify", "maya-locate")
	l.registerRelay(jordan, "jordan-notify", "")
	start := l.clk.Now()
	if r := l.putWatch(jordan, maya, grant(maya, l.cid, jordan.account, 15, start+1440*minute)); r.code != http.StatusNoContent {
		t.Fatalf("watch: %d", r.code)
	}
	l.clk.Set(start + 15*minute)
	l.srv.CheckSilences()
	c := relay.next(t, "maya-locate")
	if ptype, body := opened(t, l.srv.ServerKey(), maya, c); c.Delivery != "location" || ptype != push.Wake || len(body) != 0 {
		t.Fatalf("the wake-up: %s, type %d", c.Delivery, ptype)
	}
	l.clk.Set(start + 17*minute)
	l.srv.CheckSilences()
	c = relay.next(t, "jordan-notify")
	ptype, body := opened(t, l.srv.ServerKey(), jordan, c)
	if c.Delivery != "alert" || ptype != push.Silence || !bytes.Equal(body, push.SilenceBody(l.cid, maya.id, 0)) {
		t.Fatalf("the alert: %s, type %d", c.Delivery, ptype)
	}
}

// What a registration may hold (API.md §12).
func TestPushRegistration(t *testing.T) {
	var mu sync.Mutex
	resolved := map[string][]netip.Addr{
		"push.example":   {netip.MustParseAddr("203.0.113.7")},
		"inside.example": {netip.MustParseAddr("203.0.113.8"), netip.MustParseAddr("10.1.2.3")},
		"mapped.example": {netip.MustParseAddr("::ffff:127.0.0.1")},
		"home.lan":       {netip.MustParseAddr("192.168.1.20")},
	}
	resolve := func(_ context.Context, host string) ([]netip.Addr, error) {
		mu.Lock()
		defer mu.Unlock()
		if a, ok := resolved[host]; ok {
			return a, nil
		}
		return nil, errors.New("no such host")
	}
	vapid, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	l := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) {
		c.Push.Resolve, c.Push.Hosts, c.Push.VAPID = resolve, []string{"home.lan"}, vapid
	})
	maya := byLabel(l.devs, "maya/phone")
	tok := l.login(maya)
	key, _ := ecdh.P256().GenerateKey(nil)
	web := func(endpoint string) map[string]any {
		return map[string]any{"kind": "webpush", "endpoint": endpoint, "p256dh": b64(key.PublicKey().Bytes()),
			"auth": b64(bytes.Repeat([]byte{1}, 16))}
	}
	expect(t, l.json("PUT", "/v1/push", map[string]any{"kind": "relay", "notify": b64([]byte("x"))}, tok), http.StatusForbidden, "forbidden")
	expect(t, l.json("PUT", "/v1/push", map[string]any{"kind": "apns", "notify": b64([]byte("token"))}, tok), http.StatusForbidden, "forbidden")
	expect(t, l.json("PUT", "/v1/push", map[string]any{"kind": "fcm"}, tok), http.StatusBadRequest, "bad_request")
	for _, bad := range []string{"http://push.example/x", "https://10.0.0.1/x", "https://[::1]/x", "https://100.64.0.9/x",
		"https://169.254.1.1/x", "https://[fd00::1]/x", "https://inside.example/x", "https://mapped.example/x",
		"https://nowhere.example/x", "https://user@push.example/x", "https://push.example/" + string(bytes.Repeat([]byte("a"), 1000))} {
		expect(t, l.json("PUT", "/v1/push", web(bad), tok), http.StatusBadRequest, "bad_request")
	}
	expect(t, l.json("PUT", "/v1/push", web("https://push.example/x"), tok), http.StatusNoContent, "")
	expect(t, l.json("PUT", "/v1/push", web("https://home.lan/x"), tok), http.StatusNoContent, "") // the operator's list
	badKey := web("https://push.example/x")
	badKey["p256dh"] = b64(bytes.Repeat([]byte{4}, 65))
	expect(t, l.json("PUT", "/v1/push", badKey, tok), http.StatusBadRequest, "bad_request")
	expect(t, l.do(call{method: "DELETE", path: "/v1/push", token: tok}), http.StatusNoContent, "")
	expect(t, l.json("PUT", "/v1/push", web("https://push.example/x"), l.login(byLabel(l.devs, "jordan/recovery"))),
		http.StatusForbidden, "forbidden") // a recovery device receives nothing

	// With HostsOnly, every host off the list is refused.
	l2 := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) {
		c.Push.Resolve, c.Push.Hosts, c.Push.HostsOnly, c.Push.VAPID = resolve, []string{"home.lan"}, true, vapid
	})
	tok = l2.login(byLabel(l2.devs, "maya/phone"))
	expect(t, l2.json("PUT", "/v1/push", web("https://push.example/x"), tok), http.StatusBadRequest, "bad_request")
	expect(t, l2.json("PUT", "/v1/push", web("https://home.lan/x"), tok), http.StatusNoContent, "")

	// Without a VAPID key, a server takes no Web Push registrations.
	l3 := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) { c.Push.Resolve = resolve })
	expect(t, l3.json("PUT", "/v1/push", web("https://push.example/x"), l3.login(byLabel(l3.devs, "maya/phone"))),
		http.StatusForbidden, "forbidden")
}

// A wake-up past its limit refuses the upload: nothing is stored.
func TestPushWakeLimit(t *testing.T) {
	l := newLive(t, api.Limits{ChallengesPerDevice: 1 << 20, ChallengesPerAddress: 1 << 20, EnvelopesPerMinute: 1 << 20,
		EnvelopesPerHour: 1 << 20, WakeNotify: -1}, api.StreamTimes{})
	f3 := envelopeNamed(t, "f3")
	expect(t, l.postWake(f3, "notify"), http.StatusTooManyRequests, "rate_limited")
	rec := l.do(call{method: "GET", path: "/v1/inbox", token: l.login(byLabel(l.devs, "maya/phone"))})
	if rec.Body.Len() != 0 {
		t.Error("the refused upload was stored")
	}
	expect(t, l.postWake(f3, ""), http.StatusCreated, "")
}
