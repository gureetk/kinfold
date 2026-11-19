// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gureetk/kinfold/server/internal/api"
	"github.com/gureetk/kinfold/server/internal/apns"
	"github.com/gureetk/kinfold/server/internal/push"
	"github.com/gureetk/kinfold/server/internal/wire"
)

const bundle = "ca.gureet.kinfold"

// appleCall is one request as the fake Apple host got it.
type appleCall struct {
	proto  int
	device string // the token, as text
	header http.Header
	body   []byte
}

// fakeApple answers as Apple does, over HTTP/2: 200, or 410 Unregistered for the token
// "dead" and 403 InvalidProviderToken for "badkey".
type fakeApple struct {
	*httptest.Server
	calls chan appleCall
}

func newFakeApple(t *testing.T) *fakeApple {
	a := &fakeApple{calls: make(chan appleCall, 64)}
	a.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		token, _ := hex.DecodeString(strings.TrimPrefix(r.URL.Path, "/3/device/"))
		a.calls <- appleCall{r.ProtoMajor, string(token), r.Header.Clone(), body}
		switch string(token) {
		case "dead":
			w.WriteHeader(http.StatusGone)
			io.WriteString(w, `{"reason":"Unregistered","timestamp":1793635200000}`)
		case "badkey":
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"reason":"InvalidProviderToken"}`)
		}
	}))
	a.EnableHTTP2 = true
	a.StartTLS()
	t.Cleanup(a.Close)
	return a
}

// config is a server's Apple keys, one per environment named, all sent to this host.
func (a *fakeApple) config(keys map[string]apns.Key) api.AppleConfig {
	roots := x509.NewCertPool()
	roots.AddCert(a.Certificate())
	hosts := map[string]string{}
	for env := range keys {
		hosts[env] = a.URL
	}
	return api.AppleConfig{BundleID: bundle, Keys: keys, Hosts: hosts, Client: apns.DefaultHTTP(roots)}
}

// next waits for Apple's next request for the token, skipping others.
func (a *fakeApple) next(t *testing.T, token string) appleCall {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case c := <-a.calls:
			if c.device == token {
				return c
			}
		case <-timeout:
			t.Fatalf("no push for %s", token)
		}
	}
}

func appleKey(t *testing.T, id string) apns.Key {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return apns.Key{ID: id, Team: "TEAM123456", Private: k}
}

func (l *live) registerApple(d *device, env, notify, locate string) {
	l.t.Helper()
	reg := map[string]any{"kind": "apns", "environment": env, "notify": b64([]byte(notify))}
	if locate != "" {
		reg["locate"] = b64([]byte(locate))
	}
	expect(l.t, l.json("PUT", "/v1/push", reg, l.login(d)), http.StatusNoContent, "")
}

// appleOpened checks a request to Apple against the Apple notification of API.md §12 for its
// push type, and the provider token against the key, then opens the push with the device's
// key from the vectors.
func appleOpened(t *testing.T, server []byte, d *device, key apns.Key, now uint64, c appleCall) (string, uint8, []byte) {
	t.Helper()
	h := c.header
	pushType := h.Get("Apns-Push-Type")
	var payload struct {
		APS     map[string]any `json:"aps"`
		Kinfold string         `json:"kinfold"`
	}
	if c.proto != 2 || json.Unmarshal(c.body, &payload) != nil {
		t.Fatalf("HTTP/%d, payload %s", c.proto, c.body)
	}
	sealed, err := wire.DecodeB64u(payload.Kinfold)
	if err != nil {
		t.Fatal("the sealed push isn't base64url")
	}
	codes := map[string]uint8{"alert": push.Alert, "background": push.Background, "location": push.Location}
	want, err := push.ForApple(codes[pushType], sealed, now)
	if err != nil || h.Get("Apns-Topic") != bundle+want.TopicSuffix || h.Get("Apns-Priority") != strconv.Itoa(want.Priority) ||
		h.Get("Apns-Expiration") != strconv.FormatInt(want.Expiration, 10) || !bytes.Equal(c.body, want.Payload) {
		t.Fatalf("a %q push: %v %s", pushType, h, c.body)
	}
	bearer, _ := strings.CutPrefix(h.Get("Authorization"), "bearer ")
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		t.Fatal("the provider token")
	}
	header, _ := wire.DecodeB64u(parts[0])
	claims, _ := wire.DecodeB64u(parts[1])
	sig, _ := wire.DecodeB64u(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if string(header) != `{"alg":"ES256","kid":"`+key.ID+`"}` || string(claims) != `{"iat":`+strconv.FormatUint(now/1000, 10)+`,"iss":"`+key.Team+`"}` ||
		len(sig) != 64 || !ecdsa.Verify(&key.Private.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatalf("the provider token: %s %s", header, claims)
	}
	ptype, body := openSealed(t, server, d, sealed, now)
	return pushType, ptype, body
}

// With its own Apple key, the server sends straight to Apple: an alert for notify, a location
// push for locate, each the Apple notification of API.md §12 with a provider token made with
// the key; a dead token ends the registration; the operator's status shows Apple's last
// answer.
func TestPushApple(t *testing.T) {
	apple := newFakeApple(t)
	key := appleKey(t, "KEY1234567")
	l := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) {
		c.Push.Apple = apple.config(map[string]apns.Key{"sandbox": key})
	})
	maya, alex := byLabel(l.devs, "maya/phone"), byLabel(l.devs, "alex/phone")
	l.registerApple(maya, "sandbox", "maya-notify", "maya-locate")

	f3 := envelopeNamed(t, "f3") // jordan/ha, a circle envelope to maya and others
	expect(t, l.postWake(f3, "notify"), http.StatusCreated, "")
	pushType, ptype, body := appleOpened(t, l.srv.ServerKey(), maya, key, l.clk.Now(), apple.next(t, "maya-notify"))
	if pushType != "alert" || ptype != push.Records || !bytes.Equal(body, push.RecordsBody([][]byte{push.Record(l.clk.Now(), f3)})) {
		t.Fatalf("notify: a %s push of type %d", pushType, ptype)
	}

	f2 := envelopeNamed(t, "f2") // jordan/web, a direct envelope to maya
	expect(t, l.postWake(f2, "locate"), http.StatusCreated, "")
	if pushType, ptype, _ := appleOpened(t, l.srv.ServerKey(), maya, key, l.clk.Now(), apple.next(t, "maya-locate")); pushType != "location" ||
		ptype != push.Records {
		t.Fatalf("locate: a %s push of type %d", pushType, ptype)
	}

	// Apple has dropped Alex's token: the registration ends, and Alex's phone hears of it
	// when it next connects. (Maya's stream is open, so this is the only push.)
	l.registerApple(alex, "sandbox", "dead", "")
	l.open(maya, "")
	expect(t, l.postWake(envelopeNamed(t, "f1"), "notify"), http.StatusCreated, "")
	apple.next(t, "dead")
	if !l.srv.FlushPushes(5 * time.Second) {
		t.Fatal("pushes still in flight")
	}
	ca, _, _ := l.open(alex, "")
	if ev := awaitEvent(t, ca); ev["type"] != "push_dropped" {
		t.Fatalf("push_dropped: %v", ev)
	}

	h := l.admin("GET", "/status", "")
	keys, _ := h["apple"].([]any)
	if len(keys) != 1 {
		t.Fatalf("status: %v", h["apple"])
	}
	k := keys[0].(map[string]any)
	if k["environment"] != "sandbox" || k["key_id"] != "KEY1234567" || k["last_answer"] != "alert: Apple answered 410 Unregistered" ||
		k["last_at"] != float64(l.clk.Now()) {
		t.Fatalf("status: %v", k)
	}
}

// A device without a location token is woken with a background push before a silence alert.
// A refusal for the server's key keeps the registration, and the status says why.
func TestPushAppleBackground(t *testing.T) {
	apple := newFakeApple(t)
	key := appleKey(t, "KEY1234567")
	l := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) {
		c.Push.Apple = apple.config(map[string]apns.Key{"production": key})
	})
	jordan, maya := byLabel(l.devs, "jordan/phone"), byLabel(l.devs, "maya/phone")
	l.registerApple(maya, "production", "maya-notify", "")
	start := l.clk.Now()
	if r := l.putWatch(jordan, maya, grant(maya, l.cid, jordan.account, 15, start, start+1440*minute)); r.code != http.StatusNoContent {
		t.Fatalf("watch: %d", r.code)
	}
	l.clk.Set(start + 15*minute)
	l.srv.CheckSilences()
	if pushType, ptype, body := appleOpened(t, l.srv.ServerKey(), maya, key, l.clk.Now(), apple.next(t, "maya-notify")); pushType != "background" ||
		ptype != push.Wake || len(body) != 0 {
		t.Fatalf("the wake-up: a %s push of type %d", pushType, ptype)
	}

	l.registerApple(maya, "production", "badkey", "")
	expect(t, l.postWake(envelopeNamed(t, "f3"), "notify"), http.StatusCreated, "")
	apple.next(t, "badkey")
	if !l.srv.FlushPushes(5 * time.Second) {
		t.Fatal("pushes still in flight")
	}
	expect(t, l.postWake(envelopeNamed(t, "f14"), "notify"), http.StatusCreated, "")
	apple.next(t, "badkey") // still registered
	if !l.srv.FlushPushes(5 * time.Second) {
		t.Fatal("pushes still in flight")
	}
	k := l.admin("GET", "/status", "")["apple"].([]any)[0].(map[string]any)
	if k["environment"] != "production" || k["last_answer"] != "alert: Apple answered 403 InvalidProviderToken" {
		t.Fatalf("status: %v", k)
	}
}

// What an apns registration may hold (API.md §12), and what discovery says (§4).
func TestPushAppleRegistration(t *testing.T) {
	apple := newFakeApple(t)
	l := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) {
		c.Push.Apple = apple.config(map[string]apns.Key{"sandbox": appleKey(t, "KEY1234567")})
	})
	tok := l.login(byLabel(l.devs, "maya/phone"))
	reg := func(env string, notify, locate []byte) map[string]any {
		r := map[string]any{"kind": "apns", "notify": b64(notify)}
		if env != "" {
			r["environment"] = env
		}
		if locate != nil {
			r["locate"] = b64(locate)
		}
		return r
	}
	token := bytes.Repeat([]byte{7}, 32)
	for _, bad := range []map[string]any{reg("", token, nil), reg("staging", token, nil), reg("sandbox", nil, nil),
		reg("sandbox", make([]byte, 257), nil), reg("sandbox", token, make([]byte, 257))} {
		expect(t, l.json("PUT", "/v1/push", bad, tok), http.StatusBadRequest, "bad_request")
	}
	expect(t, l.json("PUT", "/v1/push", reg("production", token, nil), tok), http.StatusForbidden, "forbidden")
	expect(t, l.json("PUT", "/v1/push", reg("sandbox", make([]byte, 256), token), tok), http.StatusNoContent, "")

	d := decode(t, l.do(call{method: "GET", path: "/.well-known/kinfold"}))
	found := false
	for _, f := range d["features"].([]any) {
		found = found || f == "apns"
	}
	a, _ := d["apns"].(map[string]any)
	if envs, _ := a["environments"].([]any); !found || a["bundle_id"] != bundle || len(envs) != 1 || envs[0] != "sandbox" {
		t.Fatalf("discovery: %v %v", d["features"], d["apns"])
	}

	// Both environments, listed in order.
	l2 := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) {
		c.Push.Apple = apple.config(map[string]apns.Key{"sandbox": appleKey(t, "KEY1234567"), "production": appleKey(t, "KEY7654321")})
	})
	d = decode(t, l2.do(call{method: "GET", path: "/.well-known/kinfold"}))
	if envs := d["apns"].(map[string]any)["environments"].([]any); len(envs) != 2 || envs[0] != "production" || envs[1] != "sandbox" {
		t.Fatalf("environments: %v", envs)
	}
}

// A registration for an environment the server no longer holds a key for gets nothing.
func TestPushAppleOff(t *testing.T) {
	apple := newFakeApple(t)
	var cfg api.Config
	l := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) {
		c.Push.Apple = apple.config(map[string]apns.Key{"sandbox": appleKey(t, "KEY1234567")})
		cfg = *c
	})
	l.registerApple(byLabel(l.devs, "maya/phone"), "sandbox", "maya-notify", "")
	cfg.Push.Apple = apple.config(map[string]apns.Key{"production": appleKey(t, "KEY7654321")})
	off := api.New(cfg)
	f1 := envelopeNamed(t, "f1")
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
	select {
	case c := <-apple.calls:
		t.Fatalf("a push for %s", c.device)
	case <-time.After(300 * time.Millisecond):
	}
}
