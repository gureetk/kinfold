// SPDX-License-Identifier: AGPL-3.0-or-later

package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func p8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func newKey(t *testing.T) Key {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Key{ID: "ABC123DEFG", Team: "DEF123GHIJ", Private: k}
}

// A .p8 file is one PEM block of type PRIVATE KEY holding a PKCS #8 P-256 key.
func TestParseKey(t *testing.T) {
	k := newKey(t).Private
	got, err := ParseKey(p8(t, k))
	if err != nil || !got.Equal(k) {
		t.Fatalf("a .p8 key: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	sec1, _ := x509.MarshalECPrivateKey(k)
	for name, file := range map[string][]byte{
		"empty":         nil,
		"P-384":         p8(t, p384),
		"Ed25519":       p8(t, edKey),
		"SEC 1":         pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}),
		"two blocks":    append(p8(t, k), p8(t, k)...),
		"not PKCS #8":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("nonsense")}),
		"text after it": append(p8(t, k), "more"...),
	} {
		if _, err := ParseKey(file); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := ParseKey(append(p8(t, k), "\n\n"...)); err != nil {
		t.Errorf("trailing blank lines: %v", err)
	}
}

func TestAppleID(t *testing.T) {
	for s, ok := range map[string]bool{"ABC123DEFG": true, "0123456789": true, "abc123defg": false, "ABC123DEF": false,
		"ABC123DEFGH": false, "ABC-23DEFG": false, "": false} {
		if AppleID(s) != ok {
			t.Errorf("%q: %v", s, !ok)
		}
	}
}

// checkToken checks a provider token against Apple's form and the key, and returns its
// issue time.
func checkToken(t *testing.T, token string, key Key) int64 {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("a token of %d parts", len(parts))
	}
	var header map[string]string
	var claims struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
	}
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	c, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if json.Unmarshal(h, &header) != nil || len(header) != 2 || header["alg"] != "ES256" || header["kid"] != key.ID {
		t.Fatalf("the header: %s", h)
	}
	if json.Unmarshal(c, &claims) != nil || claims.Iss != key.Team || bytes.Count(c, []byte(":")) != 2 {
		t.Fatalf("the claims: %s", c)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(&key.Private.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the signature doesn't verify")
	}
	return claims.Iat
}

func TestToken(t *testing.T) {
	key := newKey(t)
	at := time.Unix(1794000000, 0)
	token, err := Token(key, at)
	if err != nil {
		t.Fatal(err)
	}
	if iat := checkToken(t, token, key); iat != at.Unix() {
		t.Fatalf("iat %d", iat)
	}
}

// request is what the fake Apple host got.
type request struct {
	proto   int
	method  string
	device  string
	header  http.Header
	payload []byte
}

// fakeApple answers as Apple does: 200, or for the devices named below, Apple's refusals.
type fakeApple struct {
	*httptest.Server
	mu       sync.Mutex
	requests []request
}

var refusals = map[string]struct {
	status int
	body   string
}{
	hex.EncodeToString([]byte("gone")):    {410, `{"reason":"Unregistered","timestamp":1794000000000}`},
	hex.EncodeToString([]byte("bad")):     {400, `{"reason":"BadDeviceToken"}`},
	hex.EncodeToString([]byte("topic")):   {400, `{"reason":"DeviceTokenNotForTopic"}`},
	hex.EncodeToString([]byte("key")):     {403, `{"reason":"InvalidProviderToken"}`},
	hex.EncodeToString([]byte("stale")):   {403, `{"reason":"ExpiredProviderToken"}`},
	hex.EncodeToString([]byte("busy")):    {429, `{"reason":"TooManyRequests"}`},
	hex.EncodeToString([]byte("strange")): {500, `{"reason":"<b>not a code</b>"}`},
	hex.EncodeToString([]byte("silent")):  {503, ``},
}

func newFakeApple(t *testing.T, http2 bool) *fakeApple {
	a := &fakeApple{}
	a.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		device, _ := strings.CutPrefix(r.URL.Path, "/3/device/")
		a.mu.Lock()
		a.requests = append(a.requests, request{r.ProtoMajor, r.Method, device, r.Header.Clone(), body})
		a.mu.Unlock()
		if f, ok := refusals[device]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.status)
			io.WriteString(w, f.body)
			return
		}
		w.Header().Set("Apns-Id", "eabeae54-14a8-11e5-b60b-1697f925ec7b")
	}))
	a.EnableHTTP2 = http2
	a.StartTLS()
	t.Cleanup(a.Close)
	return a
}

func (a *fakeApple) client(key Key, now func() time.Time) *Client {
	roots := x509.NewCertPool()
	roots.AddCert(a.Certificate())
	return NewClient(a.URL, key, DefaultHTTP(roots), now)
}

func (a *fakeApple) last(t *testing.T) request {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.requests) == 0 {
		t.Fatal("no request")
	}
	return a.requests[len(a.requests)-1]
}

func note(device string) Notification {
	return Notification{Device: []byte(device), Topic: "ca.gureet.kinfold.location-query", PushType: "location", Priority: 10,
		Expiration: 1794000600, Payload: []byte(`{"aps":{},"kinfold":"x"}`)}
}

// A request is a POST over HTTP/2 to the device's path, with the token, the push type,
// topic, priority and expiry, and the payload as it was given.
func TestSend(t *testing.T) {
	key := newKey(t)
	apple := newFakeApple(t, true)
	at := time.Unix(1794000000, 0)
	c := apple.client(key, func() time.Time { return at })
	if err := c.Send(context.Background(), note("phone")); err != nil {
		t.Fatal(err)
	}
	r := apple.last(t)
	h := r.header
	if r.proto != 2 || r.method != http.MethodPost || r.device != hex.EncodeToString([]byte("phone")) ||
		h.Get("Apns-Push-Type") != "location" || h.Get("Apns-Topic") != "ca.gureet.kinfold.location-query" ||
		h.Get("Apns-Priority") != "10" || h.Get("Apns-Expiration") != "1794000600" || string(r.payload) != `{"aps":{},"kinfold":"x"}` {
		t.Fatalf("the request: HTTP/%d %s %s %v %s", r.proto, r.method, r.device, h, r.payload)
	}
	bearer, ok := strings.CutPrefix(h.Get("Authorization"), "bearer ")
	if !ok || checkToken(t, bearer, key) != at.Unix() {
		t.Fatalf("authorization: %q", h.Get("Authorization"))
	}
	if c.KeyID() != key.ID {
		t.Error("the key ID")
	}
}

// Apple's refusals come back as Errors with their reason, and the dead ones say so.
func TestRefusals(t *testing.T) {
	apple := newFakeApple(t, true)
	c := apple.client(newKey(t), nil)
	for device, want := range map[string]Error{
		"gone":    {410, "Unregistered"},
		"bad":     {400, "BadDeviceToken"},
		"topic":   {400, "DeviceTokenNotForTopic"},
		"key":     {403, "InvalidProviderToken"},
		"busy":    {429, "TooManyRequests"},
		"strange": {500, ""}, // not a reason code: left out of what may be logged
		"silent":  {503, ""},
	} {
		var e *Error
		err := c.Send(context.Background(), note(device))
		if !errors.As(err, &e) || *e != want {
			t.Errorf("%s: %v", device, err)
			continue
		}
		if dead := device == "gone" || device == "bad" || device == "topic"; e.Dead() != dead {
			t.Errorf("%s: dead %v", device, e.Dead())
		}
		if strings.Contains(err.Error(), hex.EncodeToString([]byte(device))) {
			t.Errorf("%s: the error names the token", device)
		}
	}
}

// A token is used for 40 minutes, then made again; one Apple calls stale is made again at
// once.
func TestTokenLife(t *testing.T) {
	key := newKey(t)
	apple := newFakeApple(t, true)
	at := time.Unix(1794000000, 0)
	c := apple.client(key, func() time.Time { return at })
	bearer := func() int64 {
		t.Helper()
		b, _ := strings.CutPrefix(apple.last(t).header.Get("Authorization"), "bearer ")
		return checkToken(t, b, key)
	}
	c.Send(context.Background(), note("phone"))
	first := bearer()
	at = at.Add(39 * time.Minute)
	c.Send(context.Background(), note("phone"))
	if bearer() != first {
		t.Fatal("a new token within 40 minutes")
	}
	at = at.Add(time.Minute)
	c.Send(context.Background(), note("phone"))
	if bearer() != at.Unix() {
		t.Fatal("the same token after 40 minutes")
	}
	at = at.Add(time.Minute)
	c.Send(context.Background(), note("stale"))
	c.Send(context.Background(), note("phone"))
	if bearer() != at.Unix() {
		t.Fatal("the stale token sent again")
	}
}

// Apple speaks HTTP/2 only, and so does the client: a host without it gets no request.
func TestHTTP2Only(t *testing.T) {
	apple := newFakeApple(t, false)
	err := apple.client(newKey(t), nil).Send(context.Background(), note("phone"))
	if err == nil || len(apple.requests) != 0 {
		t.Fatalf("sent over HTTP/1.1: %v", err)
	}
	if strings.Contains(err.Error(), hex.EncodeToString([]byte("phone"))) || strings.Contains(err.Error(), apple.URL) {
		t.Fatalf("the error names the request: %v", err)
	}
}

// A host that is gone, or doesn't answer in time, gives an error without the token.
func TestUnreachable(t *testing.T) {
	apple := newFakeApple(t, true)
	c := apple.client(newKey(t), nil)
	apple.Close()
	err := c.Send(context.Background(), note("phone"))
	if err == nil || strings.Contains(err.Error(), hex.EncodeToString([]byte("phone"))) {
		t.Fatalf("a closed host: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := newFakeApple(t, true).client(newKey(t), nil).Send(ctx, note("phone")); err == nil ||
		strings.Contains(err.Error(), "/3/device/") {
		t.Fatalf("a cancelled request: %v", err)
	}
}

// What can't be sent isn't.
func TestLimits(t *testing.T) {
	apple := newFakeApple(t, true)
	c := apple.client(newKey(t), nil)
	for name, n := range map[string]Notification{
		"no device":      {Payload: []byte("{}")},
		"a long device":  {Device: make([]byte, MaxDevice+1), Payload: []byte("{}")},
		"no payload":     {Device: []byte("phone")},
		"a long payload": {Device: []byte("phone"), Payload: make([]byte, MaxPayload+1)},
	} {
		if err := c.Send(context.Background(), n); err == nil {
			t.Errorf("%s: sent", name)
		}
	}
	if len(apple.requests) != 0 {
		t.Error("a request went out")
	}
}

// ParseKey takes only P-256 keys, whatever it is given.
func FuzzParseKey(f *testing.F) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n"))
	f.Fuzz(func(t *testing.T, file []byte) {
		if k, err := ParseKey(file); err == nil && (k == nil || k.Curve != elliptic.P256()) {
			t.Fatal("accepted a key that isn't P-256")
		}
	})
}
