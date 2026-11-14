// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

// RFC 8291's example (§5, Appendix A).
const (
	rfcASPrivate = "c9f58f89813e9f8e872e71f42aa64e1757c9254dcc62b72ddc010bb4043ea11c"
	rfcASPublic  = "04fe33f4ab0dea71914db55823f73b54948f41306d920732dbb9a59a53286482200e597a7b7bc260ba1c227998580992e93973002f3012a28ae8f06bbb78e5ec0f"
	rfcUAPrivate = "ab5757a70dd4a53e553a6bbf71ffefea2874ec07a6b379e3c48f895a02dc33de"
	rfcUAPublic  = "042571b2becdfde360551aaf1ed0f4cd366c11cebe555f89bcb7b186a53339173168ece2ebe018597bd30479b86e3c8f8eced577ca59187e9246990db682008b0e"
	rfcAuth      = "05305932a1c7eabe13b6cec9fda48882"
	rfcSalt      = "0c6bfaadad67958803092d454676f397"
	rfcPlaintext = "When I grow up, I want to be a watermelon"
	rfcMessage   = "0c6bfaadad67958803092d454676f397000010004104fe33f4ab0dea71914db55823f73b54948f41306d920732dbb9a59a53286482200e597a7b7bc260ba1c227998580992e93973002f3012a28ae8f06bbb78e5ec0ff297de5b429bba7153d3a4ae0caa091fd425f3b4b5414add8ab37a19c1bbb05cf5cb5b2a2e0562d558635641ec52812c6c8ff42e95ccb86be7cd"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The server's encryption makes RFC 8291's message byte for byte, and the subscriber's side
// that the other tests use opens it.
func TestECE(t *testing.T) {
	as, err := ecdh.P256().NewPrivateKey(unhex(t, rfcASPrivate))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(as.PublicKey().Bytes(), unhex(t, rfcASPublic)) {
		t.Fatal("the application server's public key")
	}
	uaPublic := unhex(t, rfcUAPublic)
	got, err := ece([]byte(rfcPlaintext), uaPublic, unhex(t, rfcAuth), unhex(t, rfcSalt), as)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, unhex(t, rfcMessage)) {
		t.Fatalf("RFC 8291's message:\n got %x\nwant %x", got, unhex(t, rfcMessage))
	}
	ua, err := ecdh.P256().NewPrivateKey(unhex(t, rfcUAPrivate))
	if err != nil || !bytes.Equal(ua.PublicKey().Bytes(), uaPublic) {
		t.Fatal("the user agent's key")
	}
	if pt, err := OpenECE(unhex(t, rfcMessage), ua, unhex(t, rfcAuth)); err != nil || string(pt) != rfcPlaintext {
		t.Fatalf("opening RFC 8291's message: %q, %v", pt, err)
	}
	// What ece refuses.
	if _, err := ece(make([]byte, eceRecordSize-16), uaPublic, make([]byte, 16), make([]byte, 16), as); err == nil {
		t.Error("a message over one record")
	}
	if _, err := ece([]byte("x"), bytes.Repeat([]byte{4}, 65), make([]byte, 16), make([]byte, 16), as); err == nil {
		t.Error("a public key off the curve")
	}
}

// OpenECE opens a Web Push message of one record as a subscriber does (RFC 8291 §3.4, RFC
// 8188 §2). It is the subscriber's side for the tests outside the package; TestECE checks it
// on RFC 8291's example.
func OpenECE(body []byte, ua *ecdh.PrivateKey, auth []byte) ([]byte, error) {
	if len(body) < 21 || len(body) < 21+int(body[20]) {
		return nil, errors.New("short header")
	}
	salt, rs, asPublic, ct := body[:16], binary.BigEndian.Uint32(body[16:20]), body[21:21+int(body[20])], body[21+int(body[20]):]
	if uint64(len(ct)) > uint64(rs) {
		return nil, errors.New("more than one record")
	}
	as, err := ecdh.P256().NewPublicKey(asPublic)
	if err != nil {
		return nil, err
	}
	secret, err := ua.ECDH(as)
	if err != nil {
		return nil, err
	}
	ikm, err := hkdf.Key(sha256.New, secret, auth, "WebPush: info\x00"+string(ua.PublicKey().Bytes())+string(asPublic), 32)
	if err != nil {
		return nil, err
	}
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, err
	}
	cek, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	end := bytes.LastIndexFunc(pt, func(r rune) bool { return r != 0 })
	if end < 0 || pt[end] != 2 { // padding: the last record's delimiter, then zeros
		return nil, errors.New("not the last record")
	}
	return pt[:end], nil
}

// The log hears why a push failed, never the device's endpoint or the host's address.
func TestPushFailure(t *testing.T) {
	tlsHost := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsHost.Close()
	hostPort := strings.TrimPrefix(tlsHost.URL, "https://")
	s := &Server{cfg: Config{Push: PushConfig{Hosts: []string{"127.0.0.1", "listed.example"},
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}}.withDefaults()}}
	c := s.webPushClient()
	_, port, _ := strings.Cut(hostPort, ":")
	for _, tc := range []struct{ endpoint, want string }{
		{"https://rebind.example:" + port + "/secret", "the push host resolves to an address that isn't public"},
		{"https://listed.example:" + port + "/secret", "the push host's certificate doesn't verify"}, // no root for it here
	} {
		_, err := c.Post(tc.endpoint, "application/octet-stream", nil)
		if err == nil || !strings.Contains(err.Error(), "secret") {
			t.Fatalf("%s: %v", tc.endpoint, err) // what the log mustn't get
		}
		if got := pushFailure(err).Error(); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.endpoint, got, tc.want)
		}
	}
	tlsHost.Close()
	_, err := c.Post("https://127.0.0.1:"+port+"/secret", "application/octet-stream", nil)
	if got := pushFailure(err).Error(); err == nil || got != "the push host can't be reached" {
		t.Errorf("a closed port: %q", got)
	}
}

// The VAPID audience is the endpoint's origin (RFC 6454 §6.1).
func TestOrigin(t *testing.T) {
	for raw, want := range map[string]string{
		"https://Push.Example/x?y":       "https://push.example",
		"https://push.example:443/x":     "https://push.example",
		"https://push.example:8443/x":    "https://push.example:8443",
		"https://[2001:DB8::1]:8443/x":   "https://[2001:db8::1]:8443",
		"https://[2001:db8::1]/x":        "https://[2001:db8::1]",
		"https://203.0.113.7:443/up?x=1": "https://203.0.113.7",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := origin(u); got != want {
			t.Errorf("%s: %s, want %s", raw, got, want)
		}
	}
}
