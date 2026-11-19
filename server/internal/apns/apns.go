// SPDX-License-Identifier: AGPL-3.0-or-later

// Package apns sends notifications through Apple's push service with a token-based
// connection: each request goes over HTTP/2 and carries a JSON Web Token signed with an
// Apple push key (ES256), made again every 40 minutes. It knows how to ask Apple and how to
// read the answer; what a Kinfold notification holds is internal/push's.
package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Apple's push hosts.
const (
	Sandbox    = "https://api.sandbox.push.apple.com"
	Production = "https://api.push.apple.com"
)

const (
	// MaxPayload is the most a notification's JSON may hold.
	MaxPayload = 4096
	// MaxDevice is the longest device token this package sends to. Apple says not to count
	// on a size; tokens are 32 bytes today.
	MaxDevice = 256
	// tokenLife is how long a provider token is used. Apple refuses one older than an hour
	// and one renewed sooner than 20 minutes (TooManyProviderTokenUpdates).
	tokenLife = 40 * time.Minute
	timeout   = 10 * time.Second
)

// Key is an Apple push key: its 10-character ID, the 10-character ID of the team it belongs
// to, and the private key from its .p8 file.
type Key struct {
	ID, Team string
	Private  *ecdsa.PrivateKey
}

// AppleID says whether s has the form of a key ID or team ID: 10 upper-case letters and
// digits.
func AppleID(s string) bool {
	if len(s) != 10 {
		return false
	}
	for _, c := range s {
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// ParseKey reads a .p8 file as Apple hands it out: one PEM block of type PRIVATE KEY holding
// a PKCS #8 P-256 key.
func ParseKey(file []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(file)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("not a .p8 key: it holds one PEM block of type PRIVATE KEY")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("not a .p8 key: the PKCS #8 key doesn't parse")
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("not an Apple push key: it isn't a P-256 key")
	}
	return ec, nil
}

// Token is a provider token for key, issued at now: a JSON Web Token whose header names the
// algorithm and the key and whose claims name the team and the time in seconds, signed with
// the key using ES256.
func Token(key Key, now time.Time) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": key.ID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{"iss": key.Team, "iat": now.Unix()})
	if err != nil {
		return "", err
	}
	signing := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key.Private, digest[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// A Notification is one request to Apple.
type Notification struct {
	Device     []byte // the device token
	Topic      string // the app's bundle ID, with a suffix for some push types
	PushType   string // alert, background, location, …
	Priority   int    // 10, 5 or 1
	Expiration int64  // when Apple stops trying, in UNIX seconds; 0 for one try and no storage
	Payload    []byte // JSON, at most MaxPayload bytes
}

// An Error is Apple refusing a notification: the HTTP status and Apple's reason.
type Error struct {
	Status int
	Reason string // such as BadDeviceToken; "" if Apple gave none
}

func (e *Error) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("Apple answered %d", e.Status)
	}
	return fmt.Sprintf("Apple answered %d %s", e.Status, e.Reason)
}

// Dead says whether the token will never work for this app and environment again: it has
// gone (410), or it isn't a token of theirs. Apple says not to retry either.
func (e *Error) Dead() bool {
	return e.Status == http.StatusGone ||
		(e.Status == http.StatusBadRequest && (e.Reason == "BadDeviceToken" || e.Reason == "DeviceTokenNotForTopic"))
}

// A Client sends notifications to one Apple host with one key. It keeps its connections for
// later requests, as Apple asks, and is safe for concurrent use.
type Client struct {
	host string
	key  Key
	http *http.Client
	now  func() time.Time

	mu     sync.Mutex
	token  string
	madeAt time.Time
}

// NewClient returns a client for an Apple host and a key. A nil httpClient means a client
// of its own, which speaks HTTP/2 only, over TLS 1.2 or later, and a nil now the system
// clock.
func NewClient(host string, key Key, httpClient *http.Client, now func() time.Time) *Client {
	if httpClient == nil {
		httpClient = DefaultHTTP(nil)
	}
	if now == nil {
		now = time.Now
	}
	return &Client{host: host, key: key, http: httpClient, now: now}
}

// DefaultHTTP is the HTTP client NewClient uses: HTTP/2 only, TLS 1.2 or later with roots
// (the system's if nil), no redirects, and connections kept for up to an hour without use.
func DefaultHTTP(roots *x509.CertPool) *http.Client {
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			Protocols:           &protocols,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
			TLSHandshakeTimeout: timeout,
			IdleConnTimeout:     time.Hour,
		},
	}
}

// KeyID is the ID of the client's key.
func (c *Client) KeyID() string { return c.key.ID }

// bearer is the provider token to send now: the one made last, until it is tokenLife old.
func (c *Client) bearer() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if age := now.Sub(c.madeAt); c.token != "" && age >= 0 && age < tokenLife {
		return c.token, nil
	}
	t, err := Token(c.key, now)
	if err != nil {
		return "", err
	}
	c.token, c.madeAt = t, now
	return t, nil
}

// forget drops a token Apple calls stale, so the next request makes a new one.
func (c *Client) forget(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == token {
		c.token = ""
	}
}

// Send asks Apple to deliver n. It returns nil once Apple has accepted it, an *Error when
// Apple refuses it, and another error when Apple can't be asked. No error names the device
// token, which identifies a phone.
func (c *Client) Send(ctx context.Context, n Notification) error {
	if len(n.Device) == 0 || len(n.Device) > MaxDevice || len(n.Payload) == 0 || len(n.Payload) > MaxPayload {
		return errors.New("apns: a device token of 1 to 256 bytes and a payload of 1 to 4,096 bytes")
	}
	token, err := c.bearer()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.host+"/3/device/"+hex.EncodeToString(n.Device),
		bytes.NewReader(n.Payload))
	if err != nil {
		return errors.New("apns: the request can't be made")
	}
	h := req.Header
	h.Set("Authorization", "bearer "+token)
	h.Set("Apns-Push-Type", n.PushType)
	h.Set("Apns-Topic", n.Topic)
	h.Set("Apns-Priority", strconv.Itoa(n.Priority))
	h.Set("Apns-Expiration", strconv.FormatInt(n.Expiration, 10))
	resp, err := c.http.Do(req)
	if err != nil {
		return unreachable(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
		return nil
	}
	var answer struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&answer)
	if !word(answer.Reason) {
		answer.Reason = "" // only Apple's plain reason codes reach a log
	}
	if answer.Reason == "ExpiredProviderToken" {
		c.forget(token)
	}
	return &Error{Status: resp.StatusCode, Reason: answer.Reason}
}

// word says whether s is a reason code as Apple writes them: 1 to 64 ASCII letters.
func word(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// unreachable says why Apple couldn't be asked, without the request's URL, which holds the
// device token.
func unreachable(err error) error {
	var cert *tls.CertificateVerificationError
	var ne net.Error
	switch {
	case errors.As(err, &cert):
		return errors.New("apns: Apple's certificate doesn't verify")
	case errors.As(err, &ne) && ne.Timeout():
		return errors.New("apns: Apple didn't answer in time")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return errors.New("apns: gave up waiting for Apple")
	}
	return errors.New("apns: Apple can't be reached")
}
