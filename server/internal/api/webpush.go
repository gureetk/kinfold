// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gureetk/kinfold/server/internal/wire"
)

// Web Push (API.md §12): the sealed push goes to the subscription's endpoint as an RFC 8030
// message, encrypted for the subscription with RFC 8291 and signed with the server's VAPID
// key (RFC 8292). Both are assembled from the standard library's primitives; RFC 8291's own
// example checks the encryption byte for byte.

const (
	eceRecordSize = 4096 // one record holds the whole push (RFC 8291 §4)
	vapidLife     = 12 * 60 * 60
	webPushTTL    = "3600" // the same for every push, so a distributor can't tell them apart
	dialTimeout   = 3 * time.Second
)

// ece encrypts a push message for a subscription (RFC 8291 §3.4) as a single aes128gcm
// record (RFC 8188): salt ‖ rs ‖ idlen ‖ keyid ‖ ciphertext, where keyid is the server's
// one-time public key.
func ece(plaintext, uaPublic, authSecret, salt []byte, as *ecdh.PrivateKey) ([]byte, error) {
	ua, err := ecdh.P256().NewPublicKey(uaPublic)
	if err != nil {
		return nil, err
	}
	if len(authSecret) != 16 || len(salt) != 16 || len(plaintext)+1+16 > eceRecordSize {
		return nil, errors.New("ece: bad sizes")
	}
	secret, err := as.ECDH(ua)
	if err != nil {
		return nil, err
	}
	asPublic := as.PublicKey().Bytes()
	keyInfo := "WebPush: info\x00" + string(uaPublic) + string(asPublic)
	ikm, err := hkdf.Key(sha256.New, secret, authSecret, keyInfo, 32)
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
	header := wire.Concat(salt, wire.U32(eceRecordSize), []byte{byte(len(asPublic))}, asPublic)
	record := append(append([]byte(nil), plaintext...), 0x02) // the last record's delimiter; no padding
	return gcm.Seal(header, nonce, record, nil), nil
}

// vapid is the Authorization header of RFC 8292 for a push to an endpoint: a JWT signed
// with ES256 whose audience is the endpoint's origin, which expires in 12 hours and names
// the server's URL as its contact, and the server's VAPID public key.
func (s *Server) vapid(endpoint *url.URL, now uint64) (string, error) {
	key := s.cfg.Push.VAPID
	claims, err := json.Marshal(map[string]any{"aud": origin(endpoint), "exp": now/1000 + vapidLife, "sub": s.cfg.URL})
	if err != nil {
		return "", err
	}
	signing := wire.EncodeB64u([]byte(`{"typ":"JWT","alg":"ES256"}`)) + "." + wire.EncodeB64u(claims)
	digest := sha256.Sum256([]byte(signing))
	r, sv, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := append(r.FillBytes(make([]byte, 32)), sv.FillBytes(make([]byte, 32))...)
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		return "", err
	}
	return "vapid t=" + signing + "." + wire.EncodeB64u(sig) + ", k=" + wire.EncodeB64u(pub), nil
}

// origin is an https URL's origin as RFC 6454 §6.1 writes it: the host in lower case, and
// the port only if it isn't 443.
func origin(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" && p != "443" {
		host += ":" + p
	}
	return "https://" + host
}

// vapidKey is the VAPID public key for the discovery document, or "" without one.
func (s *Server) vapidKey() string {
	if s.cfg.Push.VAPID == nil {
		return ""
	}
	pub, err := s.cfg.Push.VAPID.PublicKey.Bytes()
	if err != nil {
		return ""
	}
	return wire.EncodeB64u(pub)
}

// webPushClient talks to push hosts. Each send resolves the host and checks its addresses
// again, and connects only to an address it has just checked (API.md §12), so it keeps no
// connection for the next. It uses no proxy, follows no redirect and gives up after 10
// seconds, trying each address for 3.
func (s *Server) webPushClient() *http.Client {
	dialer := &net.Dialer{Timeout: dialTimeout}
	return &http.Client{
		Timeout:       pushTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				p, err := strconv.ParseUint(port, 10, 16)
				if err != nil {
					return nil, err
				}
				addrs, err := s.pushAddrs(ctx, host)
				if err != nil {
					return nil, err
				}
				var errs []error
				for _, a := range addrs {
					c, err := dialer.DialContext(ctx, network, netip.AddrPortFrom(a, uint16(p)).String())
					if err == nil {
						return c, nil
					}
					errs = append(errs, err)
				}
				return nil, errors.Join(errs...)
			},
			TLSClientConfig:       &tls.Config{RootCAs: s.cfg.Push.RootCAs, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   pushTimeout,
			ResponseHeaderTimeout: pushTimeout,
		},
	}
}

// sendWebPush sends one sealed push to a subscription.
func (s *Server) sendWebPush(ctx context.Context, j *pushJob) error {
	if s.cfg.Push.VAPID == nil {
		return errors.New("this server has no VAPID key")
	}
	u, err := url.Parse(j.reg.Endpoint)
	if err != nil {
		return errors.New("the endpoint doesn't parse") // the error would quote it
	}
	as, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	body, err := ece(j.sealed, j.reg.P256dh, j.reg.Auth, salt, as)
	if err != nil {
		return err
	}
	auth, err := s.vapid(u, j.sentAt)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, j.reg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("the endpoint doesn't parse")
	}
	h := req.Header
	h.Set("TTL", webPushTTL)
	h.Set("Urgency", "high")
	h.Set("Content-Encoding", "aes128gcm")
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Authorization", auth)
	resp, err := s.webPush.Do(req)
	if err != nil {
		return pushFailure(err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) // the body is ignored
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusCreated, http.StatusAccepted, http.StatusOK:
		return nil
	case http.StatusNotFound, http.StatusGone:
		return errDeadPush
	}
	return fmt.Errorf("the push host answered %d", resp.StatusCode)
}

// pushFailure says why a push host couldn't be reached, for the log. The error itself would
// carry the device's endpoint, which is its push address, and the host's IP address, which
// for a distributor at home is the family's.
func pushFailure(err error) error {
	var rule addrError
	var cert *tls.CertificateVerificationError
	var ne net.Error
	switch {
	case errors.As(err, &rule):
		return rule
	case errors.As(err, &cert):
		return errors.New("the push host's certificate doesn't verify")
	case errors.As(err, &ne) && ne.Timeout():
		return errors.New("the push host didn't answer in time")
	}
	return errors.New("the push host can't be reached")
}
