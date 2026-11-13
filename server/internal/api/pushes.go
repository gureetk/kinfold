// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/push"
	"github.com/gureetk/kinfold/server/internal/store"
)

// Push (API.md §12, PROTOCOL.md §14.2–§14.4): how the server reaches a device that has no
// stream open. What it sends is always the sealed, signed, fixed-size Push.

// PushConfig is how the server reaches push hosts.
type PushConfig struct {
	// Relay is the iOS relay's base URL (API.md §14). Without one, relay registrations are
	// refused.
	Relay string
	// Hosts are Web Push hosts the operator allows without the public-address test, such as
	// a distributor on the home network. HostsOnly refuses every other host.
	Hosts     []string
	HostsOnly bool
	// VAPID is the server's key for Web Push (RFC 8292); without one, Web Push
	// registrations are refused.
	VAPID *ecdsa.PrivateKey
	// Client talks to the relay; Resolve looks up push hosts; RootCAs, if set, are the
	// only roots Web Push hosts' certificates may chain to. Tests replace them.
	Client  *http.Client
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	RootCAs *x509.CertPool
}

const (
	maxCapability = 1 << 10
	maxEndpoint   = 1000
	pushTimeout   = 10 * time.Second
	maxSending    = 16 // pushes in flight at once; past that they are dropped
)

func (c PushConfig) withDefaults() PushConfig {
	if c.Client == nil {
		c.Client = &http.Client{Timeout: pushTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if c.Resolve == nil {
		c.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	return c
}

var deliveryNames = map[uint8]string{push.Alert: "alert", push.Background: "background", push.Location: "location"}

// ---- registration ----

// putPush is PUT /v1/push: the device's push registration, replacing any before it.
func (s *Server) putPush(q *request) error {
	var in struct {
		Kind     string `json:"kind"`
		Notify   b64    `json:"notify"`
		Locate   b64    `json:"locate"`
		Endpoint string `json:"endpoint"`
		P256dh   b64    `json:"p256dh"`
		Auth     b64    `json:"auth"`
	}
	if err := q.json(&in); err != nil {
		return err
	}
	if err := s.cfg.Store.View(func(tx store.Tx) error { return s.session(q, tx, receiving) }); err != nil {
		return err
	}
	reg := store.PushReg{Device: q.dev.ID, Kind: in.Kind}
	switch in.Kind {
	case "relay":
		if s.cfg.Push.Relay == "" {
			return &apiError{status: http.StatusForbidden, code: "forbidden", msg: "this server has no iOS relay"}
		}
		if len(in.Notify) == 0 || len(in.Notify) > maxCapability || len(in.Locate) > maxCapability {
			return badRequest("notify is a capability from the relay, and so is locate if present")
		}
		reg.Notify, reg.Locate = in.Notify, nilIfEmpty(in.Locate)
	case "webpush":
		if s.cfg.Push.VAPID == nil {
			return &apiError{status: http.StatusForbidden, code: "forbidden", msg: "this server has no Web Push key"}
		}
		if err := s.checkPushURL(q.r.Context(), in.Endpoint); err != nil {
			return badRequest(err.Error())
		}
		if _, err := ecdh.P256().NewPublicKey(in.P256dh); err != nil || len(in.Auth) != 16 {
			return badRequest("p256dh is a P-256 public key and auth 16 bytes (RFC 8291)")
		}
		reg.Endpoint, reg.P256dh, reg.Auth = in.Endpoint, in.P256dh, in.Auth
	case "apns":
		return &apiError{status: http.StatusForbidden, code: "forbidden", msg: "this server holds no Apple key"}
	default:
		return badRequest("kind is relay, webpush or apns")
	}
	if err := s.cfg.Store.Update(func(tx store.Tx) error { return tx.PutPush(reg) }); err != nil {
		return err
	}
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// deletePush is DELETE /v1/push.
func (s *Server) deletePush(q *request) error {
	err := s.cfg.Store.Update(func(tx store.Tx) error {
		if err := s.session(q, tx, receiving); err != nil {
			return err
		}
		return tx.DeletePush(q.dev.ID)
	})
	if err != nil {
		return err
	}
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

// ---- push addresses (API.md §12) ----

// checkPushURL checks a Web Push endpoint: https, at most 1,000 bytes, and a host that is
// on the operator's list or resolves to public addresses only.
func (s *Server) checkPushURL(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > maxEndpoint || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("the endpoint is an https URL of at most 1,000 bytes")
	}
	_, err = s.pushAddrs(ctx, u.Hostname())
	return err
}

// An addrError is a push address the rules refuse. Its text names no host or address, so it
// may be logged.
type addrError string

func (e addrError) Error() string { return string(e) }

// pushAddrs resolves a push host to the addresses the server may connect to: all of them
// for a host on the operator's list, otherwise only if every one is public.
func (s *Server) pushAddrs(ctx context.Context, host string) ([]netip.Addr, error) {
	allowed := slices.ContainsFunc(s.cfg.Push.Hosts, func(h string) bool { return strings.EqualFold(h, host) })
	if !allowed && s.cfg.Push.HostsOnly {
		return nil, addrError("this server sends pushes only to the hosts its operator lists")
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		rctx, cancel := context.WithTimeout(ctx, pushTimeout)
		defer cancel()
		if addrs, err = s.cfg.Push.Resolve(rctx, host); err != nil || len(addrs) == 0 {
			return nil, addrError("the push host doesn't resolve")
		}
	}
	if allowed || !slices.ContainsFunc(addrs, func(a netip.Addr) bool { return !publicAddr(a) }) {
		return addrs, nil
	}
	return nil, addrError("the push host resolves to an address that isn't public")
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// publicAddr says whether the server may send to an address: not loopback, private, carrier-
// grade NAT, link-local, unique-local, multicast or unspecified, in any form.
func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	switch {
	case !a.IsValid(), a.IsUnspecified(), a.IsLoopback(), a.IsPrivate(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(),
		a.IsInterfaceLocalMulticast(), a.IsMulticast(), cgnat.Contains(a):
		return false
	}
	return true
}

// ---- sending ----

// pushJob is one push on its way to one device.
type pushJob struct {
	reg      store.PushReg
	sealed   []byte
	sentAt   uint64
	delivery uint8
}

// preparePush builds, signs and seals a push for a device without a stream that has a
// registration and a current encryption key; nil otherwise. It runs inside the transaction
// that warrants it. A location delivery falls back to fallback where the registration can't
// take one.
func (s *Server) preparePush(tx store.Tx, device []byte, ptype uint8, body []byte, delivery, fallback uint8, now uint64) (*pushJob, error) {
	if s.streams.of(device) != nil {
		return nil, nil
	}
	reg, err := tx.Push(device)
	if errors.Is(err, store.ErrNotFound) || (err == nil && reg.Kind == "dropped") {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if (reg.Kind == "relay" && s.cfg.Push.Relay == "") || (reg.Kind == "webpush" && s.cfg.Push.VAPID == nil) {
		return nil, nil // the operator has switched that route off since
	}
	dev, err := tx.Device(device)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	b, ok, err := currentBundle(tx, dev, now)
	if err != nil || !ok {
		return nil, err
	}
	if delivery == push.Location && !(reg.Kind == "relay" && reg.Locate != nil) {
		delivery = fallback
	}
	p, err := push.Build(s.cfg.Key, device, ptype, now, body)
	if err != nil {
		return nil, err
	}
	sealed, err := push.Seal(p, device, b.DEK)
	if err != nil {
		return nil, err
	}
	return &pushJob{reg: reg, sealed: sealed, sentAt: now, delivery: delivery}, nil
}

// currentBundle is the device's newest key bundle current at now: the one it registered
// with, or a later one from the log of a circle it is in.
func currentBundle(tx store.Tx, dev store.Device, now uint64) (identity.Bundle, bool, error) {
	var best identity.Bundle
	found := false
	consider := func(b identity.Bundle) {
		if b.Raw != nil && b.CurrentAt(now) && (!found || b.NotBefore > best.NotBefore) {
			best, found = b, true
		}
	}
	if b, ok := identity.ParseBundle(dev.Bundle); ok {
		consider(b)
	}
	circles, err := tx.CirclesOf(dev.Account)
	if err != nil {
		return best, false, err
	}
	for _, c := range circles {
		if d := c.State.Device(dev.ID); d != nil {
			consider(d.Bundle)
		}
	}
	return best, found, nil
}

// send delivers pushes in the background, each unless its device has opened a stream
// since. Past maxSending in flight, a push is dropped: it only says "fetch".
func (s *Server) send(jobs []*pushJob) {
	for _, j := range jobs {
		if j == nil || s.streams.of(j.reg.Device) != nil {
			continue
		}
		select {
		case s.sending <- struct{}{}:
			go func() {
				defer func() { <-s.sending }()
				s.deliver(j)
			}()
		default:
			slog.Warn("too many pushes in flight; one was dropped")
		}
	}
}

// FlushPushes waits, up to the timeout, until no push is in flight: at shutdown, so that
// the pushes started go out.
func (s *Server) FlushPushes(timeout time.Duration) bool {
	deadline := time.After(timeout)
	for taken := 0; taken < cap(s.sending); taken++ {
		select {
		case s.sending <- struct{}{}:
			defer func() { <-s.sending }()
		case <-deadline:
			return false
		}
	}
	return true
}

var errDeadPush = errors.New("the push host says the registration is dead")

func (s *Server) deliver(j *pushJob) {
	ctx, cancel := context.WithTimeout(context.Background(), pushTimeout)
	defer cancel()
	var err error
	switch j.reg.Kind {
	case "relay":
		err = s.sendRelay(ctx, j)
	case "webpush":
		err = s.sendWebPush(ctx, j)
	}
	switch {
	case errors.Is(err, errDeadPush):
		s.dropPush(j.reg)
	case err != nil:
		slog.Warn("a push failed", "kind", j.reg.Kind, "err", err) // no device, address or content
	}
}

// sendRelay hands a push to the iOS relay (API.md §14), signed with the server key.
func (s *Server) sendRelay(ctx context.Context, j *pushJob) error {
	capability := j.reg.Notify
	if j.delivery == push.Location {
		capability = j.reg.Locate
	}
	body, err := json.Marshal(map[string]any{"capability": b64(capability), "sealed": b64(j.sealed), "sent_at": j.sentAt,
		"delivery": deliveryNames[j.delivery], "sig": b64(push.RelaySig(s.cfg.Key, capability, j.sealed, j.sentAt, j.delivery))})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.Push.Relay+"/v1/push", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.cfg.Push.Client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusAccepted, http.StatusOK:
		return nil
	case http.StatusGone, http.StatusNotFound:
		return errDeadPush
	}
	return fmt.Errorf("the relay answered %s", resp.Status)
}

// dropPush ends a registration the push host has called dead. The device hears of it the
// next time it opens a stream, or at once if it has one open.
func (s *Server) dropPush(reg store.PushReg) {
	err := s.cfg.Store.Update(func(tx store.Tx) error {
		cur, err := tx.Push(reg.Device)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		if cur.Kind != reg.Kind || !bytes.Equal(cur.Notify, reg.Notify) || cur.Endpoint != reg.Endpoint {
			return nil // registered again since
		}
		return tx.PutPush(store.PushReg{Device: reg.Device, Kind: "dropped"})
	})
	if err != nil {
		slog.Warn("dropping a dead push registration failed", "err", err)
		return
	}
	s.tellDropped(reg.Device)
}

// tellDropped sends push_dropped to the device's stream, if it has one, and forgets that
// it has to.
func (s *Server) tellDropped(device []byte) {
	st := s.streams.of(device)
	if st == nil {
		return
	}
	dropped := false
	err := s.cfg.Store.Update(func(tx store.Tx) error {
		reg, err := tx.Push(device)
		if errors.Is(err, store.ErrNotFound) || (err == nil && reg.Kind != "dropped") {
			return nil
		} else if err != nil {
			return err
		}
		dropped = true
		return tx.DeletePush(device)
	})
	if err == nil && dropped {
		st.event(map[string]any{"type": "push_dropped"})
	}
}
