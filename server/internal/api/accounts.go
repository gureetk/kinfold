// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// ---- discovery and health (API.md §4) ----

// serverInfo is the signed identity document, signed again once a day.
func (s *Server) serverInfo(now uint64) []byte {
	s.infoMu.Lock()
	defer s.infoMu.Unlock()
	if s.info == nil || now >= s.infoAt+day || now < s.infoAt {
		s.info, s.infoAt = identity.MakeServerInfo(s.cfg.Key, s.cfg.URL, now, now+InfoLife), now
	}
	return s.info
}

func (s *Server) discovery(q *request) error {
	var st store.Settings
	if err := s.cfg.Store.View(func(tx store.Tx) (err error) { st, err = tx.Settings(); return }); err != nil {
		return err
	}
	features := []string{"stream_post"}
	out := map[string]any{
		"server_info": b64(s.serverInfo(q.now)),
		"api":         map[string]int{"min": APIMin, "max": APIMax},
		"repair":      repairing(st, q.now),
	}
	if s.cfg.Tiles != nil && len(s.cfg.Tiles.Regions()) > 0 {
		features = append(features, "tiles")
	}
	if s.cfg.Search != "" {
		features = append(features, "search")
	}
	if st.WebDevices {
		features = append(features, "web_devices")
	}
	if st.WebTileRanges {
		features = append(features, "web_tile_ranges")
	}
	if st.MemberTokens {
		features = append(features, "member_tokens")
	}
	if s.cfg.Push.Relay != "" {
		features = append(features, "relay")
		out["relay"] = s.cfg.Push.Relay
	}
	if k := s.vapidKey(); k != "" {
		features = append(features, "webpush")
		out["vapid_key"] = k
	}
	out["features"] = features
	writeJSON(q.w, http.StatusOK, out)
	return nil
}

func (s *Server) healthz(q *request) error {
	if !s.cfg.Clock.Synced() {
		return &apiError{status: http.StatusServiceUnavailable, code: "unavailable", msg: "the server's clock isn't synchronized"}
	}
	writeJSON(q.w, http.StatusOK, map[string]bool{"ok": true})
	return nil
}

func repairing(st store.Settings, now uint64) bool { return now < st.RepairUntil }

func (s *Server) status(q *request) error {
	var acc store.Account
	var st store.Settings
	err := s.cfg.Store.View(func(tx store.Tx) error {
		if err := s.session(q, tx, phone); err != nil {
			return err
		}
		var err error
		if acc, err = tx.Account(q.dev.Account); err != nil {
			return err
		}
		st, err = tx.Settings()
		return err
	})
	if err != nil {
		return err
	}
	if !acc.Operator {
		return errForbidden
	}
	out := map[string]any{"uptime_ms": q.now - s.start, "clock_synced": s.cfg.Clock.Synced(), "repair": repairing(st, q.now),
		"free_disk": nil, "last_backup_at": nil}
	if free, ok := diskFree(s.cfg.DataDir); ok {
		out["free_disk"] = free
	}
	if st.LastBackupAt != 0 {
		out["last_backup_at"] = st.LastBackupAt
	}
	writeJSON(q.w, http.StatusOK, out)
	return nil
}

// Health is what the operator's status shows of the running server (API.md §16).
type Health struct {
	UptimeMS       uint64  `json:"uptime_ms"`
	ClockSynced    bool    `json:"clock_synced"`
	FreeDisk       *uint64 `json:"free_disk"` // nil if unknown
	Streams        int     `json:"streams"`
	PushesInFlight int     `json:"pushes_in_flight"`
	LinkMailboxes  int     `json:"link_mailboxes"`
	Relay          *bool   `json:"relay_reachable"` // nil without a relay
}

// Health reports the server's state. With a relay, it asks whether the relay answers, which
// takes up to 5 seconds.
func (s *Server) Health(ctx context.Context) Health {
	h := Health{UptimeMS: s.cfg.Clock.Now() - s.start, ClockSynced: s.cfg.Clock.Synced(), Streams: len(s.streams.all()),
		PushesInFlight: len(s.sending), LinkMailboxes: s.links.count()}
	if free, ok := diskFree(s.cfg.DataDir); ok {
		h.FreeDisk = &free
	}
	if s.cfg.Push.Relay != "" {
		ok := s.relayAnswers(ctx)
		h.Relay = &ok
	}
	return h
}

// relayAnswers says whether the relay answers HTTPS at all: any status will do.
func (s *Server) relayAnswers(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, s.cfg.Push.Relay+"/", nil)
	if err != nil {
		return false
	}
	resp, err := s.cfg.Push.Client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// ---- accounts and devices (API.md §5) ----

func alreadyRegistered() *apiError {
	return &apiError{status: http.StatusConflict, code: "already_registered", msg: "already registered"}
}

// register is POST /v1/accounts: frames DeviceCert, identity chain, KeyBundle, token.
func (s *Server) register(q *request) error {
	b, err := q.body(maxRegister)
	if err != nil {
		return err
	}
	fs, err := wire.Frames(b, 4, maxRegister)
	if err != nil || len(fs) != 4 {
		return badRequest("send four frames: certificate, identity chain, key bundle, registration token")
	}
	cert, ok := identity.ParseCert(fs[0])
	links, chainOK := identity.ParseChain(fs[1])
	switch {
	case !ok || !chainOK:
		return refused("malformed", nil)
	case !cert.WellFormed() || !identity.ChainProves(cert, links):
		return refused("bad_cert", nil)
	case !identity.PhoneOrTablet(cert.Kind):
		return refused("kind_not_allowed", nil)
	}
	bu, ok := identity.ParseBundle(fs[2])
	if !ok || !bu.ValidFor(cert.DSK, cert.AccountID) || !bu.CurrentAt(q.now) {
		return refused("bad_bundle", nil)
	}
	err = s.cfg.Store.Update(func(tx store.Tx) error {
		tok, err := tx.Token(hashToken(fs[3]))
		if err != nil || tok.Spent || q.now >= tok.ExpiresAt {
			return &apiError{status: http.StatusForbidden, code: "bad_token", msg: "unknown, spent or expired registration token"}
		}
		if _, err := tx.Account(cert.AccountID); err == nil {
			return alreadyRegistered()
		}
		if _, err := tx.Device(cert.DeviceID()); err == nil {
			return alreadyRegistered()
		}
		tok.Spent = true
		if err := tx.PutToken(tok); err != nil {
			return err
		}
		if err := tx.PutAccount(store.Account{ID: cert.AccountID, IK: cert.IK, Chain: fs[1], CreatedAt: q.now}); err != nil {
			return err
		}
		return tx.PutDevice(store.Device{ID: cert.DeviceID(), Account: cert.AccountID, Kind: cert.Kind, DSK: cert.DSK,
			Cert: fs[0], Bundle: fs[2], CreatedAt: q.now})
	})
	if err != nil {
		return err
	}
	writeJSON(q.w, http.StatusCreated, map[string]any{"account_id": b64(cert.AccountID), "device_id": b64(cert.DeviceID())})
	return nil
}

// deleteAccount is DELETE /v1/accounts/me.
func (s *Server) deleteAccount(q *request) error {
	err := s.update(q, func(tx store.Tx) error {
		if err := s.session(q, tx, phone); err != nil {
			return err
		}
		return s.forgetAccount(q, tx, q.dev.Account)
	})
	if err != nil {
		return err
	}
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

// ErrStillMember refuses to delete an account that is in a circle (API.md §5).
var ErrStillMember error = &apiError{status: http.StatusConflict, code: "still_member", msg: "leave every circle first"}

// forgetAccount deletes an account that is in no circle, with its devices.
func (s *Server) forgetAccount(q *request, tx store.Tx, account []byte) error {
	circles, err := tx.CirclesOf(account)
	if err != nil {
		return err
	}
	if len(circles) > 0 {
		return ErrStillMember
	}
	devs, err := tx.DevicesOf(account)
	if err != nil {
		return err
	}
	for _, d := range devs {
		if err := s.forgetDevice(q, tx, d.ID); err != nil {
			return err
		}
	}
	return tx.DeleteAccount(account)
}

// RemoveDevice is the operator's removal of a device (API.md §16). Its sessions, push
// registration and stream end at once; the circles' logs don't change. It is
// store.ErrNotFound for a device the server doesn't know.
func (s *Server) RemoveDevice(id []byte) error {
	q := &request{now: s.cfg.Clock.Now()}
	return s.update(q, func(tx store.Tx) error {
		if _, err := tx.Device(id); err != nil {
			return err
		}
		return s.forgetDevice(q, tx, id)
	})
}

// RemoveAccount is the operator's removal of an account, refused with ErrStillMember while
// it is in a circle. Its devices go as RemoveDevice removes them.
func (s *Server) RemoveAccount(id []byte) error {
	q := &request{now: s.cfg.Clock.Now()}
	return s.update(q, func(tx store.Tx) error {
		if _, err := tx.Account(id); err != nil {
			return err
		}
		return s.forgetAccount(q, tx, id)
	})
}

// forgetDevice deregisters a device and ends its sessions, and its stream with them.
func (s *Server) forgetDevice(q *request, tx store.Tx, id []byte) error {
	if err := tx.DeleteSessionsOf(id); err != nil {
		return err
	}
	if err := tx.DeletePush(id); err != nil {
		return err
	}
	q.afterCommit(func() { s.endStream(id, nil) })
	return tx.DeleteDevice(id)
}

// rotateIdentity is POST /v1/accounts/me/identity: an IdentityLink.
func (s *Server) rotateIdentity(q *request) error {
	link, err := q.body(maxIdentity)
	if err != nil {
		return err
	}
	err = s.cfg.Store.Update(func(tx store.Tx) error {
		if err := s.session(q, tx, phone); err != nil {
			return err
		}
		acc, err := tx.Account(q.dev.Account)
		if err != nil {
			return err
		}
		if len(link) != identity.LinkLen || !bytes.Equal(link[:32], acc.IK) || bytes.Equal(link[32:64], acc.IK) ||
			!identity.LinkOK(acc.ID, link) || len(acc.Chain)/identity.LinkLen >= identity.MaxLinks {
			return refused("bad_rotation", nil)
		}
		acc.IK = append([]byte(nil), link[32:64]...)
		acc.Chain = wire.Concat(acc.Chain, link)
		return tx.PutAccount(acc)
	})
	if err != nil {
		return err
	}
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) listDevices(q *request) error {
	var devs []store.Device
	err := s.cfg.Store.View(func(tx store.Tx) error {
		if err := s.session(q, tx, anyDevice); err != nil {
			return err
		}
		var err error
		devs, err = tx.DevicesOf(q.dev.Account)
		return err
	})
	if err != nil {
		return err
	}
	out := []map[string]any{}
	for _, d := range devs {
		out = append(out, map[string]any{"device_id": b64(d.ID), "kind": d.Kind, "created_at": d.CreatedAt, "last_seen_at": d.LastSeenAt})
	}
	writeJSON(q.w, http.StatusOK, out)
	return nil
}

// addDevice is POST /v1/devices: frames DeviceCert and KeyBundle (none for a recovery device).
func (s *Server) addDevice(q *request) error {
	b, err := q.body(maxDeviceBody)
	if err != nil {
		return err
	}
	fs, err := wire.Frames(b, 2, maxDeviceBody)
	if err != nil || len(fs) == 0 {
		return badRequest("send the certificate, then the key bundle")
	}
	cert, ok := identity.ParseCert(fs[0])
	if !ok {
		return refused("malformed", nil)
	}
	if !cert.WellFormed() {
		return refused("bad_cert", nil)
	}
	if (cert.Kind == identity.Recovery) != (len(fs) == 1) {
		return badRequest("a recovery device has no key bundle; every other device has one")
	}
	err = s.cfg.Store.Update(func(tx store.Tx) error {
		if err := s.session(q, tx, phoneOrKit); err != nil {
			return err
		}
		acc, err := tx.Account(q.dev.Account)
		if err != nil {
			return err
		}
		if !bytes.Equal(cert.AccountID, acc.ID) || !bytes.Equal(cert.IK, acc.IK) {
			return refused("wrong_account", nil) // the certificate must carry the current identity key
		}
		var bundle []byte
		if cert.Kind != identity.Recovery {
			bu, ok := identity.ParseBundle(fs[1])
			if !ok || !bu.ValidFor(cert.DSK, cert.AccountID) || !bu.CurrentAt(q.now) {
				return refused("bad_bundle", nil)
			}
			bundle = fs[1]
		}
		st, err := tx.Settings()
		if err != nil {
			return err
		}
		if (cert.Kind == identity.Web || cert.Kind == identity.HomeAssistant) && !st.WebDevices {
			return errForbidden
		}
		devs, err := tx.DevicesOf(acc.ID)
		if err != nil {
			return err
		}
		recovery := 0
		for _, d := range devs {
			if d.Kind == identity.Recovery {
				recovery++
			}
		}
		if _, err := tx.Device(cert.DeviceID()); err == nil {
			return alreadyRegistered()
		}
		if len(devs) >= 8 || (cert.Kind == identity.Recovery && recovery > 0) {
			return refused("too_many_devices", nil)
		}
		return tx.PutDevice(store.Device{ID: cert.DeviceID(), Account: acc.ID, Kind: cert.Kind, DSK: cert.DSK,
			Cert: fs[0], Bundle: bundle, CreatedAt: q.now})
	})
	if err != nil {
		return err
	}
	writeJSON(q.w, http.StatusCreated, map[string]any{"device_id": b64(cert.DeviceID())})
	return nil
}

// deleteDevice is DELETE /v1/devices/{device_id}.
func (s *Server) deleteDevice(q *request) error {
	id, err := q.pathID("device_id")
	if err != nil {
		return err
	}
	err = s.update(q, func(tx store.Tx) error {
		if err := s.session(q, tx, anyDevice); err != nil {
			return err
		}
		self := bytes.Equal(id, q.dev.ID)
		if !self && !allowed(q.dev.Kind, phoneOrKit) {
			return errForbidden
		}
		d, err := tx.Device(id)
		if err != nil || !bytes.Equal(d.Account, q.dev.Account) {
			return errNotFound
		}
		return s.forgetDevice(q, tx, id)
	})
	if err != nil {
		return err
	}
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) listCircles(q *request) error {
	var circles []store.Circle
	err := s.cfg.Store.View(func(tx store.Tx) error {
		if err := s.session(q, tx, anyDevice); err != nil {
			return err
		}
		var err error
		circles, err = tx.CirclesOf(q.dev.Account)
		return err
	})
	if err != nil {
		return err
	}
	out := []map[string]any{}
	for _, c := range circles {
		out = append(out, map[string]any{"circle_id": b64(c.ID), "seq": c.State.Seq, "head": b64(c.State.Head)})
	}
	writeJSON(q.w, http.StatusOK, out)
	return nil
}

// ---- login (PROTOCOL.md §13.2, API.md §5) ----

func clientAddress(r *http.Request) string {
	host := r.RemoteAddr
	if i := bytes.LastIndexByte([]byte(host), ':'); i >= 0 {
		host = host[:i]
	}
	return host
}

// challenge is POST /v1/auth/challenge. It answers the same way whether or not the server
// knows the device.
func (s *Server) challenge(q *request) error {
	var in struct {
		DeviceID b64 `json:"device_id"`
	}
	if err := q.json(&in); err != nil {
		return err
	}
	if len(in.DeviceID) != 16 {
		return badRequest("device_id must be 16 bytes")
	}
	l := s.limits()
	if ok, wait := s.limiter.allow("challenge/device/"+string(in.DeviceID), l.ChallengesPerDevice, minute, q.now); !ok {
		return rateLimited(wait)
	}
	if ok, wait := s.limiter.allow("challenge/address/"+clientAddress(q.r), l.ChallengesPerAddress, minute, q.now); !ok {
		return rateLimited(wait)
	}
	ch := s.random(32)
	exp := q.now + ChallengeLife
	if err := s.cfg.Store.Update(func(tx store.Tx) error {
		return tx.PutChallenge(store.Challenge{Challenge: ch, Device: in.DeviceID, ExpiresAt: exp})
	}); err != nil {
		return err
	}
	writeJSON(q.w, http.StatusOK, map[string]any{"challenge": b64(ch), "expires_at": exp,
		"challenge_sig": b64(identity.ChallengeSig(s.cfg.Key, ch, in.DeviceID, exp))})
	return nil
}

// login is POST /v1/auth/session. Every failure is the same 401.
func (s *Server) login(q *request) error {
	var in struct {
		DeviceID  b64 `json:"device_id"`
		Challenge b64 `json:"challenge"`
		DeviceSig b64 `json:"device_sig"`
	}
	if err := q.json(&in); err != nil {
		return err
	}
	token := s.random(32)
	exp := q.now + SessionLife
	err := s.cfg.Store.Update(func(tx store.Tx) error {
		ch, err := tx.TakeChallenge(in.Challenge)
		if errors.Is(err, store.ErrNotFound) {
			return errUnauthorized
		} else if err != nil {
			return err
		}
		d, err := tx.Device(in.DeviceID)
		if err != nil || q.now >= ch.ExpiresAt || !bytes.Equal(ch.Device, in.DeviceID) ||
			!identity.AuthOK(d.DSK, s.ServerKey(), in.Challenge, in.DeviceID, in.DeviceSig) {
			return errChallengeSpent // the challenge is used up either way
		}
		d.LastSeenAt = q.now
		if err := tx.PutDevice(d); err != nil {
			return err
		}
		return tx.PutSession(store.Session{Hash: hashToken(token), Device: d.ID, ExpiresAt: exp})
	})
	if errors.Is(err, errChallengeSpent) {
		// Spend the challenge for good: the transaction above was rolled back.
		s.cfg.Store.Update(func(tx store.Tx) error { _, err := tx.TakeChallenge(in.Challenge); return err })
		return errUnauthorized
	}
	if err != nil {
		return err
	}
	writeJSON(q.w, http.StatusOK, map[string]any{"token": b64(token), "expires_at": exp})
	return nil
}

var errChallengeSpent = errors.New("challenge failed")

func (s *Server) logout(q *request) error {
	err := s.update(q, func(tx store.Tx) error {
		if err := s.session(q, tx, anyDevice); err != nil {
			return err
		}
		q.afterCommit(func() { s.endStream(q.dev.ID, q.sess.Hash) })
		return tx.DeleteSession(q.sess.Hash)
	})
	if err != nil {
		return err
	}
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}
