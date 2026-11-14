// SPDX-License-Identifier: AGPL-3.0-or-later

// Package watch checks silence-watch grants (PROTOCOL.md §14.1): the signed consent a
// watched phone gives before a server will tell a watcher that it has gone quiet.
package watch

import (
	"bytes"

	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/kcrypto"
	"github.com/gureetk/kinfold/server/internal/memberlog"
	"github.com/gureetk/kinfold/server/internal/wire"
)

const (
	GrantLen    = 131
	tbsLen      = 67
	MinAfterMin = 15
	MaxAfterMin = 1440
	MaxLifeMS   = 35 * identity.DayMS // the longest a grant lasts after its issued_at
	SkewMS      = 600_000             // how far issued_at may run ahead of the server's clock
)

// Grant is a parsed WatchGrant.
type Grant struct {
	Raw            []byte
	Version        uint8
	CircleID       []byte
	WatchedDevice  []byte
	WatcherAccount []byte
	AfterMin       uint16
	IssuedAt       uint64 // the watched device's trusted time when it signed
	NotAfter       uint64
	Sig            []byte
}

// Parse reads a WatchGrant: exactly 131 bytes.
func Parse(raw []byte) (*Grant, bool) {
	r := wire.NewReader(raw)
	g := &Grant{Raw: raw, Version: r.U8(), CircleID: r.Take(16), WatchedDevice: r.Take(16), WatcherAccount: r.Take(16),
		AfterMin: r.U16(), IssuedAt: r.U64(), NotAfter: r.U64(), Sig: r.Take(64)}
	return g, r.Done()
}

// Valid reports whether a grant is valid at time now against the circle's public state
// (§14.1): version 0, this circle, an active phone or tablet as the watched device, a
// current member as the watcher, after_min from 15 to 1,440, issued_at at most 10 minutes
// ahead of now, now < not_after, issued_at < not_after ≤ issued_at + 35 days, and a
// signature under the watched device's signing key. The device chooses both times, so every
// limit is a difference, never a sum (PROTOCOL.md Appendix C).
func Valid(s *memberlog.State, raw []byte, now uint64) (*Grant, bool) {
	g, ok := Parse(raw)
	if !ok || g.Version != identity.Version || s.CircleID == nil || !bytes.Equal(g.CircleID, s.CircleID) {
		return nil, false
	}
	d := s.Device(g.WatchedDevice)
	if d == nil || !identity.PhoneOrTablet(d.Kind) || s.Member(g.WatcherAccount) == nil {
		return nil, false
	}
	if g.AfterMin < MinAfterMin || g.AfterMin > MaxAfterMin {
		return nil, false
	}
	if (g.IssuedAt > now && g.IssuedAt-now > SkewMS) || g.NotAfter <= now ||
		g.NotAfter <= g.IssuedAt || g.NotAfter-g.IssuedAt > MaxLifeMS {
		return nil, false
	}
	if !kcrypto.Verify(d.DSK, "watch-grant", raw[:tbsLen], g.Sig) {
		return nil, false
	}
	return g, true
}
