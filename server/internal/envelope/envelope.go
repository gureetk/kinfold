// SPDX-License-Identifier: AGPL-3.0-or-later

// Package envelope makes the checks a server runs before it stores an envelope
// (PROTOCOL.md §7.5): receive steps 1 to 10 of §7.6 with its own clock, then the
// server's own checks on wraps, time-to-live and circle coverage.
package envelope

import (
	"bytes"
	"crypto/sha256"

	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/kcrypto"
	"github.com/gureetk/kinfold/server/internal/memberlog"
	"github.com/gureetk/kinfold/server/internal/wire"
)

const (
	Circle = 1
	Direct = 2

	HeaderLen = 88
	WrapLen   = 104
	MaxWraps  = 255
	// MaxLen follows from the other limits (§16.6); a server refuses a larger upload by size.
	MaxLen = 92_232

	MaxAgeMS   = 31 * identity.DayMS // sent_at at most 31 days before the clock
	MaxAheadMS = identity.DayMS      // and at most a day after it
	MinTTL     = 60
	MaxTTL     = 2_592_000
)

// Refused is an envelope the server refuses, with its reason code (§16.5).
type Refused struct{ Reason string }

func (r *Refused) Error() string { return "envelope refused: " + r.Reason }

func refuse(reason string) error { return &Refused{Reason: reason} }

// Envelope is an envelope whose framing parsed (§7.1).
type Envelope struct {
	Raw      []byte
	Version  uint8
	Suite    uint16
	Kind     uint8
	CircleID []byte
	Sender   []byte
	Seq      uint64
	SentAt   uint64
	TTL      uint32
	LogHead  []byte
	Wraps    [][]byte // each 104 bytes; the first 16 are the recipient's device ID
	Sig      []byte
}

// Parse is step 1 of §7.6: the framing, wraps a multiple of 104 bytes, nothing left over.
func Parse(raw []byte) (*Envelope, error) {
	r := wire.NewReader(raw)
	e := &Envelope{Raw: raw, Version: r.U8(), Suite: r.U16(), Kind: r.U8(), CircleID: r.Take(16), Sender: r.Take(16),
		Seq: r.U64(), SentAt: r.U64(), TTL: r.U32(), LogHead: r.Take(32)}
	w := r.Vec32()
	r.Vec32() // ciphertext: opaque to a server
	e.Sig = r.Take(64)
	if !r.Done() || len(w)%WrapLen != 0 {
		return nil, refuse("malformed")
	}
	for i := 0; i < len(w); i += WrapLen {
		e.Wraps = append(e.Wraps, w[i:i+WrapLen])
	}
	return e, nil
}

// Heads tells where an entry hash sits in the circle's log.
type Heads interface {
	// SeqOf returns the seq of the entry with this hash, or false if the log has none.
	SeqOf(hash []byte) (int64, bool)
}

// Seen is the server's replay record: the SHA-256 of the envelope stored under each
// (sender device, seq) pair.
type Seen interface {
	Digest(sender []byte, seq uint64) ([32]byte, bool)
}

// Outcome of a check that passed.
type Outcome int

const (
	// Store: the envelope is new. The caller stores it and records its digest under
	// (sender, seq).
	Store Outcome = iota + 1
	// Duplicate: exactly these bytes are already stored. Posting is idempotent, so this
	// is a success, and nothing is stored again.
	Duplicate
)

// Check runs the server's checks of §7.5 on raw for the circle whose public state is s, at
// the server's clock now (ms). It returns the parsed envelope with Store or Duplicate, or a
// *Refused.
func Check(s *memberlog.State, heads Heads, seen Seen, raw []byte, now uint64) (*Envelope, Outcome, error) {
	e, err := Parse(raw) // step 1
	if err != nil {
		return nil, 0, err
	}
	switch {
	case e.Version != identity.Version || e.Suite != identity.Suite: // step 2
		return nil, 0, refuse("bad_version")
	case e.Kind != Circle && e.Kind != Direct: // step 3
		return nil, 0, refuse("bad_kind")
	case s.CircleID == nil || !bytes.Equal(e.CircleID, s.CircleID): // step 4
		return nil, 0, refuse("wrong_circle")
	}
	d := s.Device(e.Sender) // step 5
	if d == nil || !identity.Receiving(d.Kind) {
		return nil, 0, refuse("sender_not_active")
	}
	if !kcrypto.Verify(d.DSK, "envelope", raw[:len(raw)-64], e.Sig) { // step 6
		return nil, 0, refuse("bad_signature")
	}
	headSeq, known := heads.SeqOf(e.LogHead) // step 7
	if !known {
		return nil, 0, refuse("unknown_log_head")
	}
	// Step 8, written so that no sum can overflow: sent_at is the sender's to choose.
	if now > e.SentAt && now-e.SentAt > MaxAgeMS {
		return nil, 0, refuse("expired")
	}
	if e.SentAt > now && e.SentAt-now > MaxAheadMS {
		return nil, 0, refuse("bad_time")
	}
	if prev, ok := seen.Digest(e.Sender, e.Seq); ok { // step 9
		if prev == sha256.Sum256(raw) {
			return e, Duplicate, nil
		}
		return nil, 0, refuse("replay")
	}
	if len(e.Wraps) < 1 || len(e.Wraps) > MaxWraps { // step 10
		return nil, 0, refuse("bad_wraps")
	}
	named := make(map[string]bool, len(e.Wraps))
	for i, w := range e.Wraps {
		if i > 0 && bytes.Compare(e.Wraps[i-1][:16], w[:16]) >= 0 {
			return nil, 0, refuse("bad_wraps")
		}
		named[string(w[:16])] = true
	}

	// What only a server checks (§7.5).
	for id := range named {
		if rd := s.Device([]byte(id)); rd == nil || !identity.Receiving(rd.Kind) {
			return nil, 0, refuse("bad_wraps")
		}
	}
	if e.TTL < MinTTL || e.TTL > MaxTTL {
		return nil, 0, refuse("bad_ttl")
	}
	if e.Kind == Circle {
		if headSeq < s.RecvChanged {
			return nil, 0, refuse("stale_head")
		}
		others := s.ReceivingDevices(func(x *memberlog.Device) bool { return bytes.Equal(x.ID, e.Sender) })
		if len(others) != len(named) {
			return nil, 0, refuse("bad_wraps") // a circle envelope names every receiving device but the sender
		}
		for _, o := range others {
			if !named[string(o.ID)] {
				return nil, 0, refuse("bad_wraps")
			}
		}
	}
	return e, Store, nil
}

// Recipients lists the device IDs an envelope's wraps name, in order.
func (e *Envelope) Recipients() [][]byte {
	out := make([][]byte, len(e.Wraps))
	for i, w := range e.Wraps {
		out[i] = w[:16]
	}
	return out
}
