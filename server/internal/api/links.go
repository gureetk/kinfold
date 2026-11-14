// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/kcrypto"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// Linking mailboxes (API.md §10, PROTOCOL.md §10.2). They live a few minutes and are kept
// in memory only: a restart ends them, and the two devices start again.

const (
	LinkLife1      = 120 * second // the longest a mailbox lives in direction 1
	LinkLife2      = 300 * second // and in direction 2
	LinkAfterRead  = 60 * second  // how long a mailbox lives once its response is read
	maxLinkSlot    = 1 << 10
	maxLinkReply   = 256 << 10
	linkMessageLen = 1 + 16 + 1 + 12 // a LinkMessage before its ciphertext
)

// A slot: the LinkMessage type it holds (0 for the response), the slot written before it,
// and whether the existing phone writes it (otherwise the new device does). The phone
// reads what the new device writes, and the new device what the phone writes.
var linkSlots = map[string]struct {
	msgType uint8
	after   string
	byPhone bool
}{
	"offer":    {1, "", true},
	"commit":   {3, "offer", false}, // offer: in direction 2 only
	"nonce":    {4, "commit", true},
	"request":  {2, "nonce", false},
	"response": {0, "request", true},
}

type mailbox struct {
	direction int
	expiresAt uint64
	account   []byte // the creator's account (direction 1), or the offer's writer's (direction 2)
	creator   []byte // the device that created it, in direction 1
	slots     map[string][]byte
	readAt    uint64 // when its response was first read; 0 before
}

// ended says whether a mailbox has ended at now, and when it did.
func (m *mailbox) ended(now uint64) bool {
	return now >= m.expiresAt || (m.readAt != 0 && now >= m.readAt+LinkAfterRead)
}

type mailboxes struct {
	mu    sync.Mutex
	boxes map[string]*mailbox
}

func newMailboxes() *mailboxes { return &mailboxes{boxes: map[string]*mailbox{}} }

// SweepLinks forgets the mailboxes that have ended: they are gone within a minute of it
// (API.md §15). The server runs it every minute.
func (s *Server) SweepLinks() int {
	now := s.cfg.Clock.Now()
	s.links.mu.Lock()
	var gone []string
	for id, m := range s.links.boxes {
		if m.ended(now) {
			delete(s.links.boxes, id)
			gone = append(gone, id)
		}
	}
	s.links.mu.Unlock()
	for _, id := range gone {
		for slot := range linkSlots {
			s.waits.wake("link/" + id + "/" + slot) // waiting reads find it gone
		}
	}
	return len(gone)
}

// createLink is POST /v1/links: a mailbox for linking a device.
func (s *Server) createLink(q *request) error {
	var in struct {
		LinkID    b64    `json:"link_id"`
		Direction int    `json:"direction"`
		ExpiresAt uint64 `json:"expires_at"`
	}
	if err := q.json(&in); err != nil {
		return err
	}
	if len(in.LinkID) != 16 || (in.Direction != 1 && in.Direction != 2) {
		return badRequest("link_id is 16 bytes and direction 1 or 2")
	}
	m := &mailbox{direction: in.Direction, expiresAt: in.ExpiresAt, slots: map[string][]byte{}}
	l := s.limiter.limits
	if in.Direction == 1 {
		if err := s.cfg.Store.View(func(tx store.Tx) error { return s.session(q, tx, phone) }); err != nil {
			return err
		}
		if ok, wait := s.limiter.allow("link/device/"+string(q.dev.ID), l.LinksPerDevice, hour, q.now); !ok {
			return rateLimited(wait)
		}
		m.account, m.creator = q.dev.Account, q.dev.ID
	} else {
		// Without a session, every attempt counts, refused or not (API.md §3).
		if ok, wait := s.limiter.allow("link/address/"+clientAddress(q.r), l.LinksPerAddress, hour, q.now); !ok {
			return rateLimited(wait)
		}
		if ok, wait := s.limiter.allow("link/server", l.LinksPerServer, hour, q.now); !ok {
			return rateLimited(wait)
		}
		var st store.Settings
		if err := s.cfg.Store.View(func(tx store.Tx) (err error) { st, err = tx.Settings(); return }); err != nil {
			return err
		}
		if !st.WebDevices {
			return &apiError{status: http.StatusForbidden, code: "forbidden", msg: "this server doesn't take web or Home Assistant devices"}
		}
	}
	life := map[int]uint64{1: LinkLife1, 2: LinkLife2}[in.Direction]
	if in.ExpiresAt <= q.now || in.ExpiresAt-q.now > life {
		return badRequest("expires_at must be in the future, and at most " + strconv.Itoa(int(life/second)) + " seconds away")
	}
	s.links.mu.Lock()
	defer s.links.mu.Unlock()
	if old := s.links.boxes[string(in.LinkID)]; old != nil {
		if old.direction == m.direction && old.expiresAt == m.expiresAt && bytes.Equal(old.creator, m.creator) {
			writeJSON(q.w, http.StatusCreated, map[string]any{}) // the same mailbox again
			return nil
		}
		return &apiError{status: http.StatusConflict, code: "slot_taken", msg: "that link ID is in use"}
	}
	s.links.boxes[string(in.LinkID)] = m
	writeJSON(q.w, http.StatusCreated, map[string]any{})
	return nil
}

// linkBox finds a mailbox that hasn't ended. The caller holds the lock.
func (s *Server) linkBox(q *request, id []byte) (*mailbox, error) {
	m := s.links.boxes[string(id)]
	switch {
	case m == nil:
		return nil, errNotFound
	case m.ended(q.now):
		return nil, errGone
	}
	return m, nil
}

// putLinkSlot is PUT /v1/links/{link_id}/{slot}: written once, in order.
func (s *Server) putLinkSlot(q *request) error {
	id, err := q.pathID("link_id")
	if err != nil {
		return err
	}
	name := q.r.PathValue("slot")
	slot, ok := linkSlots[name]
	if !ok {
		return errNotFound
	}
	limit := maxLinkSlot
	if name == "response" {
		limit = maxLinkReply
	}
	raw, err := q.body(limit)
	if err != nil {
		return err
	}
	// The session is checked before the lock: it reads the store.
	if slot.byPhone {
		if err := s.cfg.Store.View(func(tx store.Tx) error { return s.session(q, tx, phone) }); err != nil {
			return err
		}
	}
	s.links.mu.Lock()
	defer s.links.mu.Unlock()
	m, err := s.linkBox(q, id)
	if err != nil {
		return err
	}
	// A mailbox belongs to one account; in direction 2, to the offer's writer.
	if slot.byPhone && m.account != nil && !bytes.Equal(m.account, q.dev.Account) {
		return errForbidden
	}
	if name == "offer" && m.direction != 2 {
		return errNotFound // direction 1 has no offer: the code carries the account
	}
	if old, written := m.slots[name]; written {
		if bytes.Equal(old, raw) {
			q.w.WriteHeader(http.StatusNoContent) // the same bytes again
			return nil
		}
		return &apiError{status: http.StatusConflict, code: "slot_taken", msg: "that slot was written already"}
	}
	if before := slot.after; before != "" && !(before == "offer" && m.direction == 1) && m.slots[before] == nil {
		return &apiError{status: http.StatusConflict, code: "out_of_order", msg: "the " + before + " comes first"}
	}
	if !linkMessageOK(raw, id, slot.msgType, q) {
		return refused("malformed", nil)
	}
	if name == "offer" {
		m.account = q.dev.Account
	}
	m.slots[name] = raw
	s.waits.wake("link/" + string(id) + "/" + name)
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

// linkMessageOK checks what the server can see of a slot's bytes. A LinkMessage: version 0,
// the path's link ID, the slot's type, a nonce and a ciphertext, nothing after. The
// response: version 0, the link ID, the session's own certificate, then enc, a ciphertext
// and a signature under that device's key (PROTOCOL.md §10.3).
func linkMessageOK(raw, id []byte, msgType uint8, q *request) bool {
	r := wire.NewReader(raw)
	ver, linkID := r.U8(), r.Take(16)
	if ver != identity.Version || !bytes.Equal(linkID, id) {
		return false
	}
	if msgType != 0 {
		t := r.U8()
		r.Take(12)
		ct := r.Vec32()
		return r.Done() && t == msgType && len(ct) > 0
	}
	cert := identity.ReadCert(r)
	r.Take(32)
	ct := r.Vec32()
	tbs := r.Pos()
	sig := r.Take(64)
	return r.Done() && len(ct) > 0 && bytes.Equal(cert.DSK, q.dev.DSK) && bytes.Equal(cert.AccountID, q.dev.Account) &&
		kcrypto.Verify(q.dev.DSK, "link-response", raw[:tbs], sig)
}

// getLinkSlot is GET /v1/links/{link_id}/{slot}?wait=: the slot's bytes once written.
func (s *Server) getLinkSlot(q *request) error {
	id, err := q.pathID("link_id")
	if err != nil {
		return err
	}
	name := q.r.PathValue("slot")
	slot, ok := linkSlots[name]
	if !ok {
		return errNotFound
	}
	wait := 0
	if v := q.r.URL.Query().Get("wait"); v != "" {
		if wait, err = strconv.Atoi(v); err != nil || wait < 0 {
			return badRequest("bad wait")
		}
	}
	phoneSide := !slot.byPhone // the phone reads what the new device writes
	if phoneSide {
		if err := s.cfg.Store.View(func(tx store.Tx) error { return s.session(q, tx, phone) }); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(time.Duration(min(wait, MaxWaitSeconds)) * time.Second)
	for {
		woken := s.waits.wait("link/" + string(id) + "/" + name) // before reading, so no write is missed
		q.now = s.cfg.Clock.Now()
		s.links.mu.Lock()
		m, err := s.linkBox(q, id)
		if err == nil && phoneSide && (m.account == nil || !bytes.Equal(m.account, q.dev.Account)) {
			err = errForbidden
		}
		var got []byte
		if err == nil {
			got = m.slots[name]
			if got != nil && name == "response" && m.readAt == 0 {
				m.readAt = q.now
			}
		}
		s.links.mu.Unlock()
		if err != nil {
			return err
		}
		if got != nil {
			writeBytes(q.w, http.StatusOK, got)
			return nil
		}
		left := time.Until(deadline)
		if left <= 0 {
			q.w.WriteHeader(http.StatusNoContent)
			return nil
		}
		timer := time.NewTimer(left)
		select {
		case <-woken:
		case <-timer.C:
		case <-q.r.Context().Done():
			timer.Stop()
			return nil
		}
		timer.Stop()
	}
}
