// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"errors"
	"net/http"
	"strconv"

	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/kcrypto"
	"github.com/gureetk/kinfold/server/internal/memberlog"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// activeCircle returns the circle if the session's device is an active device of it at the
// server's current head (API.md §1). Everyone else gets the 404 of a circle that doesn't exist.
func (s *Server) activeCircle(q *request, tx store.Tx, id []byte) (store.Circle, error) {
	c, err := tx.Circle(id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && c.State.Device(q.dev.ID) == nil) {
		return store.Circle{}, errNotFound
	}
	return c, err
}

func headOf(st *memberlog.State) map[string]any {
	return map[string]any{"seq": st.Seq, "head": b64(st.Head)}
}

// refusedEntry maps a fatal entry onto the API: 409 when it was built on an old head,
// 422 otherwise. Both carry the circle's current seq and head.
func refusedEntry(err error, st *memberlog.State) error {
	var f *memberlog.Fatal
	if !errors.As(err, &f) {
		return err
	}
	if st == nil {
		return refused(f.Reason, nil)
	}
	if f.Reason == "bad_seq" || f.Reason == "bad_prev_hash" {
		return &apiError{status: http.StatusConflict, code: "conflict", msg: "the log has moved on", extra: headOf(st)}
	}
	return refused(f.Reason, headOf(st))
}

func (s *Server) countAppend(q *request, circle []byte) error {
	l := s.limiter.limits
	if ok, wait := s.limiter.allow("append/device/"+string(q.dev.ID), l.AppendsPerDevice, hour, q.now); !ok {
		return rateLimited(wait)
	}
	if circle != nil {
		if ok, wait := s.limiter.allow("append/circle/"+string(circle), l.AppendsPerCircle, day, q.now); !ok {
			return rateLimited(wait)
		}
	}
	return nil
}

// createCircle is POST /v1/circles: a GENESIS entry.
func (s *Server) createCircle(q *request) error {
	raw, err := q.body(memberlog.MaxEntry)
	if err != nil {
		return err
	}
	var cid []byte
	err = s.update(q, func(tx store.Tx) error {
		if err := s.session(q, tx, phone); err != nil {
			return err
		}
		st, err := tx.Settings()
		if err != nil {
			return err
		}
		repair := repairing(st, q.now)
		// Posting twice is safe: the same GENESIS again succeeds, however late, without
		// counting against the limits. Its hash is the circle ID.
		if e, err := memberlog.ParseEntry(raw); err == nil && (repair || bytes.Equal(e.Author, q.dev.ID)) {
			id := kcrypto.H("circle-id", raw)[:16]
			if have, err := tx.Entries(id, -1, 1, maxPageBytes); err == nil && len(have) == 1 && bytes.Equal(have[0], raw) {
				cid = id
				return nil
			}
		}
		if err := s.countAppend(q, nil); err != nil {
			return err
		}
		ns, e, err := memberlog.Append(memberlog.New(), raw, q.now, repair)
		if err != nil {
			return refusedEntry(err, nil)
		}
		// The founder is the session's device and account, except when a phone re-posts a
		// circle that a restored server lost (repair mode).
		if !repair && (!bytes.Equal(e.Author, q.dev.ID) || ns.Member(q.dev.Account) == nil) {
			return errForbidden
		}
		cid = ns.CircleID
		q.afterCommit(func() { s.tellLog(cid, nil, ns) })
		return tx.CreateCircle(store.Circle{ID: cid, State: ns, CreatedAt: q.now}, raw)
	})
	if err != nil {
		return err
	}
	writeJSON(q.w, http.StatusCreated, map[string]any{"circle_id": b64(cid)})
	return nil
}

func (s *Server) head(q *request) error {
	id, err := q.pathID("id")
	if err != nil {
		return err
	}
	var c store.Circle
	err = s.cfg.Store.View(func(tx store.Tx) error {
		if err := s.session(q, tx, anyDevice); err != nil {
			return err
		}
		c, err = s.activeCircle(q, tx, id)
		return err
	})
	if err != nil {
		return err
	}
	writeJSON(q.w, http.StatusOK, map[string]any{"seq": c.State.Seq, "head": b64(c.State.Head), "epoch": c.State.Epoch,
		"rekey_pending": c.State.RekeyPending})
	return nil
}

// readLog is GET /v1/circles/{id}/log?after=&limit=. A device that has been removed may
// read up to and including the entry that removed it, for 30 days (API.md §6).
func (s *Server) readLog(q *request) error {
	id, err := q.pathID("id")
	if err != nil {
		return err
	}
	after, limit := int64(-1), maxLogPage
	if v := q.r.URL.Query().Get("after"); v != "" {
		if after, err = strconv.ParseInt(v, 10, 64); err != nil || after < -1 {
			return badRequest("bad after")
		}
	}
	if v := q.r.URL.Query().Get("limit"); v != "" {
		if limit, err = strconv.Atoi(v); err != nil || limit < 1 {
			return badRequest("bad limit")
		}
		limit = min(limit, maxLogPage)
	}
	var entries [][]byte
	var seq int64
	var head []byte
	err = s.cfg.Store.View(func(tx store.Tx) error {
		if err := s.session(q, tx, anyDevice); err != nil {
			return err
		}
		c, err := tx.Circle(id)
		if errors.Is(err, store.ErrNotFound) {
			return errNotFound
		} else if err != nil {
			return err
		}
		seq, head = c.State.Seq, c.State.Head
		if c.State.Device(q.dev.ID) == nil {
			rm, err := tx.Removal(id, q.dev.ID)
			if err != nil || q.now >= rm.At+RemovedReadLife {
				return errNotFound
			}
			// Show the log as it stood after the entry that removed this device.
			removing, err := tx.Entries(id, rm.Seq-1, 1, maxPageBytes)
			if err != nil || len(removing) != 1 {
				return errNotFound
			}
			seq, head = rm.Seq, memberlog.Hash(removing[0])
			limit = int(min(int64(limit), rm.Seq-after))
			if limit < 1 {
				return nil
			}
		}
		entries, err = tx.Entries(id, after, limit, maxPageBytes)
		return err
	})
	if err != nil {
		return err
	}
	var out []byte
	for _, e := range entries {
		out = wire.AppendFrame(out, e)
	}
	q.w.Header().Set("Kinfold-Seq", strconv.FormatInt(seq, 10))
	q.w.Header().Set("Kinfold-Head", wire.EncodeB64u(head))
	writeBytes(q.w, http.StatusOK, out)
	return nil
}

func (s *Server) appendEntry(q *request) error { return s.append(q, false) }
func (s *Server) repairEntry(q *request) error { return s.append(q, true) }

// append is POST /v1/circles/{id}/log and, in repair mode, its repair path.
func (s *Server) append(q *request, repairPath bool) error {
	id, err := q.pathID("id")
	if err != nil {
		return err
	}
	raw, err := q.body(memberlog.MaxEntry)
	if err != nil {
		return err
	}
	var result map[string]any
	err = s.update(q, func(tx store.Tx) error {
		if err := s.session(q, tx, anyDevice); err != nil {
			return err
		}
		c, err := s.activeCircle(q, tx, id)
		if err != nil {
			return err
		}
		st, err := tx.Settings()
		if err != nil {
			return err
		}
		switch repair := repairing(st, q.now); {
		case repairPath && !repair:
			return errNotFound
		case !repairPath && repair:
			return &apiError{status: http.StatusServiceUnavailable, code: "repair_mode", msg: "the server is in repair mode"}
		}
		if e, err := memberlog.ParseEntry(raw); err == nil {
			// On the normal path the author is the session's device. On the repair path any
			// active device re-posts what the server lost, whoever authored it.
			if !repairPath && !bytes.Equal(e.Author, q.dev.ID) {
				return errForbidden
			}
			// Posting twice is safe: an entry that is already in the log succeeds again.
			if int64(e.Seq) <= c.State.Seq {
				have, err := tx.Entries(id, int64(e.Seq)-1, 1, maxPageBytes)
				if err == nil && len(have) == 1 && bytes.Equal(have[0], raw) {
					result = map[string]any{"seq": e.Seq, "head": b64(memberlog.Hash(raw))}
					return nil
				}
			}
		}
		if err := s.countAppend(q, id); err != nil {
			return err
		}
		ns, e, err := memberlog.Append(c.State, raw, q.now, repairPath)
		if err != nil {
			return refusedEntry(err, c.State)
		}
		if err := tx.AppendEntry(id, raw, ns, q.now); err != nil {
			return err
		}
		old := c.State
		q.afterCommit(func() { s.tellLog(id, old, ns) })
		if err := s.afterAppend(q, tx, id, c.State, ns, e); err != nil {
			return err
		}
		result = headOf(ns)
		return nil
	})
	if err != nil {
		return err
	}
	writeJSON(q.w, http.StatusCreated, result)
	return nil
}

// afterAppend applies the public effects an entry has outside the log (API.md §6): removed
// devices keep read access to their removal only, and a spent invite takes no more requests.
func (s *Server) afterAppend(q *request, tx store.Tx, circle []byte, old, ns *memberlog.State, e *memberlog.Entry) error {
	for _, m := range old.Members {
		for _, d := range m.Devices {
			if ns.Device(d.ID) == nil {
				if err := tx.PutRemoval(store.Removal{Circle: circle, Device: d.ID, Seq: ns.Seq, At: q.now}); err != nil {
					return err
				}
			}
		}
	}
	// A member who has left can't answer an invite: nobody else may read its requests.
	for acc := range old.Members {
		if ns.Members[acc] != nil {
			continue
		}
		invs, err := tx.InvitesOf(circle)
		if err != nil {
			return err
		}
		for _, inv := range invs {
			if string(inv.Account) == acc && !inv.Ended {
				inv.Ended, inv.Requests = true, nil
				if err := tx.PutInvite(inv); err != nil {
					return err
				}
				if err := s.revokeInviteTokens(tx, inv.ID); err != nil {
					return err
				}
			}
		}
	}
	if e.Type != memberlog.AddMember {
		return nil
	}
	inv, err := tx.Invite(e.InviteID())
	if errors.Is(err, store.ErrNotFound) || (err == nil && !bytes.Equal(inv.Circle, circle)) {
		return nil
	} else if err != nil {
		return err
	}
	// The result slot stays open: the inviter posts the result after this entry (§9).
	inv.Used, inv.Requests = true, nil
	if err := tx.PutInvite(inv); err != nil {
		return err
	}
	return s.revokeInviteTokens(tx, inv.ID)
}

func (s *Server) revokeInviteTokens(tx store.Tx, invite []byte) error {
	toks, err := tx.Tokens()
	if err != nil {
		return err
	}
	for _, t := range toks {
		if !t.Spent && bytes.Equal(t.Invite, invite) {
			if err := tx.DeleteToken(t.Hash); err != nil {
				return err
			}
		}
	}
	return nil
}

// activeCircles lists the circles in which device is an active receiving device.
func activeCircles(tx store.Tx, dev store.Device) ([][]byte, error) {
	circles, err := tx.CirclesOf(dev.Account)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, c := range circles {
		if d := c.State.Device(dev.ID); d != nil && identity.Receiving(d.Kind) {
			out = append(out, c.ID)
		}
	}
	return out, nil
}
