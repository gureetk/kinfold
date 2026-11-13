// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"strconv"

	"github.com/gureetk/kinfold/server/internal/envelope"
	"github.com/gureetk/kinfold/server/internal/push"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// heads and seen let the protocol checks read the store. A store error is kept and
// returned once the check is done.
type heads struct {
	tx     store.Tx
	circle []byte
	err    error
}

func (h *heads) SeqOf(hash []byte) (int64, bool) {
	s, ok, err := h.tx.SeqOf(h.circle, hash)
	if err != nil {
		h.err = err
	}
	return s, ok
}

type seen struct {
	tx     store.Tx
	circle []byte
	rec    store.SeenRecord
	err    error
}

func (s *seen) Digest(sender []byte, seq uint64) ([32]byte, bool) {
	r, ok, err := s.tx.Seen(s.circle, sender, seq)
	if err != nil {
		s.err = err
	}
	s.rec = r
	return r.Digest, ok
}

// wakeRecipients prepares the pushes Kinfold-Wake asks for (API.md §7, §12): a records push
// when the delivery record fits in one, otherwise a wake push, for each recipient that has no
// stream open. Wake-ups have their own limits, which refuse the upload past them.
func (s *Server) wakeRecipients(q *request, tx store.Tx, wake string, recipients [][]byte, raw []byte) ([]*pushJob, error) {
	if wake == "" {
		return nil, nil
	}
	l := s.limiter.limits
	if wake == "notify" {
		if ok, wait := s.limiter.allow("wake/notify/"+string(q.dev.ID), l.WakeNotify, hour, q.now); !ok {
			return nil, rateLimited(wait)
		}
	} else {
		for _, r := range recipients {
			if ok, wait := s.limiter.allow("wake/locate/"+string(q.dev.ID)+"/"+string(r), l.WakeLocate, hour, q.now); !ok {
				return nil, rateLimited(wait)
			}
		}
	}
	ptype, body := uint8(push.Records), push.RecordsBody([][]byte{push.Record(q.now, raw)})
	if len(body) > push.MaxBody {
		ptype, body = push.Wake, nil
	}
	delivery := uint8(push.Alert)
	if wake == "locate" {
		delivery = push.Location
	}
	var jobs []*pushJob
	for _, r := range recipients {
		j, err := s.preparePush(tx, r, ptype, body, delivery, push.Alert, q.now)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, nil
}

// postEnvelope is POST /v1/circles/{id}/envelopes, with an optional Kinfold-Wake.
func (s *Server) postEnvelope(q *request) error {
	id, err := q.pathID("id")
	if err != nil {
		return err
	}
	wake := q.r.Header.Get("Kinfold-Wake")
	if wake != "" && wake != "notify" && wake != "locate" {
		return badRequest("Kinfold-Wake is notify or locate")
	}
	raw, err := q.body(envelope.MaxLen)
	if err != nil {
		return err
	}
	var receivedAt uint64
	err = s.update(q, func(tx store.Tx) error {
		if err := s.session(q, tx, receiving); err != nil {
			return err
		}
		c, err := s.activeCircle(q, tx, id)
		if err != nil {
			return err
		}
		if e, err := envelope.Parse(raw); err == nil {
			if !bytes.Equal(e.Sender, q.dev.ID) {
				return errForbidden
			}
			if wake == "locate" && e.Kind != envelope.Direct {
				return badRequest("locate is for direct envelopes")
			}
		}
		// Every upload counts, refused or not: checking one costs signature verifications.
		l := s.limiter.limits
		if ok, wait := s.limiter.allow("envelope/minute/"+string(q.dev.ID), l.EnvelopesPerMinute, minute, q.now); !ok {
			return rateLimited(wait)
		}
		if ok, wait := s.limiter.allow("envelope/hour/"+string(q.dev.ID), l.EnvelopesPerHour, hour, q.now); !ok {
			return rateLimited(wait)
		}
		h, sn := &heads{tx: tx, circle: id}, &seen{tx: tx, circle: id}
		env, out, err := envelope.Check(c.State, h, sn, raw, q.now)
		if h.err != nil || sn.err != nil {
			return firstErr(h.err, sn.err)
		}
		if err != nil {
			if r, ok := err.(*envelope.Refused); ok {
				return refused(r.Reason, headOf(c.State))
			}
			return err
		}
		if out == envelope.Duplicate {
			receivedAt = sn.rec.ReceivedAt // posting twice is safe
			return nil
		}
		receivedAt = q.now
		recipients := env.Recipients()
		jobs, err := s.wakeRecipients(q, tx, wake, recipients, raw)
		if err != nil {
			return err
		}
		if _, err := tx.PutEnvelope(store.Envelope{Circle: id, Sender: env.Sender, Recipients: recipients,
			ReceivedAt: q.now, ExpiresAt: q.now + uint64(env.TTL)*second, Raw: raw}); err != nil {
			return err
		}
		q.afterCommit(func() { s.tellRecords(recipients); s.send(jobs) })
		if env.Kind == envelope.Circle { // a circle envelope, and nothing else, resets its sender's watches
			if err := tx.Heard(id, env.Sender, q.now); err != nil {
				return err
			}
		}
		// Pushes for Kinfold-Wake come with push registration (API.md §12): until then the
		// envelope waits for the recipient's next fetch.
		return tx.PutSeen(id, env.Sender, env.Seq, store.SeenRecord{Digest: sha256.Sum256(raw), ReceivedAt: q.now,
			KeepUntil: env.SentAt + SeenKeep})
	})
	if err != nil {
		return err
	}
	writeJSON(q.w, http.StatusCreated, map[string]any{"received_at": receivedAt})
	return nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// inbox is GET /v1/inbox?since=&limit=: delivery records, u64 received_at ‖ envelope, for
// the circles in which the device is still an active receiving device.
func (s *Server) inbox(q *request) error {
	since, err := cursorParam(q)
	if err != nil {
		return err
	}
	limit := maxInboxPage
	if v := q.r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return badRequest("bad limit")
		}
		limit = min(n, maxInboxPage)
	}
	var envs []store.Envelope
	var more bool
	err = s.cfg.Store.View(func(tx store.Tx) error {
		if err := s.session(q, tx, receiving); err != nil {
			return err
		}
		circles, err := activeCircles(tx, q.dev)
		if err != nil {
			return err
		}
		envs, more, err = tx.Inbox(q.dev.ID, circles, since, limit, maxPageBytes, q.now)
		return err
	})
	if err != nil {
		return err
	}
	var out []byte
	cursor := since
	for _, e := range envs {
		out = wire.AppendFrame(out, wire.Concat(wire.U64(e.ReceivedAt), e.Raw))
		cursor = e.Seq
	}
	q.w.Header().Set("Kinfold-Cursor", cursorText(cursor))
	if more {
		q.w.Header().Set("Kinfold-More", "1")
	}
	writeBytes(q.w, http.StatusOK, out)
	return nil
}
