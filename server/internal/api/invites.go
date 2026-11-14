// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// inviteEnded: deleted, expired without a result, or a result older than a day.
func inviteEnded(inv store.Invite, now uint64) bool {
	return inv.Ended || (inv.Result == nil && now >= inv.ExpiresAt) || (inv.Result != nil && now >= inv.ResultAt+ResultKeep)
}

// pending: an invite that still takes join requests.
func invitePending(inv store.Invite, now uint64) bool { return !inviteEnded(inv, now) && !inv.Used }

// joinMessage checks the clear part of a JoinRequest or JoinResult (PROTOCOL.md §9.2,
// §9.3): version 0, the invite ID of the path, a 12-byte nonce, a vec32 ciphertext and
// nothing after it. The server can read nothing else.
func joinMessage(raw, invite []byte) bool {
	r := wire.NewReader(raw)
	ver, id := r.U8(), r.Take(16)
	r.Take(12)
	ct := r.Vec32()
	return r.Done() && ver == identity.Version && bytes.Equal(id, invite) && len(ct) >= 16
}

// createInvite is POST /v1/invites.
func (s *Server) createInvite(q *request) error {
	var in struct {
		CircleID  b64    `json:"circle_id"`
		InviteID  b64    `json:"invite_id"`
		ExpiresAt uint64 `json:"expires_at"`
		RegToken  bool   `json:"reg_token"`
	}
	if err := q.json(&in); err != nil {
		return err
	}
	if len(in.CircleID) != 16 || len(in.InviteID) != 16 {
		return badRequest("circle_id and invite_id are 16 bytes")
	}
	if in.ExpiresAt <= q.now || in.ExpiresAt-q.now > InviteMaxLife {
		return badRequest("expires_at must be in the future and at most 7 days away")
	}
	var token []byte
	err := s.cfg.Store.Update(func(tx store.Tx) error {
		if err := s.session(q, tx, phone); err != nil {
			return err
		}
		c, err := s.activeCircle(q, tx, in.CircleID)
		if err != nil {
			return err
		}
		if m := c.State.Member(q.dev.Account); m == nil || !m.Admin {
			return errForbidden
		}
		inv := store.Invite{ID: in.InviteID, Circle: in.CircleID, Account: q.dev.Account, ExpiresAt: in.ExpiresAt}
		if old, err := tx.Invite(in.InviteID); err == nil {
			if !bytes.Equal(old.Circle, in.CircleID) || !bytes.Equal(old.Account, q.dev.Account) || old.Ended || old.Used {
				return &apiError{status: http.StatusConflict, code: "slot_taken", msg: "that invite ID is in use"}
			}
			inv = old // the same invite again: it keeps its requests and its expiry
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		} else {
			all, err := tx.InvitesOf(in.CircleID)
			if err != nil {
				return err
			}
			pending := 0
			for _, inv := range all {
				if invitePending(inv, q.now) {
					pending++
				}
			}
			if pending >= s.limiter.limits.PendingInvites {
				return rateLimited(60)
			}
		}
		if err := tx.PutInvite(inv); err != nil {
			return err
		}
		st, err := tx.Settings()
		if err != nil || !in.RegToken || !st.MemberTokens {
			return err
		}
		// A retry gets a new token, and the one before it no longer works.
		if err := s.revokeInviteTokens(tx, in.InviteID); err != nil {
			return err
		}
		token = s.random(32)
		return tx.PutToken(store.Token{Hash: hashToken(token), CreatedAt: q.now, ExpiresAt: inv.ExpiresAt, Invite: in.InviteID})
	})
	if err != nil {
		return err
	}
	out := map[string]any{}
	if token != nil {
		out["reg_token"] = b64(token)
	}
	writeJSON(q.w, http.StatusCreated, out)
	return nil
}

// postJoinRequest is POST /v1/invites/{invite_id}/requests.
func (s *Server) postJoinRequest(q *request) error {
	id, err := q.pathID("invite_id")
	if err != nil {
		return err
	}
	raw, err := q.body(maxJoin)
	if err != nil {
		return err
	}
	if !joinMessage(raw, id) {
		return refused("malformed", nil)
	}
	err = s.cfg.Store.Update(func(tx store.Tx) error {
		if err := s.session(q, tx, phone); err != nil {
			return err
		}
		inv, err := tx.Invite(id)
		if errors.Is(err, store.ErrNotFound) {
			return errNotFound
		} else if err != nil {
			return err
		}
		if !invitePending(inv, q.now) {
			return errGone
		}
		if slices.ContainsFunc(inv.Requests, func(r []byte) bool { return bytes.Equal(r, raw) }) {
			return nil // the same request again
		}
		if len(inv.Requests) >= s.limiter.limits.WaitingRequests {
			return rateLimited(int((inv.ExpiresAt - q.now + 999) / 1000))
		}
		inv.Requests = append(slices.Clone(inv.Requests), raw)
		if !slices.ContainsFunc(inv.Askers, func(d []byte) bool { return bytes.Equal(d, q.dev.ID) }) {
			inv.Askers = append(slices.Clone(inv.Askers), q.dev.ID)
		}
		return tx.PutInvite(inv)
	})
	if err != nil {
		return err
	}
	q.w.WriteHeader(http.StatusCreated)
	return nil
}

// inviterInvite finds an invite that the session's account made.
func (s *Server) inviterInvite(q *request, tx store.Tx, id []byte) (store.Invite, error) {
	if err := s.session(q, tx, phone); err != nil {
		return store.Invite{}, err
	}
	inv, err := tx.Invite(id)
	if errors.Is(err, store.ErrNotFound) {
		return inv, errNotFound
	} else if err != nil {
		return inv, err
	}
	if !bytes.Equal(inv.Account, q.dev.Account) {
		return inv, errForbidden
	}
	if inviteEnded(inv, q.now) {
		return inv, errGone
	}
	return inv, nil
}

// joinRequests is GET /v1/invites/{invite_id}/requests.
func (s *Server) joinRequests(q *request) error {
	id, err := q.pathID("invite_id")
	if err != nil {
		return err
	}
	var inv store.Invite
	if err := s.cfg.Store.View(func(tx store.Tx) (err error) { inv, err = s.inviterInvite(q, tx, id); return }); err != nil {
		return err
	}
	var out []byte
	for _, r := range inv.Requests {
		out = wire.AppendFrame(out, r)
	}
	writeBytes(q.w, http.StatusOK, out)
	return nil
}

// putJoinResult is PUT /v1/invites/{invite_id}/result. It is written once.
func (s *Server) putJoinResult(q *request) error {
	id, err := q.pathID("invite_id")
	if err != nil {
		return err
	}
	raw, err := q.body(maxJoin)
	if err != nil {
		return err
	}
	if !joinMessage(raw, id) {
		return refused("malformed", nil)
	}
	err = s.cfg.Store.Update(func(tx store.Tx) error {
		inv, err := s.inviterInvite(q, tx, id)
		if err != nil {
			return err
		}
		if inv.Result != nil {
			if bytes.Equal(inv.Result, raw) {
				return nil
			}
			return &apiError{status: http.StatusConflict, code: "slot_taken", msg: "the result was written already"}
		}
		inv.Result, inv.ResultAt, inv.Requests = raw, q.now, nil
		return tx.PutInvite(inv)
	})
	if err != nil {
		return err
	}
	s.waits.wake("result/" + string(id))
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

// joinResult is GET /v1/invites/{invite_id}/result?wait=, for a device that posted a request.
func (s *Server) joinResult(q *request) error {
	id, err := q.pathID("invite_id")
	if err != nil {
		return err
	}
	wait := 0
	if v := q.r.URL.Query().Get("wait"); v != "" {
		if wait, err = strconv.Atoi(v); err != nil || wait < 0 {
			return badRequest("bad wait")
		}
	}
	deadline := time.Now().Add(time.Duration(min(wait, MaxWaitSeconds)) * time.Second)
	for {
		woken := s.waits.wait("result/" + string(id)) // before reading, so no write is missed
		var result []byte
		err := s.cfg.Store.View(func(tx store.Tx) error {
			if err := s.session(q, tx, phone); err != nil {
				return err
			}
			inv, err := tx.Invite(id)
			if errors.Is(err, store.ErrNotFound) {
				return errNotFound
			} else if err != nil {
				return err
			}
			if !slices.ContainsFunc(inv.Askers, func(d []byte) bool { return bytes.Equal(d, q.dev.ID) }) {
				return errForbidden
			}
			if inviteEnded(inv, q.now) {
				return errGone
			}
			result = inv.Result
			return nil
		})
		if err != nil {
			return err
		}
		if result != nil {
			writeBytes(q.w, http.StatusOK, result)
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
		}
		timer.Stop()
		if q.r.Context().Err() != nil {
			return nil
		}
	}
}

// deleteInvite is DELETE /v1/invites/{invite_id}: the inviter's account, or any admin of
// the circle.
func (s *Server) deleteInvite(q *request) error {
	id, err := q.pathID("invite_id")
	if err != nil {
		return err
	}
	err = s.cfg.Store.Update(func(tx store.Tx) error {
		if err := s.session(q, tx, phone); err != nil {
			return err
		}
		inv, err := tx.Invite(id)
		if errors.Is(err, store.ErrNotFound) {
			return errNotFound
		} else if err != nil {
			return err
		}
		if !bytes.Equal(inv.Account, q.dev.Account) {
			c, err := tx.Circle(inv.Circle)
			if err != nil {
				return errForbidden
			}
			if m := c.State.Member(q.dev.Account); m == nil || !m.Admin || c.State.Device(q.dev.ID) == nil {
				return errForbidden
			}
		}
		inv.Ended, inv.Requests = true, nil
		if err := tx.PutInvite(inv); err != nil {
			return err
		}
		return s.revokeInviteTokens(tx, id)
	})
	if err != nil {
		return err
	}
	s.waits.wake("result/" + string(id))
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}
