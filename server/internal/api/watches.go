// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"errors"
	"net/http"
	"slices"

	"github.com/gureetk/kinfold/server/internal/memberlog"
	"github.com/gureetk/kinfold/server/internal/push"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/watch"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// WakeWait is how long the server waits, after waking a silent device, before it alerts
// the watcher (API.md §8).
const WakeWait = 2 * minute

var (
	errBadGrant   = &apiError{status: http.StatusUnprocessableEntity, code: "bad_grant", msg: "the watch grant isn't valid (PROTOCOL.md §14.1)"}
	errStaleGrant = &apiError{status: http.StatusConflict, code: "stale_grant", msg: "this grant was issued no later than the one registered, or before the watch was ended"}
)

// putWatch is PUT /v1/circles/{id}/watches/{device_id}: register a watch, or renew it with
// a newer grant.
func (s *Server) putWatch(q *request) error {
	id, err := q.pathID("id")
	if err != nil {
		return err
	}
	device, err := q.pathID("device_id")
	if err != nil {
		return err
	}
	raw, err := q.body(watch.GrantLen)
	if err != nil {
		return err
	}
	err = s.update(q, func(tx store.Tx) error {
		if err := s.session(q, tx, phone); err != nil {
			return err
		}
		c, err := s.activeCircle(q, tx, id)
		if err != nil {
			return err
		}
		g, ok := watch.Valid(c.State, raw, q.now)
		if !ok || !bytes.Equal(g.WatchedDevice, device) {
			return errBadGrant
		}
		if !bytes.Equal(g.WatcherAccount, q.dev.Account) {
			return errForbidden
		}
		w := store.Watch{Circle: id, Device: device, Watcher: q.dev.Account, Grant: raw, AfterMin: g.AfterMin,
			IssuedAt: g.IssuedAt, NotAfter: g.NotAfter}
		old, err := tx.Watch(id, device, q.dev.Account)
		switch {
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return err
		case err == nil && g.IssuedAt <= old.RevokedAt:
			// Issued no later than the watched account last ended the watch: a grant the
			// watcher kept can't bring it back, however late its not_after.
			return errStaleGrant
		case err == nil && !old.Revoked && bytes.Equal(old.Grant, raw):
			return nil // the same grant again
		case err == nil && !old.Revoked && g.IssuedAt <= old.IssuedAt:
			return errStaleGrant // newer means a later issued_at
		case err == nil && !old.Revoked:
			// A renewal: the silence goes on.
			w.Since, w.WokeAt, w.Alerted, w.RevokedAt = old.Since, old.WokeAt, old.Alerted, old.RevokedAt
		default:
			// A new watch, or one the device has granted again since the watched account
			// ended the last, which is remembered past it. A device that has been quiet for a
			// while has been silent since it was last heard.
			if err == nil {
				w.RevokedAt = old.RevokedAt
			}
			at, heard, err := tx.LastHeard(id, device)
			if err != nil {
				return err
			}
			w.Since = q.now
			if heard {
				w.Since = at
			}
		}
		return tx.PutWatch(w)
	})
	if err != nil {
		return err
	}
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

// listWatches is GET /v1/circles/{id}/watches: the watches this account holds, and the
// watches on its devices.
func (s *Server) listWatches(q *request) error {
	id, err := q.pathID("id")
	if err != nil {
		return err
	}
	out := []map[string]any{}
	err = s.cfg.Store.View(func(tx store.Tx) error {
		if err := s.session(q, tx, phone); err != nil {
			return err
		}
		c, err := s.activeCircle(q, tx, id)
		if err != nil {
			return err
		}
		ws, err := tx.WatchesIn(id)
		if err != nil {
			return err
		}
		for _, w := range ws {
			if w.Revoked || !(bytes.Equal(w.Watcher, q.dev.Account) || watchedBy(c.State, w, q.dev.Account)) {
				continue
			}
			out = append(out, map[string]any{"watched_device_id": b64(w.Device), "watcher_account_id": b64(w.Watcher),
				"after_min": w.AfterMin, "issued_at": w.IssuedAt, "not_after": w.NotAfter})
		}
		return nil
	})
	if err != nil {
		return err
	}
	writeJSON(q.w, http.StatusOK, out)
	return nil
}

// watchedBy says whether the watched device belongs to the account.
func watchedBy(s *memberlog.State, w store.Watch, account []byte) bool {
	d := s.Device(w.Device)
	return d != nil && bytes.Equal(d.Account, account)
}

// deleteWatch is DELETE /v1/circles/{id}/watches/{device_id}?watcher=: the watcher ends
// its own watch, or the watched account ends one on its device.
func (s *Server) deleteWatch(q *request) error {
	id, err := q.pathID("id")
	if err != nil {
		return err
	}
	device, err := q.pathID("device_id")
	if err != nil {
		return err
	}
	var watcher []byte
	if v := q.r.URL.Query().Get("watcher"); v != "" {
		if watcher, err = wire.DecodeB64u(v); err != nil || len(watcher) != 16 {
			return badRequest("bad watcher")
		}
	}
	err = s.update(q, func(tx store.Tx) error {
		if err := s.session(q, tx, phone); err != nil {
			return err
		}
		c, err := s.activeCircle(q, tx, id)
		if err != nil {
			return err
		}
		if watcher == nil {
			watcher = q.dev.Account
		}
		w, err := tx.Watch(id, device, watcher)
		if errors.Is(err, store.ErrNotFound) || (err == nil && w.Revoked) {
			return errNotFound
		} else if err != nil {
			return err
		}
		switch {
		case bytes.Equal(w.Watcher, q.dev.Account):
			err = dropWatch(tx, w, q.now)
		case watchedBy(c.State, w, q.dev.Account):
			// Kept for 35 days, until every grant issued before now has run out (API.md §8).
			w.Revoked, w.RevokedAt, w.NotAfter = true, q.now, q.now+watch.MaxLifeMS
			err = tx.PutWatch(w)
		default:
			return errForbidden
		}
		if err != nil {
			return err
		}
		return s.tellWatchEnded(q, tx, w, "deleted")
	})
	if err != nil {
		return err
	}
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

// dropWatch ends a watch. If the watched account ended it within the last 35 days, the
// record stays, inactive, until those days are over: a grant issued before that ending can
// still be valid, and mustn't bring the watch back (API.md §8).
func dropWatch(tx store.Tx, w store.Watch, now uint64) error {
	if w.RevokedAt != 0 && (now < w.RevokedAt || now-w.RevokedAt < watch.MaxLifeMS) {
		w.Revoked, w.NotAfter = true, w.RevokedAt+watch.MaxLifeMS
		return tx.PutWatch(w)
	}
	return tx.DeleteWatch(w.Circle, w.Device, w.Watcher)
}

// tellWatchEnded sends watch_ended to the watcher's phones and tablets once the transaction
// has committed.
func (s *Server) tellWatchEnded(q *request, tx store.Tx, w store.Watch, reason string) error {
	devs, err := phonesOf(tx, w.Watcher)
	if err != nil {
		return err
	}
	ev := watchEnded(w, reason)
	q.afterCommit(func() { s.tellDevices(devs, ev) })
	return nil
}

func watchEnded(w store.Watch, reason string) map[string]any {
	return map[string]any{"type": "watch_ended", "circle_id": b64(w.Circle), "watched_device_id": b64(w.Device), "reason": reason}
}

// phonesOf lists an account's phones and tablets.
func phonesOf(tx store.Tx, account []byte) ([]store.Device, error) {
	devs, err := tx.DevicesOf(account)
	return slices.DeleteFunc(devs, func(d store.Device) bool { return !allowed(d.Kind, phone) }), err
}

// endWatches ends the watches an append has made invalid (PROTOCOL.md §14.1): those on a
// device that left the circle, which tells the watcher, and those of a watcher whose
// account left, which tells nobody. What the watched account ended stays until the sweep
// takes it, so that a device or a watcher that comes back can't revive it with an old grant.
func (s *Server) endWatches(q *request, tx store.Tx, circle []byte, ns *memberlog.State) error {
	ws, err := tx.WatchesIn(circle)
	if err != nil {
		return err
	}
	for _, w := range ws {
		gone, member := ns.Device(w.Device) == nil, ns.Member(w.Watcher) != nil
		if (!gone && member) || w.Revoked {
			continue
		}
		if err := dropWatch(tx, w, q.now); err != nil {
			return err
		}
		if gone && member {
			if err := s.tellWatchEnded(q, tx, w, "device_removed"); err != nil {
				return err
			}
		}
	}
	return nil
}

// CheckSilences is the silence check of API.md §8, which the server runs every minute. It
// ends watches whose grant has run out, and wakes, then reports, devices that have gone
// quiet: once per silence.
func (s *Server) CheckSilences() error {
	now := s.cfg.Clock.Now()
	q := &request{now: now}
	return s.update(q, func(tx store.Tx) error {
		ws, err := tx.Watches()
		if err != nil {
			return err
		}
		for _, w := range ws {
			switch {
			case w.Revoked:
				continue
			case now >= w.NotAfter:
				if err := dropWatch(tx, w, now); err != nil {
					return err
				}
				if err := s.tellWatchEnded(q, tx, w, "expired"); err != nil {
					return err
				}
				continue
			case w.Alerted || now < w.Since || now-w.Since < uint64(w.AfterMin)*minute:
				continue
			case w.WokeAt == 0:
				// A device on its stream needs no wake-up; others get a location push where
				// they can take one, otherwise a background one.
				w.WokeAt = now
				j, err := s.preparePush(tx, w.Device, push.Wake, nil, push.Location, push.Background, now)
				if err != nil {
					return err
				}
				q.afterCommit(func() { s.send([]*pushJob{j}) })
			case now < w.WokeAt || now-w.WokeAt < WakeWait:
				continue
			default:
				w.Alerted = true
				devs, err := phonesOf(tx, w.Watcher)
				if err != nil {
					return err
				}
				last, _, err := tx.LastHeard(w.Circle, w.Device)
				if err != nil {
					return err
				}
				body := push.SilenceBody(w.Circle, w.Device, last)
				var jobs []*pushJob
				for _, d := range devs {
					j, err := s.preparePush(tx, d.ID, push.Silence, body, push.Alert, push.Alert, now)
					if err != nil {
						return err
					}
					jobs = append(jobs, j)
				}
				q.afterCommit(func() { s.alert(devs, body, now); s.send(jobs) })
			}
			if err := tx.PutWatch(w); err != nil {
				return err
			}
		}
		return nil
	})
}

// alert sends a silence push to each of the watcher's devices on a stream; the others get
// it by push (§12).
func (s *Server) alert(devs []store.Device, body []byte, now uint64) {
	for _, d := range devs {
		st := s.streams.of(d.ID)
		if st == nil {
			continue
		}
		if p, err := push.Build(s.cfg.Key, d.ID, push.Silence, now, body); err == nil {
			st.push(p)
		}
	}
}
