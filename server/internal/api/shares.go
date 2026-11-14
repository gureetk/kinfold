// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"embed"
	"errors"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// Share links (API.md §11, PROTOCOL.md §12).

const (
	ShareMaxLife   = 24 * hour
	maxShareUpdate = 2 << 10
	shareAADLen    = 1 + 16 + 8 + 8 // version, link ID, seq, expires_at
)

var errStaleUpdate = &apiError{status: http.StatusConflict, code: "stale_update", msg: "the server has an update with this seq or a higher one"}

// The viewer page: the same static files for every link.
//
//go:embed viewer/index.html viewer/viewer.js viewer/share.js viewer/viewer.css
var viewerFiles embed.FS

// viewerCSP lets the page load its scripts and styles from this server and talk to it,
// and nothing else (API.md §11).
const viewerCSP = "default-src 'none'; script-src 'self'; style-src 'self'; worker-src 'self'; connect-src 'self'; " +
	"img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// createShare is POST /v1/shares: a share link from this device.
func (s *Server) createShare(q *request) error {
	var in struct {
		LinkID    b64    `json:"link_id"`
		ExpiresAt uint64 `json:"expires_at"`
	}
	if err := q.json(&in); err != nil {
		return err
	}
	if len(in.LinkID) != 16 {
		return badRequest("link_id is 16 bytes")
	}
	if in.ExpiresAt <= q.now || in.ExpiresAt-q.now > ShareMaxLife {
		return badRequest("expires_at must be in the future and at most 24 hours away")
	}
	err := s.cfg.Store.Update(func(tx store.Tx) error {
		if err := s.session(q, tx, phone); err != nil {
			return err
		}
		if old, err := tx.Share(in.LinkID); err == nil {
			if bytes.Equal(old.Device, q.dev.ID) && old.ExpiresAt == in.ExpiresAt && !old.Ended {
				return nil // the same link again
			}
			return &apiError{status: http.StatusConflict, code: "slot_taken", msg: "that link ID is in use"}
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		mine, err := tx.SharesOf(q.dev.ID)
		if err != nil {
			return err
		}
		open, soonest := 0, uint64(0)
		for _, sh := range mine {
			if !sh.Ended && q.now < sh.ExpiresAt {
				open++
				if soonest == 0 || sh.ExpiresAt < soonest {
					soonest = sh.ExpiresAt
				}
			}
		}
		if open >= s.limits().SharesPerDevice {
			return rateLimited(int((soonest - q.now + 999) / 1000))
		}
		return tx.PutShare(store.Share{ID: in.LinkID, Account: q.dev.Account, Device: q.dev.ID, ExpiresAt: in.ExpiresAt})
	})
	if err != nil {
		return err
	}
	writeJSON(q.w, http.StatusCreated, map[string]any{})
	return nil
}

// shareLive finds a share link that hasn't ended.
func shareLive(tx store.Tx, id []byte, now uint64) (store.Share, error) {
	sh, err := tx.Share(id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return sh, errNotFound
	case err != nil:
		return sh, err
	case sh.Ended || now >= sh.ExpiresAt:
		return sh, errGone
	}
	return sh, nil
}

// postShareUpdate is POST /v1/shares/{link_id}/updates, from the device that made the link.
// The server keeps only the newest update.
func (s *Server) postShareUpdate(q *request) error {
	id, err := q.pathID("link_id")
	if err != nil {
		return err
	}
	raw, err := q.body(maxShareUpdate)
	if err != nil {
		return err
	}
	err = s.cfg.Store.Update(func(tx store.Tx) error {
		if err := s.session(q, tx, phone); err != nil {
			return err
		}
		sh, err := shareLive(tx, id, q.now)
		if err != nil {
			return err
		}
		if !bytes.Equal(sh.Device, q.dev.ID) {
			return errForbidden
		}
		if ok, wait := s.limiter.allow("share/"+string(id), 1, 5*second, q.now); !ok {
			return rateLimited(wait)
		}
		seq, ok := shareUpdate(raw, sh)
		switch {
		case !ok:
			return refused("malformed", nil)
		case bytes.Equal(raw, sh.Update):
			return nil // the same update again
		case sh.Update != nil && seq <= sh.Seq:
			return errStaleUpdate
		}
		sh.Update, sh.Seq = raw, seq
		return tx.PutShare(sh)
	})
	if err != nil {
		return err
	}
	s.waits.wake("share/" + string(id))
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

// shareUpdate reads what the server can see of a ShareUpdate: version 0, the link's ID, a
// seq, the link's own expires_at, a nonce and a ciphertext, nothing after.
func shareUpdate(raw []byte, sh store.Share) (uint64, bool) {
	r := wire.NewReader(raw)
	ver, id, seq, expires := r.U8(), r.Take(16), r.U64(), r.U64()
	r.Take(12)
	ct := r.Vec32()
	return seq, r.Done() && ver == identity.Version && bytes.Equal(id, sh.ID) && expires == sh.ExpiresAt && len(ct) > 0
}

// shareOwn finds a share link of the session's account, ended or not.
func (s *Server) shareOwn(q *request, tx store.Tx, id []byte) (store.Share, error) {
	if err := s.session(q, tx, phone); err != nil {
		return store.Share{}, err
	}
	sh, err := tx.Share(id)
	if errors.Is(err, store.ErrNotFound) {
		return sh, errNotFound
	} else if err != nil {
		return sh, err
	}
	if !bytes.Equal(sh.Account, q.dev.Account) {
		return sh, errForbidden
	}
	return sh, nil
}

// getShare is GET /v1/shares/{link_id}: how often the link was opened.
func (s *Server) getShare(q *request) error {
	id, err := q.pathID("link_id")
	if err != nil {
		return err
	}
	var sh store.Share
	if err := s.cfg.Store.View(func(tx store.Tx) (err error) { sh, err = s.shareOwn(q, tx, id); return }); err != nil {
		return err
	}
	writeJSON(q.w, http.StatusOK, map[string]any{"expires_at": sh.ExpiresAt, "views": sh.Views, "last_view_at": sh.LastView})
	return nil
}

// deleteShare is DELETE /v1/shares/{link_id}: the link ends at once, and its update goes.
func (s *Server) deleteShare(q *request) error {
	id, err := q.pathID("link_id")
	if err != nil {
		return err
	}
	err = s.cfg.Store.Update(func(tx store.Tx) error {
		sh, err := s.shareOwn(q, tx, id)
		if err != nil {
			return err
		}
		sh.Ended, sh.Update = true, nil
		return tx.PutShare(sh)
	})
	if err != nil {
		return err
	}
	s.waits.wake("share/" + string(id)) // waiting viewers learn it has ended
	q.w.WriteHeader(http.StatusNoContent)
	return nil
}

// latestShare is GET /v1/shares/{link_id}/latest?after=&wait=, for the viewer page: the
// newest update if its seq is above after.
func (s *Server) latestShare(q *request) error {
	id, err := q.pathID("link_id")
	if err != nil {
		return err
	}
	var after uint64
	if v := q.r.URL.Query().Get("after"); v != "" {
		if after, err = strconv.ParseUint(v, 10, 64); err != nil {
			return badRequest("bad after")
		}
	}
	wait := 0
	if v := q.r.URL.Query().Get("wait"); v != "" {
		if wait, err = strconv.Atoi(v); err != nil || wait < 0 {
			return badRequest("bad wait")
		}
	}
	deadline := time.Now().Add(time.Duration(min(wait, MaxWaitSeconds)) * time.Second)
	for {
		woken := s.waits.wait("share/" + string(id)) // before reading, so no update is missed
		var sh store.Share
		err := s.cfg.Store.View(func(tx store.Tx) (err error) {
			sh, err = shareLive(tx, id, s.cfg.Clock.Now())
			return err
		})
		if err != nil {
			return err
		}
		if sh.Update != nil && sh.Seq > after {
			writeBytes(q.w, http.StatusOK, sh.Update)
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

// viewerPage is GET /s/{link_id}: the viewer page, the same for every link. A load of a
// live link counts as a view, and the device that made the link hears of it.
func (s *Server) viewerPage(q *request) error {
	if id, err := wire.DecodeB64u(q.r.PathValue("link_id")); err == nil && len(id) == 16 {
		s.countView(q, id)
	}
	return s.viewerFile(q.w, "index.html")
}

// countView counts a view of a live link: at most 60 a minute per link, so that loading
// the page in a loop can't flood the sharer's phone.
func (s *Server) countView(q *request, id []byte) {
	if ok, _ := s.limiter.allow("view/"+string(id), 60, minute, q.now); !ok {
		return
	}
	var sh store.Share
	err := s.cfg.Store.Update(func(tx store.Tx) error {
		var err error
		if sh, err = shareLive(tx, id, q.now); err != nil {
			return err
		}
		sh.Views++
		sh.LastView = q.now
		return tx.PutShare(sh)
	})
	if err == nil {
		s.tellDevices([]store.Device{{ID: sh.Device}}, map[string]any{"type": "share_view", "link_id": b64(id), "views": sh.Views})
	}
}

// viewerAsset is GET /assets/{name}: the viewer's script and styles.
func (s *Server) viewerAsset(q *request) error {
	return s.viewerFile(q.w, q.r.PathValue("name"))
}

func (s *Server) viewerFile(w http.ResponseWriter, name string) error {
	types := map[string]string{".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
		".css": "text/css; charset=utf-8"}
	b, err := viewerFiles.ReadFile("viewer/" + name)
	if err != nil || types[path.Ext(name)] == "" {
		return errNotFound
	}
	h := w.Header()
	h.Set("Content-Type", types[path.Ext(name)])
	h.Set("Content-Security-Policy", viewerCSP)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	w.Write(b)
	return nil
}
