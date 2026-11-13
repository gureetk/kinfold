// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/tiles"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// Maps (API.md §13). Apps download a region whole and draw it from the phone, so the server
// learns which regions a phone holds and nothing about what it looks at. The share viewer
// reads the coarse archive as it goes.

// minRate is the slowest download the server waits for: a region's response may take a
// minute plus a second for every 32 KiB of the file.
const minRate = 32 << 10

// listTiles is GET /v1/tiles.
func (s *Server) listTiles(q *request) error {
	if err := s.cfg.Store.View(func(tx store.Tx) error { return s.session(q, tx, anyDevice) }); err != nil {
		return err
	}
	regions := []map[string]any{}
	if s.cfg.Tiles != nil {
		for _, r := range s.cfg.Tiles.Regions() {
			regions = append(regions, map[string]any{"id": r.ID, "name": r.Name, "bbox": r.Bounds, "minzoom": r.MinZoom,
				"maxzoom": r.MaxZoom, "size": r.Size, "sha256": b64(r.Sum()), "updated_at": r.UpdatedAt})
		}
	}
	writeJSON(q.w, http.StatusOK, map[string]any{"regions": regions, "attribution": tiles.Attribution})
	return nil
}

// tileFile is GET /tiles/{file}: a region, for a device, whole or from an offset to its end
// (in any range for a web device, if the operator allows it); or the coarse archive, for
// anyone, in any range.
func (s *Server) tileFile(q *request) error {
	name, ok := strings.CutSuffix(q.r.PathValue("file"), ".pmtiles")
	if !ok || s.cfg.Tiles == nil {
		return errNotFound
	}
	var r tiles.Region
	if name == "coarse" {
		r, ok = s.cfg.Tiles.Coarse()
	} else {
		var st store.Settings
		err := s.cfg.Store.View(func(tx store.Tx) error {
			if err := s.session(q, tx, anyDevice); err != nil {
				return err
			}
			var err error
			st, err = tx.Settings()
			return err
		})
		if err != nil {
			return err
		}
		r, ok = s.cfg.Tiles.Region(name)
		browser := q.dev.Kind == identity.Web && st.WebTileRanges // a browser can't hold a region
		if ok && !browser && !wholeOrRest(q.r.Header.Get("Range")) {
			return badRequest("a region is read whole, or from an offset to its end (Range: bytes=N-)")
		}
	}
	if !ok {
		return errNotFound
	}
	f, err := s.cfg.Tiles.Open(r)
	if err != nil {
		return errNotFound // replaced or removed since it was looked up
	}
	defer f.Close()
	// The server's write timeout is a minute; a region can take hours on a slow line.
	http.NewResponseController(q.w).SetWriteDeadline(time.Now().Add(time.Minute + time.Duration(r.Size/minRate)*time.Second))
	h := q.w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("ETag", `"`+wire.EncodeB64u(r.Sum())+`"`)
	http.ServeContent(q.w, q.r, "", time.Time{}, f) // Range, If-Range, If-None-Match and HEAD
	return nil
}

// wholeOrRest says whether a Range header asks for no range or for one that runs from an
// offset to the end: the only reads of a region the server answers (API.md §13).
func wholeOrRest(h string) bool {
	if h == "" {
		return true
	}
	n, ok := strings.CutPrefix(h, "bytes=")
	n, ok2 := strings.CutSuffix(n, "-")
	return ok && ok2 && n != "" && strings.Trim(n, "0123456789") == ""
}
