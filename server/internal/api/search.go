// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gureetk/kinfold/server/internal/store"
)

// Address search (API.md §13). The text goes to the search add-on, a Photon instance the
// operator runs beside the server, which learns the text and nothing about who asked. The
// server logs none of it.

const (
	maxSearchText  = 256
	defaultResults = 5
	maxResults     = 10
	searchTimeout  = 5 * time.Second
	maxPhotonBody  = 1 << 20
)

var langPattern = regexp.MustCompile(`^[a-z]{2}$`)

// searchClient talks to the add-on directly: no proxy and no redirects.
func searchClient() *http.Client {
	return &http.Client{Timeout: searchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 4, IdleConnTimeout: time.Minute}}
}

// place is one search result.
type place struct {
	Name    string  `json:"name"`
	Address string  `json:"address"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

var errSearchDown = &apiError{status: http.StatusServiceUnavailable, code: "unavailable", msg: "the search add-on isn't answering"}

// search is POST /v1/search.
func (s *Server) search(q *request) error {
	if s.cfg.Search == "" {
		return errNotFound
	}
	var in struct {
		Q     string    `json:"q"`
		Lang  string    `json:"lang"`
		Limit int       `json:"limit"`
		Near  []float64 `json:"near"`
	}
	if err := q.json(&in); err != nil {
		return err
	}
	if err := s.cfg.Store.View(func(tx store.Tx) error { return s.session(q, tx, phoneOrWeb) }); err != nil {
		return err
	}
	if ok, wait := s.limiter.allow("search/"+string(q.dev.ID), s.limiter.limits.SearchPerMinute, minute, q.now); !ok {
		return rateLimited(wait)
	}
	switch {
	case len(in.Q) > maxSearchText:
		return tooLarge()
	case strings.TrimSpace(in.Q) == "" || !plainText(in.Q):
		return badRequest("q is the text to search for, without control characters")
	case in.Lang != "" && !langPattern.MatchString(in.Lang):
		return badRequest("lang is a two-letter language code")
	case in.Limit < 0 || in.Limit > maxResults:
		return badRequest("limit is 1 to 10")
	case in.Near != nil && (len(in.Near) != 2 || math.Abs(in.Near[0]) > 90 || math.Abs(in.Near[1]) > 180):
		return badRequest("near is [lat, lon] in degrees")
	}
	results, err := s.photon(q.r.Context(), in.Q, in.Lang, cmp.Or(in.Limit, defaultResults), in.Near)
	if err != nil {
		return errSearchDown // the error would quote the text: it goes nowhere
	}
	writeJSON(q.w, http.StatusOK, map[string]any{"results": results})
	return nil
}

func plainText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7F })
}

// photon asks the add-on (Photon's /api) and turns its GeoJSON into results. A language the
// add-on's index wasn't built with is dropped rather than failing the search.
func (s *Server) photon(ctx context.Context, text, lang string, limit int, near []float64) ([]place, error) {
	v := url.Values{"q": {text}, "limit": {strconv.Itoa(limit)}}
	if lang != "" {
		v.Set("lang", lang)
	}
	if near != nil {
		v.Set("lat", strconv.FormatFloat(near[0], 'f', -1, 64))
		v.Set("lon", strconv.FormatFloat(near[1], 'f', -1, 64))
	}
	body, status, err := s.photonGet(ctx, v)
	if err == nil && status == http.StatusBadRequest && lang != "" {
		v.Del("lang")
		body, status, err = s.photonGet(ctx, v)
	}
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("the add-on refused the search")
	}
	var fc struct {
		Features []struct {
			Geometry struct {
				Coordinates []float64 `json:"coordinates"`
			} `json:"geometry"`
			Properties map[string]any `json:"properties"`
		} `json:"features"`
	}
	if err := json.Unmarshal(body, &fc); err != nil {
		return nil, err
	}
	results := []place{}
	for _, f := range fc.Features {
		c := f.Geometry.Coordinates
		if len(c) < 2 || math.Abs(c[0]) > 180 || math.Abs(c[1]) > 90 {
			continue
		}
		name, address := describe(f.Properties)
		if name == "" {
			continue
		}
		results = append(results, place{Name: name, Address: address, Lat: c[1], Lon: c[0]})
		if len(results) == limit {
			break
		}
	}
	return results, nil
}

func (s *Server) photonGet(ctx context.Context, v url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.Search+"/api?"+v.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := s.searcher.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPhotonBody+1))
	if err == nil && len(body) > maxPhotonBody {
		err = errors.New("the add-on's answer is too long")
	}
	return body, resp.StatusCode, err
}

// describe names a result and writes its address: house number and street, then the place
// it is in, the state and the country, as the add-on knows them, without repeating the name.
// A house without a name is named by its street address.
func describe(p map[string]any) (name, address string) {
	str := func(k string) string { s, _ := p[k].(string); return strings.TrimSpace(s) }
	street := strings.TrimSpace(str("housenumber") + " " + str("street"))
	name = cmp.Or(str("name"), street)
	var parts []string
	for _, part := range []string{street, cmp.Or(str("city"), str("locality"), str("district")), str("state"), str("country")} {
		if part != "" && part != name && !slices.Contains(parts, part) {
			parts = append(parts, part)
		}
	}
	return name, strings.Join(parts, ", ")
}
