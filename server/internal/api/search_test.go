// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/gureetk/kinfold/server/internal/api"
)

// photonAnswer is what Photon's /api says to a few searches.
const photonAnswer = `{"type": "FeatureCollection", "features": [
 {"type": "Feature", "geometry": {"type": "Point", "coordinates": [-79.3871, 43.6426]},
  "properties": {"name": "CN Tower", "housenumber": "290", "street": "Bremner Boulevard", "city": "Toronto",
   "state": "Ontario", "country": "Canada", "countrycode": "CA", "osm_key": "tourism", "osm_id": 3}},
 {"type": "Feature", "geometry": {"type": "Point", "coordinates": [-79.3839, 43.6535]},
  "properties": {"name": "Toronto", "state": "Ontario", "country": "Canada", "osm_key": "place"}},
 {"type": "Feature", "geometry": {"type": "Point", "coordinates": [-79.4, 43.66]},
  "properties": {"housenumber": "12", "street": "Oak Avenue", "city": "Toronto", "state": "Ontario", "country": "Canada"}},
 {"type": "Feature", "geometry": {"type": "Point", "coordinates": [-79.4]}, "properties": {"name": "no position"}},
 {"type": "Feature", "geometry": {"type": "Point", "coordinates": [-79.4, 43.66]}, "properties": {}}
]}`

// fakePhoton answers /api as answer says, and keeps every query it gets.
type fakePhoton struct {
	*httptest.Server
	mu      sync.Mutex
	queries []neturl.Values
	answer  func(neturl.Values) (int, string)
}

func newFakePhoton(t *testing.T) *fakePhoton {
	p := &fakePhoton{answer: func(neturl.Values) (int, string) { return http.StatusOK, photonAnswer }}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		p.mu.Lock()
		p.queries = append(p.queries, r.URL.Query())
		answer := p.answer
		p.mu.Unlock()
		status, body := answer(r.URL.Query())
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *fakePhoton) last() neturl.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.queries) == 0 {
		return nil
	}
	return p.queries[len(p.queries)-1]
}

func (p *fakePhoton) setAnswer(f func(neturl.Values) (int, string)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.answer = f
}

// Search (API.md §13): the text, language, limit and bias go to the add-on; its answer comes
// back as names, addresses and positions; and only phones, tablets and web devices may ask.
func TestSearch(t *testing.T) {
	photon := newFakePhoton(t)
	l := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) { c.Search = photon.URL })
	phone := l.login(byLabel(l.devs, "maya/phone"))
	search := func(body map[string]any, tok []byte) map[string]any {
		t.Helper()
		return decode(t, l.json("POST", "/v1/search", body, tok))
	}
	if disc := decode(t, l.do(call{method: "GET", path: "/.well-known/kinfold"})); !slices.Contains(disc["features"].([]any), any("search")) {
		t.Fatalf("features: %v", disc["features"])
	}

	out := search(map[string]any{"q": "cn tower", "lang": "en", "near": []float64{43.65, -79.38}}, phone)
	want := []any{
		map[string]any{"name": "CN Tower", "address": "290 Bremner Boulevard, Toronto, Ontario, Canada", "lat": 43.6426, "lon": -79.3871},
		map[string]any{"name": "Toronto", "address": "Ontario, Canada", "lat": 43.6535, "lon": -79.3839},
		map[string]any{"name": "12 Oak Avenue", "address": "Toronto, Ontario, Canada", "lat": 43.66, "lon": -79.4},
	}
	if got := out["results"].([]any); !slices.EqualFunc(got, want, func(a, b any) bool { return equalJSON(a, b) }) {
		t.Fatalf("results: %v", got)
	}
	if q := photon.last(); q.Get("q") != "cn tower" || q.Get("lang") != "en" || q.Get("limit") != "5" ||
		q.Get("lat") != "43.65" || q.Get("lon") != "-79.38" {
		t.Fatalf("what the add-on got: %v", q)
	}
	out = search(map[string]any{"q": "toronto", "limit": 2}, l.login(byLabel(l.devs, "jordan/web")))
	if got := out["results"].([]any); len(got) != 2 {
		t.Fatalf("limit 2: %v", got)
	}
	if q := photon.last(); q.Get("limit") != "2" || q.Has("lang") || q.Has("lat") {
		t.Fatalf("what the add-on got: %v", q)
	}

	// Who may search, and what a search may hold.
	expect(t, l.json("POST", "/v1/search", map[string]any{"q": "x"}, nil), http.StatusUnauthorized, "unauthorized")
	for _, label := range []string{"jordan/ha", "jordan/recovery"} {
		expect(t, l.json("POST", "/v1/search", map[string]any{"q": "x"}, l.login(byLabel(l.devs, label))), http.StatusForbidden, "forbidden")
	}
	expect(t, l.json("POST", "/v1/search", map[string]any{"q": strings.Repeat("a", 257)}, phone), http.StatusRequestEntityTooLarge, "too_large")
	expect(t, l.json("POST", "/v1/search", map[string]any{"q": strings.Repeat("é", 128)}, phone), http.StatusOK, "")
	for _, bad := range []map[string]any{{"q": ""}, {"q": "   "}, {"q": "oak\navenue"}, {"q": "x", "lang": "eng"},
		{"q": "x", "lang": "EN"}, {"q": "x", "limit": 11}, {"q": "x", "limit": -1}, {"q": "x", "near": []float64{91, 0}},
		{"q": "x", "near": []float64{0, 181}}, {"q": "x", "near": []float64{43.6}}} {
		expect(t, l.json("POST", "/v1/search", bad, phone), http.StatusBadRequest, "bad_request")
	}

	// A language the add-on's index lacks is dropped, not refused.
	photon.setAnswer(func(q neturl.Values) (int, string) {
		if q.Has("lang") {
			return http.StatusBadRequest, `{"message": "language is not supported"}`
		}
		return http.StatusOK, photonAnswer
	})
	if out := search(map[string]any{"q": "toronto", "lang": "pa"}, phone); len(out["results"].([]any)) != 3 || photon.last().Has("lang") {
		t.Fatalf("an unknown language: %v", out)
	}

	// An add-on that fails, answers nonsense or too much is unavailable.
	for _, answer := range []func(neturl.Values) (int, string){
		func(neturl.Values) (int, string) { return http.StatusInternalServerError, "" },
		func(neturl.Values) (int, string) { return http.StatusOK, "<html>" },
		func(neturl.Values) (int, string) {
			return http.StatusOK, `{"features": [` + strings.Repeat(" ", 1<<20) + `]}`
		},
	} {
		photon.setAnswer(answer)
		expect(t, l.json("POST", "/v1/search", map[string]any{"q": "toronto"}, phone), http.StatusServiceUnavailable, "unavailable")
	}
	photon.Close()
	expect(t, l.json("POST", "/v1/search", map[string]any{"q": "toronto"}, phone), http.StatusServiceUnavailable, "unavailable")
}

func equalJSON(a, b any) bool {
	am, bm := a.(map[string]any), b.(map[string]any)
	for k, v := range bm {
		if am[k] != v {
			return false
		}
	}
	return len(am) == len(bm)
}

// 30 searches a minute per device (API.md §3); and without the add-on there is no search.
func TestSearchLimits(t *testing.T) {
	photon := newFakePhoton(t)
	limits := generous
	limits.SearchPerMinute = 2
	l := newLive(t, limits, api.StreamTimes{}, func(c *api.Config) { c.Search = photon.URL })
	phone := l.login(byLabel(l.devs, "maya/phone"))
	for range 2 {
		expect(t, l.json("POST", "/v1/search", map[string]any{"q": "toronto"}, phone), http.StatusOK, "")
	}
	expect(t, l.json("POST", "/v1/search", map[string]any{"q": "toronto"}, phone), http.StatusTooManyRequests, "rate_limited")
	expect(t, l.json("POST", "/v1/search", map[string]any{"q": "toronto"}, l.login(byLabel(l.devs, "alex/phone"))), http.StatusOK, "")
	l.clk.Set(l.clk.Now() + 60_000)
	expect(t, l.json("POST", "/v1/search", map[string]any{"q": "toronto"}, phone), http.StatusOK, "")

	none := newLive(t, generous, api.StreamTimes{})
	expect(t, none.json("POST", "/v1/search", map[string]any{"q": "toronto"}, none.login(byLabel(none.devs, "maya/phone"))),
		http.StatusNotFound, "not_found")
	if disc := decode(t, none.do(call{method: "GET", path: "/.well-known/kinfold"})); slices.Contains(disc["features"].([]any), any("search")) {
		t.Fatal("search offered without the add-on")
	}
}
