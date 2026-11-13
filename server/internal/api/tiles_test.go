// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/gureetk/kinfold/server/internal/api"
	"github.com/gureetk/kinfold/server/internal/tiles"
	"github.com/gureetk/kinfold/server/internal/tiles/tilestest"
)

// mapLibrary is a library with the regions given, each from a fresh archive.
func mapLibrary(t *testing.T, regions map[string][]byte) *tiles.Library {
	t.Helper()
	lib, err := tiles.Open(filepath.Join(t.TempDir(), "tiles"))
	if err != nil {
		t.Fatal(err)
	}
	for id, a := range regions {
		src := filepath.Join(t.TempDir(), id+".pmtiles")
		if err := os.WriteFile(src, a, 0o600); err != nil {
			t.Fatal(err)
		}
		if id == "coarse" {
			_, err = lib.SetCoarse(src, 1_793_000_000_000)
		} else {
			_, err = lib.Add(id, "British Columbia", src, 1_793_000_000_000)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return lib
}

func (l *live) get(path string, token []byte, header map[string]string) *fetched {
	l.t.Helper()
	req, err := http.NewRequest("GET", l.base+path, nil)
	if err != nil {
		l.t.Fatal(err)
	}
	if token != nil {
		req.Header.Set("Authorization", "Bearer "+b64(token))
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		l.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return &fetched{resp, body}
}

// fetched is a response over the network, with its body read.
type fetched struct {
	*http.Response
	body []byte
}

// Maps (API.md §13): the list, a region whole or resumed, never a part of one, and the
// coarse archive for anyone. Over a real listener, so the download's deadline is set too.
func TestTiles(t *testing.T) {
	bc := [4]float64{-139.1, 48.2, -114.0, 60.0}
	region, coarse := tilestest.Archive(0, 15, bc, 8<<20), tilestest.Archive(0, 13, bc, 8<<10) // the region outgrows socket buffers
	lib := mapLibrary(t, map[string][]byte{"bc": region, "coarse": coarse})
	l := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) { c.Tiles = lib })
	phone, web := l.login(byLabel(l.devs, "maya/phone")), l.login(byLabel(l.devs, "jordan/web"))
	sum := sha256.Sum256(region)
	etag := `"` + b64(sum[:]) + `"`

	expect(t, l.do(call{method: "GET", path: "/v1/tiles"}), http.StatusUnauthorized, "unauthorized")
	list := decode(t, l.do(call{method: "GET", path: "/v1/tiles", token: web}))
	regions := list["regions"].([]any)
	r := regions[0].(map[string]any)
	if len(regions) != 1 || r["id"] != "bc" || r["name"] != "British Columbia" || r["minzoom"] != 0.0 || r["maxzoom"] != 15.0 ||
		r["size"] != float64(len(region)) || r["sha256"] != b64(sum[:]) || r["updated_at"] != 1_793_000_000_000.0 ||
		!slices.Equal(floats(r["bbox"]), bc[:]) || list["attribution"] != "© OpenStreetMap contributors" {
		t.Fatalf("the list: %v", list)
	}
	if disc := decode(t, l.do(call{method: "GET", path: "/.well-known/kinfold"})); !slices.Contains(disc["features"].([]any), any("tiles")) {
		t.Fatalf("features: %v", disc["features"])
	}

	// A region, whole, to any device with a session.
	if res := l.get("/tiles/bc.pmtiles", nil, nil); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without a session: %d", res.StatusCode)
	}
	for _, tok := range [][]byte{phone, web} {
		res := l.get("/tiles/bc.pmtiles", tok, nil)
		if res.StatusCode != http.StatusOK || !bytes.Equal(res.body, region) || res.Header.Get("ETag") != etag ||
			res.Header.Get("Content-Type") != "application/octet-stream" {
			t.Fatalf("whole: %d, %d bytes, %v", res.StatusCode, len(res.body), res.Header)
		}
	}
	// Resumed from an offset, if the file is still the one the app began with.
	res := l.get("/tiles/bc.pmtiles", phone, map[string]string{"Range": "bytes=1000-", "If-Range": etag})
	if res.StatusCode != http.StatusPartialContent || !bytes.Equal(res.body, region[1000:]) ||
		res.Header.Get("Content-Range") != "bytes 1000-"+strconv.Itoa(len(region)-1)+"/"+strconv.Itoa(len(region)) {
		t.Fatalf("resumed: %d %v", res.StatusCode, res.Header)
	}
	if res := l.get("/tiles/bc.pmtiles", phone, map[string]string{"Range": "bytes=1000-", "If-Range": `"older"`}); res.StatusCode != http.StatusOK ||
		!bytes.Equal(res.body, region) {
		t.Fatalf("resumed after a change: %d", res.StatusCode)
	}
	if res := l.get("/tiles/bc.pmtiles", phone, map[string]string{"If-None-Match": etag}); res.StatusCode != http.StatusNotModified {
		t.Fatalf("unchanged: %d", res.StatusCode)
	}
	if res := l.get("/tiles/bc.pmtiles", phone, map[string]string{"Range": "bytes=" + strconv.Itoa(len(region)) + "-"}); res.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("past the end: %d", res.StatusCode)
	}
	// Never a part of a region, from a phone or a browser.
	for _, rng := range []string{"bytes=0-16383", "bytes=-100", "bytes=0-,1000-", "bytes=x-", "bytes=-", "items=0-", "bytes= 5-"} {
		for _, tok := range [][]byte{phone, web} {
			if res := l.get("/tiles/bc.pmtiles", tok, map[string]string{"Range": rng}); res.StatusCode != http.StatusBadRequest {
				t.Errorf("Range %s: %d", rng, res.StatusCode)
			}
		}
	}
	head, err := http.NewRequest("HEAD", l.base+"/tiles/bc.pmtiles", nil)
	if err != nil {
		t.Fatal(err)
	}
	head.Header.Set("Authorization", "Bearer "+b64(phone))
	if resp, err := http.DefaultClient.Do(head); err != nil || resp.StatusCode != http.StatusOK ||
		resp.ContentLength != int64(len(region)) {
		t.Fatalf("HEAD: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}
	for _, path := range []string{"/tiles/on.pmtiles", "/tiles/bc", "/tiles/index.json", "/tiles/" + b64(sum[:]) + ".pmtiles"} {
		if res := l.get(path, phone, nil); res.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", path, res.StatusCode)
		}
	}

	// The coarse archive needs no session and answers any range.
	if res := l.get("/tiles/coarse.pmtiles", nil, nil); res.StatusCode != http.StatusOK || !bytes.Equal(res.body, coarse) {
		t.Fatalf("coarse: %d", res.StatusCode)
	}
	if res := l.get("/tiles/coarse.pmtiles", nil, map[string]string{"Range": "bytes=127-4095"}); res.StatusCode != http.StatusPartialContent ||
		!bytes.Equal(res.body, coarse[127:4096]) {
		t.Fatalf("a part of the coarse archive: %d", res.StatusCode)
	}

	// A region replaced while a download is under way: the download finishes on the old
	// file, and the next starts on the new one.
	newer := tilestest.Archive(0, 15, bc, 32<<10)
	src := filepath.Join(t.TempDir(), "newer.pmtiles")
	os.WriteFile(src, newer, 0o600)
	req, _ := http.NewRequest("GET", l.base+"/tiles/bc.pmtiles", nil)
	req.Header.Set("Authorization", "Bearer "+b64(phone))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 100)
	io.ReadFull(resp.Body, first)
	if _, err := lib.Add("bc", "British Columbia", src, 1_794_000_000_000); err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(append(first, rest...), region) {
		t.Fatal("the download under way changed")
	}
	if res := l.get("/tiles/bc.pmtiles", phone, nil); !bytes.Equal(res.body, newer) {
		t.Fatal("the next download isn't the new file")
	}
}

func floats(v any) []float64 {
	var out []float64
	for _, x := range v.([]any) {
		out = append(out, x.(float64))
	}
	return out
}

// Without regions, the list is empty, nothing is served and discovery doesn't offer tiles.
func TestNoTiles(t *testing.T) {
	l := newLive(t, generous, api.StreamTimes{})
	tok := l.login(byLabel(l.devs, "maya/phone"))
	if list := decode(t, l.do(call{method: "GET", path: "/v1/tiles", token: tok})); len(list["regions"].([]any)) != 0 {
		t.Fatalf("%v", list)
	}
	for _, path := range []string{"/tiles/bc.pmtiles", "/tiles/coarse.pmtiles"} {
		expect(t, l.do(call{method: "GET", path: path, token: tok}), http.StatusNotFound, "not_found")
	}
	if disc := decode(t, l.do(call{method: "GET", path: "/.well-known/kinfold"})); slices.Contains(disc["features"].([]any), any("tiles")) {
		t.Fatal("tiles offered")
	}
}
