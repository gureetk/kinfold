// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gureetk/kinfold/server/internal/api"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// shareUpdate builds a ShareUpdate the server can check; it can't read the ciphertext.
func shareUpdate(id []byte, seq, expiresAt uint64) []byte {
	return wire.Concat([]byte{0}, id, wire.U64(seq), wire.U64(expiresAt), make([]byte, 12),
		wire.Vec32(bytes.Repeat([]byte{byte(seq)}, 272)))
}

func TestShares(t *testing.T) {
	l := newLive(t, generous, api.StreamTimes{})
	sl := tv.Obj(tv.Load(t)["share_link"])
	id, update := tv.Hex(sl["link_id"]), tv.Hex(tv.Obj(sl["update"])["message"])
	expires := tv.Num(tv.Obj(sl["update"])["expires_at"])
	l.clk.Set(expires - 3_600_000)
	jordan, tablet, alex := byLabel(l.devs, "jordan/phone"), byLabel(l.devs, "jordan/tablet"), byLabel(l.devs, "alex/phone")
	tok := l.login(jordan)
	path := "/v1/shares/" + b64(id)
	create := func(id []byte, expires uint64, tok []byte) *httptest.ResponseRecorder {
		return l.json("POST", "/v1/shares", map[string]any{"link_id": b64(id), "expires_at": expires}, tok)
	}
	post := func(raw, tok []byte) *httptest.ResponseRecorder {
		rec := l.octets("POST", path+"/updates", raw, tok)
		l.clk.Advance(5_000) // one update every 5 seconds
		return rec
	}
	latest := func(after string) *httptest.ResponseRecorder {
		return l.do(call{method: "GET", path: path + "/latest?after=" + after})
	}

	expect(t, create(id, l.clk.Now()+api.ShareMaxLife+1, tok), http.StatusBadRequest, "bad_request")
	expect(t, create(id, expires, tok), http.StatusCreated, "")
	expect(t, create(id, expires, tok), http.StatusCreated, "") // the same again
	expect(t, create(id, expires-1, tok), http.StatusConflict, "slot_taken")
	expect(t, latest("0"), http.StatusNoContent, "")

	// Only the device that made the link posts to it, and only well-formed updates.
	expect(t, post(update, l.login(tablet)), http.StatusForbidden, "forbidden")
	expect(t, post(shareUpdate(id, 1, expires-1), tok), http.StatusUnprocessableEntity, "malformed")
	expect(t, post(shareUpdate(bytes.Repeat([]byte{1}, 16), 1, expires), tok), http.StatusUnprocessableEntity, "malformed")
	expect(t, post(make([]byte, 2049), tok), http.StatusRequestEntityTooLarge, "too_large")
	expect(t, l.octets("POST", path+"/updates", update, tok), http.StatusNoContent, "")
	expect(t, l.octets("POST", path+"/updates", update, tok), http.StatusTooManyRequests, "rate_limited") // at once
	l.clk.Advance(5_000)
	expect(t, post(update, tok), http.StatusNoContent, "") // the same again
	expect(t, post(shareUpdate(id, 1, expires), tok), http.StatusConflict, "stale_update")

	// The viewer's call: the newest update above after, or nothing.
	if rec := latest("0"); rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), update) {
		t.Fatalf("latest: %d", rec.Code)
	}
	expect(t, latest("1"), http.StatusNoContent, "")
	done := make(chan *httptest.ResponseRecorder)
	go func() { done <- l.do(call{method: "GET", path: path + "/latest?after=1&wait=10"}) }()
	time.Sleep(100 * time.Millisecond)
	second := shareUpdate(id, 2, expires)
	expect(t, post(second, tok), http.StatusNoContent, "")
	select {
	case rec := <-done:
		if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), second) {
			t.Fatalf("waiting viewer: %d", rec.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting viewer wasn't woken")
	}

	// Opening the page counts a view, and the sharing phone hears of it.
	cj, _, _ := l.open(jordan, "")
	page := l.do(call{method: "GET", path: "/s/" + b64(id)})
	h := page.Header()
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "/assets/viewer.js") ||
		!strings.Contains(h.Get("Content-Security-Policy"), "connect-src 'self'") ||
		!strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") || h.Get("Referrer-Policy") != "no-referrer" ||
		h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("the viewer page: %d %v", page.Code, h)
	}
	if ev := awaitEvent(t, cj); ev["type"] != "share_view" || ev["link_id"] != b64(id) || ev["views"] != float64(1) {
		t.Fatalf("share_view: %v", ev)
	}
	info := decode(t, l.do(call{method: "GET", path: path, token: tok}))
	if info["views"] != float64(1) || info["last_view_at"] != float64(l.clk.Now()) || info["expires_at"] != float64(expires) {
		t.Errorf("share: %v", info)
	}
	expect(t, l.do(call{method: "GET", path: path, token: l.login(alex)}), http.StatusForbidden, "forbidden")
	if js := l.do(call{method: "GET", path: "/assets/share.js"}); js.Code != http.StatusOK ||
		!strings.HasPrefix(js.Header().Get("Content-Type"), "text/javascript") {
		t.Errorf("the script: %d %s", js.Code, js.Header().Get("Content-Type"))
	}
	expect(t, l.do(call{method: "GET", path: "/assets/share_test.mjs"}), http.StatusNotFound, "not_found")

	// Deleting ends it at once, for everyone.
	expect(t, l.do(call{method: "DELETE", path: path, token: l.login(alex)}), http.StatusForbidden, "forbidden")
	expect(t, l.do(call{method: "DELETE", path: path, token: tok}), http.StatusNoContent, "")
	expect(t, latest("0"), http.StatusGone, "gone")
	expect(t, post(shareUpdate(id, 3, expires), tok), http.StatusGone, "gone")
	l.do(call{method: "GET", path: "/s/" + b64(id)})
	if info := decode(t, l.do(call{method: "GET", path: path, token: tok})); info["views"] != float64(1) {
		t.Errorf("an ended link counted a view: %v", info)
	}

	// Five open links per device.
	for i := range 5 {
		expect(t, create(bytes.Repeat([]byte{byte(i)}, 16), expires, tok), http.StatusCreated, "")
	}
	expect(t, create(bytes.Repeat([]byte{9}, 16), expires, tok), http.StatusTooManyRequests, "rate_limited")
}

// The viewer's cryptography passes the vectors' share_link group, run by Node when it is
// installed.
func TestViewerScript(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node isn't installed")
	}
	vec, err := tv.Path()
	if err != nil {
		t.Fatal(err)
	}
	vec, _ = filepath.Abs(vec)
	cmd := exec.Command(node, "share_test.mjs", vec)
	cmd.Dir = "viewer"
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("share_test.mjs: %v\n%s", err, out)
	}
	// viewer.js at least parses as a module.
	src, err := os.ReadFile("viewer/viewer.js")
	if err != nil {
		t.Fatal(err)
	}
	mod := filepath.Join(t.TempDir(), "viewer.mjs")
	if err := os.WriteFile(mod, src, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(node, "--check", mod).CombinedOutput(); err != nil {
		t.Fatalf("viewer.js: %v\n%s", err, out)
	}
}
