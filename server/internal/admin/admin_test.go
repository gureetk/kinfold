// SPDX-License-Identifier: AGPL-3.0-or-later

package admin_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gureetk/kinfold/server/internal/admin"
	"github.com/gureetk/kinfold/server/internal/api"
	"github.com/gureetk/kinfold/server/internal/clock"
	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/store/memstore"
	"github.com/gureetk/kinfold/server/internal/tiles"
	"github.com/gureetk/kinfold/server/internal/tiles/tilestest"
	"github.com/gureetk/kinfold/server/internal/wire"
)

const url = "https://kinfold.example.org"

func TestAdmin(t *testing.T) {
	seed := sha256.Sum256([]byte("kinfold admin test key"))
	key := ed25519.NewKeyFromSeed(seed[:])
	clk := clock.NewFake(1_793_635_200_000)
	st := memstore.New()
	h := (&admin.Admin{Store: st, Clock: clk, Key: key, URL: url}).Handler()
	call := func(method, path, body string, want int) any {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		if rec.Code != want {
			t.Fatalf("%s %s: %d %s, want %d", method, path, rec.Code, rec.Body, want)
		}
		var out any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	obj := func(v any) map[string]any { m, _ := v.(map[string]any); return m }

	// A setup code carries the server's address and key, and a token that expires with it.
	out := obj(call("POST", "/setup", ``, http.StatusCreated))
	raw, ok := identity.ParseCode("KFS0", out["code"].(string))
	s, ok2 := identity.ParseSetup(raw)
	if !ok || !ok2 || s.URL != url || !bytes.Equal(s.Key, key.Public().(ed25519.PublicKey)) ||
		s.ExpiresAt != clk.Now()+admin.DefaultSetup || out["server_key"] != wire.EncodeB64u(s.Key) {
		t.Fatalf("setup code: %v", out)
	}
	// Only the token's hash is kept.
	h1 := sha256.Sum256(s.RegToken)
	st.View(func(tx store.Tx) error {
		if _, err := tx.Token(h1[:]); err != nil {
			t.Errorf("the setup token isn't stored by its hash: %v", err)
		}
		return nil
	})

	// Tokens are listed by ID, never shown again, and revoked by ID.
	tok := obj(call("POST", "/tokens", `{"expires_in_ms": 3600000}`, http.StatusCreated))
	if tok["expires_at"] != float64(clk.Now()+3_600_000) || len(tok["token_id"].(string)) != 16 {
		t.Errorf("token: %v", tok)
	}
	list, _ := call("GET", "/tokens", ``, http.StatusOK).([]any)
	if len(list) != 2 || obj(list[1])["token"] != nil || obj(list[0])["token"] != nil {
		t.Errorf("token list: %v", list)
	}
	call("DELETE", "/tokens/"+tok["token_id"].(string), ``, http.StatusNoContent)
	call("DELETE", "/tokens/"+tok["token_id"].(string), ``, http.StatusNotFound)
	if list, _ := call("GET", "/tokens", ``, http.StatusOK).([]any); len(list) != 1 {
		t.Errorf("%d tokens after revoking one", len(list))
	}
	call("POST", "/tokens", `{"expires_in_ms": 2592000001}`, http.StatusBadRequest) // over 30 days
	call("POST", "/tokens", `{"expires_in_ms": -1}`, http.StatusBadRequest)
	call("POST", "/tokens", `not JSON`, http.StatusBadRequest)

	// Settings change one at a time.
	set := obj(call("PATCH", "/settings", `{"web_devices": true}`, http.StatusOK))
	if set["web_devices"] != true || set["member_tokens"] != false {
		t.Errorf("settings: %v", set)
	}
	set = obj(call("PATCH", "/settings", `{"member_tokens": true}`, http.StatusOK))
	if set["web_devices"] != true || set["member_tokens"] != true {
		t.Errorf("settings: %v", set)
	}

	// Repair mode lasts at most 72 hours.
	set = obj(call("POST", "/repair", `{"hours": 1000}`, http.StatusOK))
	if set["repair_until"] != float64(clk.Now()+admin.MaxRepairHours*3_600_000) {
		t.Errorf("repair: %v", set)
	}
	set = obj(call("DELETE", "/repair", ``, http.StatusOK))
	if set["repair_until"] != float64(0) {
		t.Errorf("repair after its end: %v", set)
	}

	// Operators are accounts the server has.
	call("PUT", "/operators/"+wire.EncodeB64u(make([]byte, 16)), ``, http.StatusNotFound)
	call("PUT", "/operators/not-an-id", ``, http.StatusBadRequest)
	acc := store.Account{ID: bytes.Repeat([]byte{7}, 16), IK: make([]byte, 32), CreatedAt: clk.Now()}
	st.Update(func(tx store.Tx) error { return tx.PutAccount(acc) })
	call("PUT", "/operators/"+wire.EncodeB64u(acc.ID), ``, http.StatusNoContent)
	st.View(func(tx store.Tx) error {
		if a, err := tx.Account(acc.ID); err != nil || !a.Operator {
			t.Error("the account isn't an operator")
		}
		return nil
	})
	call("DELETE", "/operators/"+wire.EncodeB64u(acc.ID), ``, http.StatusNoContent)
	st.View(func(tx store.Tx) error {
		if a, _ := tx.Account(acc.ID); a.Operator {
			t.Error("the account is still an operator")
		}
		return nil
	})
}

// The operator adds, replaces and removes regions and the coarse archive (API.md §13, §16).
func TestMaps(t *testing.T) {
	clk := clock.NewFake(1_793_635_200_000)
	lib, err := tiles.Open(filepath.Join(t.TempDir(), "tiles"))
	if err != nil {
		t.Fatal(err)
	}
	h := (&admin.Admin{Store: memstore.New(), Clock: clk, Tiles: lib}).Handler()
	call := func(method, path, body string, want int) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		if rec.Code != want {
			t.Fatalf("%s %s: %d %s, want %d", method, path, rec.Code, rec.Body, want)
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	file := func(b []byte) string {
		p := filepath.Join(t.TempDir(), "map.pmtiles")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		js, _ := json.Marshal(p)
		return string(js)
	}
	bc := [4]float64{-139.1, 48.2, -114.0, 60.0}
	a := tilestest.Archive(0, 15, bc, 4096)
	sum := sha256.Sum256(a)

	if out := call("GET", "/regions", ``, http.StatusOK); len(out["regions"].([]any)) != 0 || out["coarse"] != nil {
		t.Fatalf("an empty library: %v", out)
	}
	r := call("PUT", "/regions/bc", `{"file": `+file(a)+`, "name": "British Columbia"}`, http.StatusOK)
	if r["id"] != "bc" || r["name"] != "British Columbia" || r["sha256"] != hex.EncodeToString(sum[:]) ||
		r["size"] != float64(len(a)) || r["updated_at"] != float64(clk.Now()) {
		t.Fatalf("added: %v", r)
	}
	if got, ok := lib.Region("bc"); !ok || got.Name != "British Columbia" {
		t.Fatal("the library hasn't got it")
	}
	call("PUT", "/regions/bc", `{"file": "relative.pmtiles"}`, http.StatusBadRequest)
	call("PUT", "/regions/bc", `{"file": "/nowhere/bc.pmtiles"}`, http.StatusBadRequest)
	call("PUT", "/regions/bc", `{"file": `+file([]byte("not a map"))+`}`, http.StatusBadRequest)
	call("PUT", "/regions/coarse", `{"file": `+file(a)+`}`, http.StatusBadRequest)
	call("PUT", "/coarse", `{"file": `+file(a)+`}`, http.StatusBadRequest) // zoom 15
	c := call("PUT", "/coarse", `{"file": `+file(tilestest.Archive(0, 13, bc, 1024))+`}`, http.StatusOK)
	if c["maxzoom"] != 13.0 {
		t.Fatalf("coarse: %v", c)
	}
	if out := call("GET", "/regions", ``, http.StatusOK); len(out["regions"].([]any)) != 1 || out["coarse"] == nil {
		t.Fatalf("the list: %v", out)
	}
	call("DELETE", "/regions/bc", ``, http.StatusNoContent)
	call("DELETE", "/regions/bc", ``, http.StatusNotFound)
	call("DELETE", "/coarse", ``, http.StatusNoContent)
	call("DELETE", "/coarse", ``, http.StatusNotFound)

	// A server without a library says so.
	none := (&admin.Admin{Store: memstore.New(), Clock: clk}).Handler()
	rec := httptest.NewRecorder()
	none.ServeHTTP(rec, httptest.NewRequest("GET", "/regions", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no library: %d", rec.Code)
	}
}

// An account in no circle is removed with its devices and their sessions; without the API
// server to remove through, the admin socket says it can't.
func TestRemoveAccount(t *testing.T) {
	seed := sha256.Sum256([]byte("kinfold admin test key"))
	key := ed25519.NewKeyFromSeed(seed[:])
	clk := clock.NewFake(1_793_635_200_000)
	st := memstore.New()
	id := func(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }
	st.Update(func(tx store.Tx) error {
		tx.PutAccount(store.Account{ID: id(1), IK: id(2), CreatedAt: 1_793_000_000_000})
		tx.PutDevice(store.Device{ID: id(3), Account: id(1), Kind: 1, DSK: id(4), Cert: []byte("c"), Bundle: []byte("b"),
			CreatedAt: 1_793_000_000_000, LastSeenAt: 1_793_600_000_000})
		return tx.PutSession(store.Session{Hash: id(5), Device: id(3), ExpiresAt: clk.Now() + 1000})
	})
	srv := api.New(api.Config{URL: url, Key: key, Clock: clk, Store: st})
	h := (&admin.Admin{Store: st, Clock: clk, Remove: srv}).Handler()
	call := func(method, path string, want int) string {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		if rec.Code != want {
			t.Fatalf("%s %s: %d %s, want %d", method, path, rec.Code, rec.Body, want)
		}
		return rec.Body.String()
	}
	want := `[{"account_id":"AQEBAQEBAQEBAQEBAQEBAQ","circles":0,"created_day":"2026-10-26","devices":[{"created_day":"2026-10-26",` +
		`"device_id":"AwMDAwMDAwMDAwMDAwMDAw","kind":1,"last_seen_day":"2026-11-02","nickname":""}],"nickname":"","operator":false}]`
	if got := strings.TrimSpace(call("GET", "/accounts", http.StatusOK)); got != want {
		t.Fatalf("accounts:\n%s\nwant\n%s", got, want)
	}
	if got := strings.TrimSpace(call("GET", "/circles", http.StatusOK)); got != "[]" {
		t.Fatalf("circles: %s", got)
	}
	call("DELETE", "/accounts/"+wire.EncodeB64u(id(1)), http.StatusNoContent)
	call("DELETE", "/accounts/"+wire.EncodeB64u(id(1)), http.StatusNotFound)
	st.View(func(tx store.Tx) error {
		_, e1 := tx.Device(id(3))
		_, e2 := tx.Session(id(5))
		if !errors.Is(e1, store.ErrNotFound) || !errors.Is(e2, store.ErrNotFound) {
			t.Error("the account's device or session is still there")
		}
		return nil
	})
	if got := strings.TrimSpace(call("GET", "/accounts", http.StatusOK)); got != "[]" {
		t.Fatalf("accounts after: %s", got)
	}

	none := (&admin.Admin{Store: st, Clock: clk}).Handler()
	for _, path := range []string{"/accounts/" + wire.EncodeB64u(id(1)), "/devices/" + wire.EncodeB64u(id(3))} {
		rec := httptest.NewRecorder()
		none.ServeHTTP(rec, httptest.NewRequest("DELETE", path, nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s without the API server: %d", path, rec.Code)
		}
	}
}
