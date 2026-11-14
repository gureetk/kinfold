// SPDX-License-Identifier: AGPL-3.0-or-later

package admin_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gureetk/kinfold/server/internal/admin"
	"github.com/gureetk/kinfold/server/internal/clock"
	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/store/memstore"
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
