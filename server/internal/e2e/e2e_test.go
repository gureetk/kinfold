// SPDX-License-Identifier: AGPL-3.0-or-later

// Package e2e drives a whole server through its HTTP API with two clients built on the
// Python reference (testdata/clients.py): registration from a setup code, a circle, an
// invite and a join, and an envelope each way, fetched and opened. It needs a Python with
// reference/python/requirements.txt installed in KINFOLD_PYTHON, and is skipped without one.
package e2e_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gureetk/kinfold/server/internal/admin"
	"github.com/gureetk/kinfold/server/internal/api"
	"github.com/gureetk/kinfold/server/internal/clock"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/store/memstore"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
)

func TestTwoReferenceClients(t *testing.T) {
	py := os.Getenv("KINFOLD_PYTHON")
	if py == "" {
		t.Skip("set KINFOLD_PYTHON to a Python with reference/python/requirements.txt installed")
	}
	vec, err := tv.Path()
	if err != nil {
		t.Fatal(err)
	}
	vec, _ = filepath.Abs(vec)
	ref := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(vec))), "reference", "python")

	// The server's clock is injected and stands still: clients take their time from the
	// Kinfold-Time header, as phones do.
	clk := clock.NewFake(1_794_571_200_000) // 2026-11-13T12:00:00Z
	st := memstore.New()
	seed := sha256.Sum256([]byte("kinfold e2e server key"))
	key := ed25519.NewKeyFromSeed(seed[:])

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + l.Addr().String()
	srv := &httptest.Server{Listener: l, Config: &http.Server{Handler: api.New(api.Config{URL: url, Key: key, Clock: clk, Store: st})}}
	srv.Start()
	defer srv.Close()

	adm := (&admin.Admin{Store: st, Clock: clk, Key: key, URL: url}).Handler()
	call := func(method, path, body string) map[string]any {
		rec := httptest.NewRecorder()
		adm.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		if rec.Code >= 300 {
			t.Fatalf("admin %s %s: %d %s", method, path, rec.Code, rec.Body)
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	call("PATCH", "/settings", `{"member_tokens": true}`)
	code := call("POST", "/setup", `{}`)["code"].(string)

	cmd := exec.Command(py, "-I", "testdata/clients.py", ref, url, code)
	out, err := cmd.CombinedOutput()
	t.Logf("clients:\n%s", out)
	if err != nil {
		t.Fatalf("the reference clients failed: %v", err)
	}

	// What the server kept: one circle of two members, and no epoch secret.
	st.View(func(tx store.Tx) error {
		toks, _ := tx.Tokens()
		spent := 0
		for _, tok := range toks {
			if tok.Spent {
				spent++
			}
		}
		if spent != 2 {
			t.Errorf("%d registration tokens spent, want 2", spent)
		}
		return nil
	})
}
