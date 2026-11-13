// SPDX-License-Identifier: AGPL-3.0-or-later

// Package admin is the operator's API (API.md §16): JSON over HTTP on a Unix socket that
// file permissions protect, never on the network. It handles nothing encrypted and shows
// no location, name or role. So far it covers what a first device needs: setup codes and
// registration tokens, plus the settings, operators and repair mode.
package admin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gureetk/kinfold/server/internal/clock"
	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/wire"
)

const (
	hour           = 3_600_000
	DefaultSetup   = 24 * hour
	DefaultToken   = 7 * 24 * hour
	MaxTokenLife   = 30 * 24 * hour
	MaxRepairHours = 72
)

// Admin serves the operator's API.
type Admin struct {
	Store  store.Store
	Clock  clock.Clock
	Key    ed25519.PrivateKey
	URL    string
	Random io.Reader // crypto/rand if nil
	// Notify, if set, tells the devices online of a change: "repair_mode" when repair mode
	// starts (API.md §7).
	Notify func(code string)
}

// Handler returns the HTTP handler to serve on the admin socket.
func (a *Admin) Handler() http.Handler {
	if a.Random == nil {
		a.Random = rand.Reader
	}
	m := http.NewServeMux()
	m.HandleFunc("POST /setup", a.wrap(a.setup))
	m.HandleFunc("POST /tokens", a.wrap(a.createToken))
	m.HandleFunc("GET /tokens", a.wrap(a.listTokens))
	m.HandleFunc("DELETE /tokens/{id}", a.wrap(a.revokeToken))
	m.HandleFunc("GET /settings", a.wrap(a.getSettings))
	m.HandleFunc("PATCH /settings", a.wrap(a.patchSettings))
	m.HandleFunc("POST /repair", a.wrap(a.startRepair))
	m.HandleFunc("DELETE /repair", a.wrap(a.endRepair))
	m.HandleFunc("PUT /operators/{account_id}", a.wrap(a.setOperator(true)))
	m.HandleFunc("DELETE /operators/{account_id}", a.wrap(a.setOperator(false)))
	return m
}

type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func (a *Admin) wrap(fn func(*http.Request) (int, any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status, out, err := fn(r)
		if err != nil {
			var he *httpError
			status, out = http.StatusInternalServerError, map[string]string{"error": "the server failed"}
			if errors.As(err, &he) {
				status, out = he.status, map[string]string{"error": he.msg}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if out != nil {
			json.NewEncoder(w).Encode(out)
		}
	}
}

func decode(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil || (len(b) > 0 && json.Unmarshal(b, v) != nil) {
		return &httpError{http.StatusBadRequest, "unreadable JSON"}
	}
	return nil
}

func (a *Admin) newToken(tx store.Tx, life uint64) ([]byte, store.Token, error) {
	tok := make([]byte, 32)
	if _, err := io.ReadFull(a.Random, tok); err != nil {
		return nil, store.Token{}, err
	}
	now := a.Clock.Now()
	h := sha256.Sum256(tok)
	t := store.Token{Hash: h[:], CreatedAt: now, ExpiresAt: now + life}
	return tok, t, tx.PutToken(t)
}

func tokenID(hash []byte) string { return hex.EncodeToString(hash[:8]) }

func lifeOf(ms uint64, def uint64) (uint64, error) {
	switch {
	case ms == 0:
		return def, nil
	case ms > MaxTokenLife:
		return 0, &httpError{http.StatusBadRequest, "a token lives at most 30 days"}
	}
	return ms, nil
}

// setup makes a registration token for the first account and the setup code that carries
// it with the server's address and key (PROTOCOL.md §13.1).
func (a *Admin) setup(r *http.Request) (int, any, error) {
	var in struct {
		ExpiresInMS uint64 `json:"expires_in_ms"`
	}
	if err := decode(r, &in); err != nil {
		return 0, nil, err
	}
	life, err := lifeOf(in.ExpiresInMS, DefaultSetup)
	if err != nil {
		return 0, nil, err
	}
	var tok []byte
	var t store.Token
	if err := a.Store.Update(func(tx store.Tx) (err error) { tok, t, err = a.newToken(tx, life); return }); err != nil {
		return 0, nil, err
	}
	key := a.Key.Public().(ed25519.PublicKey)
	code := identity.SetupCode(identity.MakeSetup(a.URL, key, tok, t.ExpiresAt))
	return http.StatusCreated, map[string]any{"code": code, "server_url": a.URL, "server_key": wire.EncodeB64u(key),
		"token_id": tokenID(t.Hash), "expires_at": t.ExpiresAt}, nil
}

func (a *Admin) createToken(r *http.Request) (int, any, error) {
	var in struct {
		ExpiresInMS uint64 `json:"expires_in_ms"`
	}
	if err := decode(r, &in); err != nil {
		return 0, nil, err
	}
	life, err := lifeOf(in.ExpiresInMS, DefaultToken)
	if err != nil {
		return 0, nil, err
	}
	var tok []byte
	var t store.Token
	if err := a.Store.Update(func(tx store.Tx) (err error) { tok, t, err = a.newToken(tx, life); return }); err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, map[string]any{"token": wire.EncodeB64u(tok), "token_id": tokenID(t.Hash), "expires_at": t.ExpiresAt}, nil
}

func (a *Admin) listTokens(*http.Request) (int, any, error) {
	var toks []store.Token
	if err := a.Store.View(func(tx store.Tx) (err error) { toks, err = tx.Tokens(); return }); err != nil {
		return 0, nil, err
	}
	out := []map[string]any{}
	for _, t := range toks {
		e := map[string]any{"token_id": tokenID(t.Hash), "created_at": t.CreatedAt, "expires_at": t.ExpiresAt, "spent": t.Spent}
		if t.Invite != nil {
			e["invite"] = true // a member token, minted with an invite
		}
		out = append(out, e)
	}
	return http.StatusOK, out, nil
}

func (a *Admin) revokeToken(r *http.Request) (int, any, error) {
	id := r.PathValue("id")
	err := a.Store.Update(func(tx store.Tx) error {
		toks, err := tx.Tokens()
		if err != nil {
			return err
		}
		for _, t := range toks {
			if tokenID(t.Hash) == id {
				return tx.DeleteToken(t.Hash)
			}
		}
		return &httpError{http.StatusNotFound, "no such token"}
	})
	return http.StatusNoContent, nil, err
}

func settingsJSON(st store.Settings) map[string]any {
	return map[string]any{"member_tokens": st.MemberTokens, "web_devices": st.WebDevices, "repair_until": st.RepairUntil}
}

func (a *Admin) getSettings(*http.Request) (int, any, error) {
	var st store.Settings
	err := a.Store.View(func(tx store.Tx) (err error) { st, err = tx.Settings(); return })
	return http.StatusOK, settingsJSON(st), err
}

func (a *Admin) patchSettings(r *http.Request) (int, any, error) {
	var in struct {
		MemberTokens *bool `json:"member_tokens"`
		WebDevices   *bool `json:"web_devices"`
	}
	if err := decode(r, &in); err != nil {
		return 0, nil, err
	}
	var st store.Settings
	err := a.Store.Update(func(tx store.Tx) error {
		var err error
		if st, err = tx.Settings(); err != nil {
			return err
		}
		if in.MemberTokens != nil {
			st.MemberTokens = *in.MemberTokens
		}
		if in.WebDevices != nil {
			st.WebDevices = *in.WebDevices
		}
		return tx.PutSettings(st)
	})
	return http.StatusOK, settingsJSON(st), err
}

// startRepair switches repair mode on after a restore (API.md §6); it ends by itself
// after at most 72 hours.
func (a *Admin) startRepair(r *http.Request) (int, any, error) {
	var in struct {
		Hours uint64 `json:"hours"`
	}
	if err := decode(r, &in); err != nil {
		return 0, nil, err
	}
	if in.Hours == 0 || in.Hours > MaxRepairHours {
		in.Hours = MaxRepairHours
	}
	var st store.Settings
	err := a.Store.Update(func(tx store.Tx) error {
		var err error
		if st, err = tx.Settings(); err != nil {
			return err
		}
		st.RepairUntil = a.Clock.Now() + in.Hours*hour
		return tx.PutSettings(st)
	})
	if err == nil && a.Notify != nil {
		a.Notify("repair_mode")
	}
	return http.StatusOK, settingsJSON(st), err
}

func (a *Admin) endRepair(*http.Request) (int, any, error) {
	var st store.Settings
	err := a.Store.Update(func(tx store.Tx) error {
		var err error
		if st, err = tx.Settings(); err != nil {
			return err
		}
		st.RepairUntil = 0
		return tx.PutSettings(st)
	})
	return http.StatusOK, settingsJSON(st), err
}

// setOperator marks an account as one of the server's operators, who may read
// /v1/server/status.
func (a *Admin) setOperator(on bool) func(*http.Request) (int, any, error) {
	return func(r *http.Request) (int, any, error) {
		id, err := wire.DecodeB64u(strings.TrimSpace(r.PathValue("account_id")))
		if err != nil || len(id) != 16 {
			return 0, nil, &httpError{http.StatusBadRequest, "account IDs are 22 characters of base64url"}
		}
		err = a.Store.Update(func(tx store.Tx) error {
			acc, err := tx.Account(id)
			if errors.Is(err, store.ErrNotFound) {
				return &httpError{http.StatusNotFound, "no such account"}
			} else if err != nil {
				return err
			}
			acc.Operator = on
			return tx.PutAccount(acc)
		})
		return http.StatusNoContent, nil, err
	}
}
