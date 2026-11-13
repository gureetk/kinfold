// SPDX-License-Identifier: AGPL-3.0-or-later

// Package admin is the operator's API (API.md §16): JSON over HTTP on a Unix socket that
// file permissions protect, never on the network. It handles nothing encrypted and shows
// no location, name or role. So far it covers what a first device needs: setup codes and
// registration tokens, plus the settings, operators, repair mode, the map files, and the
// accounts, devices and circles as far as the server knows them.
package admin

import (
	"archive/tar"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gureetk/kinfold/server/internal/api"
	"github.com/gureetk/kinfold/server/internal/clock"
	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/tiles"
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
	// Tiles are the map files on offer (API.md §13); nil on a server that keeps none.
	Tiles *tiles.Library
	// API is the running API server. Devices and accounts are removed through it, so that
	// their sessions, push registrations and streams end at once, and the status asks it how
	// it is. Without it, the admin can do neither.
	API *api.Server
	// DataDir is the server's data directory, where backups take the keys from.
	DataDir string
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
	m.HandleFunc("GET /limits", a.wrap(a.getLimits))
	m.HandleFunc("PATCH /limits", a.wrap(a.patchLimits))
	m.HandleFunc("POST /repair", a.wrap(a.startRepair))
	m.HandleFunc("DELETE /repair", a.wrap(a.endRepair))
	m.HandleFunc("PUT /operators/{account_id}", a.wrap(a.setOperator(true)))
	m.HandleFunc("DELETE /operators/{account_id}", a.wrap(a.setOperator(false)))
	m.HandleFunc("GET /accounts", a.wrap(a.listAccounts))
	m.HandleFunc("PATCH /accounts/{id}", a.wrap(a.nameAccount))
	m.HandleFunc("DELETE /accounts/{id}", a.wrap(a.removeAccount))
	m.HandleFunc("PATCH /devices/{id}", a.wrap(a.nameDevice))
	m.HandleFunc("DELETE /devices/{id}", a.wrap(a.removeDevice))
	m.HandleFunc("GET /circles", a.wrap(a.listCircles))
	m.HandleFunc("POST /backup", a.wrap(a.backup))
	m.HandleFunc("GET /status", a.wrap(a.status))
	m.HandleFunc("GET /regions", a.wrap(a.listRegions))
	m.HandleFunc("PUT /regions/{id}", a.wrap(a.putRegion))
	m.HandleFunc("DELETE /regions/{id}", a.wrap(a.deleteRegion))
	m.HandleFunc("PUT /coarse", a.wrap(a.putCoarse))
	m.HandleFunc("DELETE /coarse", a.wrap(a.deleteCoarse))
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
	return map[string]any{"member_tokens": st.MemberTokens, "web_devices": st.WebDevices, "web_tile_ranges": st.WebTileRanges,
		"repair_until": st.RepairUntil}
}

func (a *Admin) getSettings(*http.Request) (int, any, error) {
	var st store.Settings
	err := a.Store.View(func(tx store.Tx) (err error) { st, err = tx.Settings(); return })
	return http.StatusOK, settingsJSON(st), err
}

func (a *Admin) patchSettings(r *http.Request) (int, any, error) {
	var in struct {
		MemberTokens  *bool `json:"member_tokens"`
		WebDevices    *bool `json:"web_devices"`
		WebTileRanges *bool `json:"web_tile_ranges"`
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
		if in.WebTileRanges != nil {
			st.WebTileRanges = *in.WebTileRanges
		}
		return tx.PutSettings(st)
	})
	return http.StatusOK, settingsJSON(st), err
}

// ---- rate limits (API.md §3) ----

// MaxLimit is the largest value a rate limit may be set to.
const MaxLimit = 1_000_000

// limitsJSON are limits as a map by name, the names of API.md §3.
func limitsJSON(l api.Limits) map[string]int {
	b, _ := json.Marshal(l)
	out := map[string]int{}
	json.Unmarshal(b, &out)
	return out
}

func (a *Admin) getLimits(*http.Request) (int, any, error) {
	if a.API == nil {
		return 0, nil, &httpError{http.StatusServiceUnavailable, "this admin socket has no server to ask"}
	}
	var st store.Settings
	if err := a.Store.View(func(tx store.Tx) (err error) { st, err = tx.Settings(); return }); err != nil {
		return 0, nil, err
	}
	set := map[string]int{}
	if st.Limits != "" {
		json.Unmarshal([]byte(st.Limits), &set)
	}
	return http.StatusOK, map[string]any{"in_force": limitsJSON(a.API.Limits()), "set": set}, nil
}

// patchLimits sets rate limits by name, at once and for later starts; 0 returns one to its
// default.
func (a *Admin) patchLimits(r *http.Request) (int, any, error) {
	if a.API == nil {
		return 0, nil, &httpError{http.StatusServiceUnavailable, "this admin socket has no server to change"}
	}
	var in map[string]int
	if err := decode(r, &in); err != nil {
		return 0, nil, err
	}
	known := limitsJSON(api.DefaultLimits())
	for name, v := range in {
		if _, ok := known[name]; !ok {
			return 0, nil, &httpError{http.StatusBadRequest, "no limit is called " + name}
		}
		if v < 0 || v > MaxLimit {
			return 0, nil, &httpError{http.StatusBadRequest, "a limit is 1 to 1,000,000, or 0 for its default"}
		}
	}
	var limits api.Limits
	err := a.Store.Update(func(tx store.Tx) error {
		st, err := tx.Settings()
		if err != nil {
			return err
		}
		set := map[string]int{}
		if st.Limits != "" {
			json.Unmarshal([]byte(st.Limits), &set)
		}
		for name, v := range in {
			if v == 0 {
				delete(set, name)
			} else {
				set[name] = v
			}
		}
		b, err := json.Marshal(set)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(b, &limits); err != nil {
			return err
		}
		st.Limits = ""
		if len(set) > 0 {
			st.Limits = string(b)
		}
		return tx.PutSettings(st)
	})
	if err != nil {
		return 0, nil, err
	}
	a.API.SetLimits(limits)
	return a.getLimits(r)
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
		id, err := pathID(r, "account_id", "account")
		if err != nil {
			return 0, nil, err
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

// ---- accounts, devices and circles ----
//
// The operator sees IDs, device kinds, counts and days, and the nicknames the operator gave:
// never a time of day, a name, a role or anything encrypted.

// day is the UTC day of a time in milliseconds, as YYYY-MM-DD.
func day(ms uint64) string { return time.UnixMilli(int64(ms)).UTC().Format(time.DateOnly) }

func pathID(r *http.Request, name, what string) ([]byte, error) {
	id, err := wire.DecodeB64u(strings.TrimSpace(r.PathValue(name)))
	if err != nil || len(id) != 16 {
		return nil, &httpError{http.StatusBadRequest, what + " IDs are 22 characters of base64url"}
	}
	return id, nil
}

func (a *Admin) listAccounts(*http.Request) (int, any, error) {
	out := []map[string]any{}
	err := a.Store.View(func(tx store.Tx) error {
		accs, err := tx.Accounts()
		if err != nil {
			return err
		}
		for _, acc := range accs {
			devs, err := tx.DevicesOf(acc.ID)
			if err != nil {
				return err
			}
			circles, err := tx.CirclesOf(acc.ID)
			if err != nil {
				return err
			}
			ds := []map[string]any{}
			for _, d := range devs {
				ds = append(ds, map[string]any{"device_id": wire.EncodeB64u(d.ID), "kind": d.Kind, "created_day": day(d.CreatedAt),
					"last_seen_day": day(d.LastSeenAt), "nickname": d.Nickname})
			}
			out = append(out, map[string]any{"account_id": wire.EncodeB64u(acc.ID), "created_day": day(acc.CreatedAt),
				"operator": acc.Operator, "circles": len(circles), "nickname": acc.Nickname, "devices": ds})
		}
		return nil
	})
	return http.StatusOK, out, err
}

// nickname reads a nickname: at most 64 bytes of UTF-8 without control characters, or ""
// to clear it.
func nickname(r *http.Request) (string, error) {
	var in struct {
		Nickname *string `json:"nickname"`
	}
	if err := decode(r, &in); err != nil {
		return "", err
	}
	if in.Nickname == nil || len(*in.Nickname) > 64 || !utf8.ValidString(*in.Nickname) ||
		strings.ContainsFunc(*in.Nickname, func(c rune) bool { return c < 0x20 || c == 0x7F }) {
		return "", &httpError{http.StatusBadRequest, "nickname is at most 64 bytes of text, or empty to clear it"}
	}
	return *in.Nickname, nil
}

func (a *Admin) nameAccount(r *http.Request) (int, any, error) {
	id, err := pathID(r, "id", "account")
	if err != nil {
		return 0, nil, err
	}
	name, err := nickname(r)
	if err != nil {
		return 0, nil, err
	}
	err = a.Store.Update(func(tx store.Tx) error {
		acc, err := tx.Account(id)
		if errors.Is(err, store.ErrNotFound) {
			return &httpError{http.StatusNotFound, "no such account"}
		} else if err != nil {
			return err
		}
		acc.Nickname = name
		return tx.PutAccount(acc)
	})
	return http.StatusNoContent, nil, err
}

func (a *Admin) nameDevice(r *http.Request) (int, any, error) {
	id, err := pathID(r, "id", "device")
	if err != nil {
		return 0, nil, err
	}
	name, err := nickname(r)
	if err != nil {
		return 0, nil, err
	}
	err = a.Store.Update(func(tx store.Tx) error {
		d, err := tx.Device(id)
		if errors.Is(err, store.ErrNotFound) {
			return &httpError{http.StatusNotFound, "no such device"}
		} else if err != nil {
			return err
		}
		d.Nickname = name
		return tx.PutDevice(d)
	})
	return http.StatusNoContent, nil, err
}

// removeDevice cuts a device off: its sessions, push registration and stream end at once.
// The circles' logs still name it until a member removes it there.
func (a *Admin) removeDevice(r *http.Request) (int, any, error) {
	id, err := pathID(r, "id", "device")
	if err != nil {
		return 0, nil, err
	}
	if a.API == nil {
		return 0, nil, &httpError{http.StatusServiceUnavailable, "this admin socket can't remove devices"}
	}
	if err := a.API.RemoveDevice(id); errors.Is(err, store.ErrNotFound) {
		return 0, nil, &httpError{http.StatusNotFound, "no such device"}
	} else if err != nil {
		return 0, nil, err
	}
	return http.StatusNoContent, nil, nil
}

// removeAccount deletes an account that is in no circle, with its devices.
func (a *Admin) removeAccount(r *http.Request) (int, any, error) {
	id, err := pathID(r, "id", "account")
	if err != nil {
		return 0, nil, err
	}
	if a.API == nil {
		return 0, nil, &httpError{http.StatusServiceUnavailable, "this admin socket can't remove accounts"}
	}
	switch err := a.API.RemoveAccount(id); {
	case errors.Is(err, store.ErrNotFound):
		return 0, nil, &httpError{http.StatusNotFound, "no such account"}
	case errors.Is(err, api.ErrStillMember):
		return 0, nil, &httpError{http.StatusConflict, "the account is still in a circle: remove its devices instead"}
	case err != nil:
		return 0, nil, err
	}
	return http.StatusNoContent, nil, nil
}

func (a *Admin) listCircles(*http.Request) (int, any, error) {
	out := []map[string]any{}
	err := a.Store.View(func(tx store.Tx) error {
		cs, err := tx.Circles()
		if err != nil {
			return err
		}
		for _, c := range cs {
			devices := 0
			for _, m := range c.State.Members {
				devices += len(m.Devices)
			}
			out = append(out, map[string]any{"circle_id": wire.EncodeB64u(c.ID), "members": len(c.State.Members), "devices": devices,
				"entries": c.State.Seq + 1, "head": wire.EncodeB64u(c.State.Head), "created_day": day(c.CreatedAt),
				"closed": len(c.State.Members) == 0})
		}
		return nil
	})
	return http.StatusOK, out, err
}

// ---- backups and health ----

// BackupFiles are what a backup holds, as the archive names them: a snapshot of the database
// and the server's keys. The map files are left out; they come from the operator's own copies.
var BackupFiles = []string{"kinfold.db", "server.key", "vapid.key"}

// backup writes the server's data to a tar archive at file, which must not exist yet. The
// database is a snapshot taken while the server runs. vapid.key is left out if the server
// has none.
func (a *Admin) backup(r *http.Request) (int, any, error) {
	snap, ok := a.Store.(interface{ Backup(path string) error })
	if !ok || a.DataDir == "" {
		return 0, nil, &httpError{http.StatusServiceUnavailable, "this server's store can't be backed up"}
	}
	file, _, err := mapFile(r)
	if err != nil {
		return 0, nil, err
	}
	out, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return 0, nil, &httpError{http.StatusConflict, "the file exists"}
	} else if err != nil {
		return 0, nil, mapError(err)
	}
	now := a.Clock.Now()
	size, err := func() (int64, error) {
		defer out.Close()
		db := filepath.Join(a.DataDir, "backup-"+hex.EncodeToString(a.random(8))+".db")
		if err := snap.Backup(db); err != nil {
			return 0, err
		}
		defer os.Remove(db)
		tw := tar.NewWriter(out)
		for _, name := range BackupFiles {
			src := filepath.Join(a.DataDir, name)
			if name == "kinfold.db" {
				src = db
			}
			if err := addFile(tw, name, src, now); errors.Is(err, fs.ErrNotExist) && name == "vapid.key" {
				continue
			} else if err != nil {
				return 0, err
			}
		}
		if err := tw.Close(); err != nil {
			return 0, err
		}
		if err := out.Sync(); err != nil {
			return 0, err
		}
		return out.Seek(0, io.SeekCurrent)
	}()
	if err != nil {
		os.Remove(file)
		return 0, nil, err
	}
	err = a.Store.Update(func(tx store.Tx) error {
		st, err := tx.Settings()
		if err != nil {
			return err
		}
		st.LastBackupAt = now
		return tx.PutSettings(st)
	})
	return http.StatusOK, map[string]any{"file": file, "size": size, "at": now}, err
}

func addFile(tw *tar.Writer, name, src string, now uint64) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	hdr := &tar.Header{Name: name, Mode: 0o600, Size: st.Size(), ModTime: time.UnixMilli(int64(now)), Format: tar.FormatPAX}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.CopyN(tw, f, st.Size())
	return err
}

func (a *Admin) random(n int) []byte {
	b := make([]byte, n)
	io.ReadFull(a.Random, b)
	return b
}

// status is the running server's health, repair mode and last backup.
func (a *Admin) status(r *http.Request) (int, any, error) {
	if a.API == nil {
		return 0, nil, &httpError{http.StatusServiceUnavailable, "this admin socket has no server to ask"}
	}
	h := a.API.Health(r.Context())
	var st store.Settings
	if err := a.Store.View(func(tx store.Tx) (err error) { st, err = tx.Settings(); return }); err != nil {
		return 0, nil, err
	}
	b, err := json.Marshal(h)
	if err != nil {
		return 0, nil, err
	}
	var out map[string]any
	json.Unmarshal(b, &out)
	out["repair_until"], out["last_backup_at"] = st.RepairUntil, st.LastBackupAt
	return http.StatusOK, out, nil
}

// ---- maps (API.md §13) ----

func (a *Admin) library() (*tiles.Library, error) {
	if a.Tiles == nil {
		return nil, &httpError{http.StatusServiceUnavailable, "this server keeps no maps"}
	}
	return a.Tiles, nil
}

// mapFile is the file a region or the coarse archive is copied from: an absolute path the
// server's user can read.
func mapFile(r *http.Request) (string, string, error) {
	var in struct {
		File string `json:"file"`
		Name string `json:"name"`
	}
	if err := decode(r, &in); err != nil {
		return "", "", err
	}
	if !filepath.IsAbs(in.File) {
		return "", "", &httpError{http.StatusBadRequest, "file is an absolute path"}
	}
	return in.File, in.Name, nil
}

// mapError says what was wrong with a map file, or with the region asked for.
func mapError(err error) error {
	switch {
	case errors.Is(err, tiles.ErrNotFound):
		return &httpError{http.StatusNotFound, err.Error()}
	case errors.Is(err, tiles.ErrBadID), errors.Is(err, tiles.ErrBadName), errors.Is(err, tiles.ErrNotPMTiles),
		errors.Is(err, tiles.ErrTooFine), errors.Is(err, fs.ErrNotExist), errors.Is(err, fs.ErrPermission):
		return &httpError{http.StatusBadRequest, err.Error()}
	}
	return err
}

func (a *Admin) listRegions(*http.Request) (int, any, error) {
	lib, err := a.library()
	if err != nil {
		return 0, nil, err
	}
	out := map[string]any{"regions": lib.Regions(), "coarse": nil}
	if c, ok := lib.Coarse(); ok {
		out["coarse"] = c
	}
	return http.StatusOK, out, nil
}

// putRegion copies a PMTiles archive in as a region, replacing any earlier file for it.
func (a *Admin) putRegion(r *http.Request) (int, any, error) {
	lib, err := a.library()
	if err != nil {
		return 0, nil, err
	}
	file, name, err := mapFile(r)
	if err != nil {
		return 0, nil, err
	}
	reg, err := lib.Add(r.PathValue("id"), name, file, a.Clock.Now())
	if err != nil {
		return 0, nil, mapError(err)
	}
	return http.StatusOK, reg, nil
}

func (a *Admin) deleteRegion(r *http.Request) (int, any, error) {
	lib, err := a.library()
	if err != nil {
		return 0, nil, err
	}
	if err := lib.Remove(r.PathValue("id")); err != nil {
		return 0, nil, mapError(err)
	}
	return http.StatusNoContent, nil, nil
}

// putCoarse copies in the coarse archive for the share viewer: zoom 13 at most.
func (a *Admin) putCoarse(r *http.Request) (int, any, error) {
	lib, err := a.library()
	if err != nil {
		return 0, nil, err
	}
	file, _, err := mapFile(r)
	if err != nil {
		return 0, nil, err
	}
	c, err := lib.SetCoarse(file, a.Clock.Now())
	if err != nil {
		return 0, nil, mapError(err)
	}
	return http.StatusOK, c, nil
}

func (a *Admin) deleteCoarse(*http.Request) (int, any, error) {
	lib, err := a.library()
	if err != nil {
		return 0, nil, err
	}
	if err := lib.RemoveCoarse(); err != nil {
		return 0, nil, mapError(err)
	}
	return http.StatusNoContent, nil, nil
}
