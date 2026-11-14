// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/coder/websocket"

	"github.com/gureetk/kinfold/server/internal/admin"
	"github.com/gureetk/kinfold/server/internal/api"
	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/store/sqlstore"
)

// The operator's view of the vectors' family (API.md §16): accounts with their devices'
// kinds and days, the circle with its counts, nicknames only the operator sees, and a device
// removed on the server, cut off at once while the log still names it.
func TestOperatorView(t *testing.T) {
	l := newLive(t, generous, api.StreamTimes{})
	maya := byLabel(l.devs, "maya/phone")
	var accounts []map[string]any
	if err := json.Unmarshal(l.adminCall("GET", "/accounts", "").Body.Bytes(), &accounts); err != nil {
		t.Fatal(err)
	}
	var mayas map[string]any
	devices := 0
	for _, a := range accounts {
		for _, d := range a["devices"].([]any) {
			devices++
			if dd := d.(map[string]any); dd["device_id"] == b64(maya.id) {
				mayas = a
				if seen, _ := dd["last_seen_day"].(string); dd["kind"] != 1.0 || !dayPattern.MatchString(seen) || len(dd) != 5 {
					t.Errorf("Maya's phone: %v", dd)
				}
			}
		}
	}
	if len(accounts) == 0 || mayas == nil || mayas["account_id"] != b64(maya.account) || mayas["circles"] != 1.0 || devices != len(l.devs) {
		t.Fatalf("accounts: %v", accounts)
	}
	var circles []map[string]any
	if err := json.Unmarshal(l.adminCall("GET", "/circles", "").Body.Bytes(), &circles); err != nil || len(circles) != 1 {
		t.Fatalf("circles: %v %v", circles, err)
	}
	head := decode(t, l.do(call{method: "GET", path: "/v1/circles/" + b64(l.cid) + "/head", token: l.login(maya)}))
	if c := circles[0]; c["circle_id"] != b64(l.cid) || c["entries"] != 21.0 || c["members"] == 0.0 || c["closed"] != false ||
		c["head"] != head["head"] {
		t.Errorf("the circle: %v, head %v", c, head)
	}

	// Nicknames are the operator's alone.
	expectAdmin(t, l.adminCall("PATCH", "/accounts/"+b64(maya.account), `{"nickname": "Maya"}`), http.StatusNoContent)
	expectAdmin(t, l.adminCall("PATCH", "/devices/"+b64(maya.id), `{"nickname": "Maya's old phone"}`), http.StatusNoContent)
	expectAdmin(t, l.adminCall("PATCH", "/devices/"+b64(maya.id), `{"nickname": "two\nlines"}`), http.StatusBadRequest)
	expectAdmin(t, l.adminCall("PATCH", "/devices/"+b64(maya.id), `{}`), http.StatusBadRequest)
	expectAdmin(t, l.adminCall("PATCH", "/devices/"+b64(l.cid), `{"nickname": "x"}`), http.StatusNotFound)
	expectAdmin(t, l.adminCall("PATCH", "/devices/short", `{"nickname": "x"}`), http.StatusBadRequest)
	if body := l.adminCall("GET", "/accounts", "").Body.String(); !json.Valid([]byte(body)) ||
		!strings.Contains(body, `"nickname":"Maya"`) || !strings.Contains(body, `"nickname":"Maya's old phone"`) {
		t.Errorf("the nicknames: %s", body)
	}
	rec := l.do(call{method: "GET", path: "/v1/devices", token: l.login(maya)})
	if strings.Contains(rec.Body.String(), "Maya") {
		t.Error("a device sees the operator's nickname")
	}

	// Removing Maya's phone on the server ends its stream and session at once.
	c, _, _ := l.open(maya, "")
	tok := l.login(maya)
	expectAdmin(t, l.adminCall("DELETE", "/devices/"+b64(maya.id), ""), http.StatusNoContent)
	closedWith(t, c, websocket.StatusCode(4401))
	expect(t, l.do(call{method: "GET", path: "/v1/inbox", token: tok}), http.StatusUnauthorized, "unauthorized")
	expectAdmin(t, l.adminCall("DELETE", "/devices/"+b64(maya.id), ""), http.StatusNotFound)
	// Maya is still in the circle, so her account stays.
	expectAdmin(t, l.adminCall("DELETE", "/accounts/"+b64(maya.account), ""), http.StatusConflict)
	expectAdmin(t, l.adminCall("DELETE", "/accounts/"+b64(l.cid), ""), http.StatusNotFound)
}

func expectAdmin(t *testing.T, rec interface{ Result() *http.Response }, status int) {
	t.Helper()
	if got := rec.Result().StatusCode; got != status {
		t.Fatalf("admin: %d, want %d", got, status)
	}
}

// dayPattern is a day without a time: the most the operator learns of when a device was
// last seen.
var dayPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// The operators' status (API.md §4) and the operator's health report (§16): uptime, the clock,
// free disk, what is open and in flight, the relay, and the last backup.
func TestServerStatus(t *testing.T) {
	dir := t.TempDir()
	relay := newFakeRelay(t)
	l := newLive(t, generous, api.StreamTimes{}, func(c *api.Config) { c.DataDir, c.Push.Relay = dir, relay.URL })
	maya, alex := byLabel(l.devs, "maya/phone"), byLabel(l.devs, "alex/phone")
	expect(t, l.do(call{method: "GET", path: "/v1/server/status", token: l.login(maya)}), http.StatusForbidden, "forbidden")
	l.admin("PUT", "/operators/"+b64(maya.account), "")
	st := decode(t, l.do(call{method: "GET", path: "/v1/server/status", token: l.login(maya)}))
	if free, _ := st["free_disk"].(float64); free <= 0 || st["clock_synced"] != true || st["repair"] != false || st["last_backup_at"] != nil {
		t.Fatalf("status: %v", st)
	}
	expect(t, l.do(call{method: "GET", path: "/v1/server/status", token: l.login(alex)}), http.StatusForbidden, "forbidden")

	l.open(alex, "")
	h := l.admin("GET", "/status", "")
	if h["streams"] != 1.0 || h["pushes_in_flight"] != 0.0 || h["link_mailboxes"] != 0.0 || h["relay_reachable"] != true ||
		h["clock_synced"] != true || h["last_backup_at"] != 0.0 || h["fingerprint"] != identity.Fingerprint(l.srv.ServerKey()) {
		t.Fatalf("health: %v", h)
	}
	if free, _ := h["free_disk"].(float64); free <= 0 {
		t.Fatalf("free disk: %v", h["free_disk"])
	}
	relay.Close()
	if h := l.admin("GET", "/status", ""); h["relay_reachable"] != false {
		t.Fatalf("a relay that's gone: %v", h["relay_reachable"])
	}

	// A backup shows in both.
	if _, ok := l.st.(*sqlstore.Store); !ok {
		return // the memory store can't be backed up
	}
	os.WriteFile(filepath.Join(dir, "server.key"), make([]byte, 32), 0o600)
	adm := (&admin.Admin{Store: l.st, Clock: l.clk, DataDir: dir, API: l.srv}).Handler()
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"file": filepath.Join(t.TempDir(), "b.tar")})
	adm.ServeHTTP(rec, httptest.NewRequest("POST", "/backup", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("backup: %d %s", rec.Code, rec.Body)
	}
	if st := decode(t, l.do(call{method: "GET", path: "/v1/server/status", token: l.login(maya)})); st["last_backup_at"] != float64(l.clk.Now()) {
		t.Fatalf("status after a backup: %v", st)
	}
	if h := l.admin("GET", "/status", ""); h["last_backup_at"] != float64(l.clk.Now()) {
		t.Fatalf("health after a backup: %v", h)
	}
}

// The operator sets rate limits (API.md §3): at once, for later starts, and back to their
// defaults; names and values are checked.
func TestOperatorLimits(t *testing.T) {
	photon := newFakePhoton(t)
	l := newLive(t, api.Limits{}, api.StreamTimes{}, func(c *api.Config) { c.Search = photon.URL })
	limits := func(method, body string, want int) map[string]any {
		t.Helper()
		rec := l.adminCall(method, "/limits", body)
		if rec.Code != want {
			t.Fatalf("%s /limits %s: %d %s", method, body, rec.Code, rec.Body)
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	out := limits("GET", "", http.StatusOK)
	inForce := out["in_force"].(map[string]any)
	if inForce["search_per_minute"] != 30.0 || inForce["envelopes_per_hour"] != 600.0 || len(inForce) != 16 || len(out["set"].(map[string]any)) != 0 {
		t.Fatalf("the defaults: %v", out)
	}
	out = limits("PATCH", `{"search_per_minute": 1}`, http.StatusOK)
	if out["in_force"].(map[string]any)["search_per_minute"] != 1.0 || out["set"].(map[string]any)["search_per_minute"] != 1.0 {
		t.Fatalf("set: %v", out)
	}
	phone := l.login(byLabel(l.devs, "maya/phone"))
	expect(t, l.json("POST", "/v1/search", map[string]any{"q": "toronto"}, phone), http.StatusOK, "")
	expect(t, l.json("POST", "/v1/search", map[string]any{"q": "toronto"}, phone), http.StatusTooManyRequests, "rate_limited")
	l.st.View(func(tx store.Tx) error {
		if s, _ := tx.Settings(); s.Limits != `{"search_per_minute":1}` {
			t.Errorf("kept for later starts: %q", s.Limits)
		}
		return nil
	})
	out = limits("PATCH", `{"search_per_minute": 0}`, http.StatusOK)
	if out["in_force"].(map[string]any)["search_per_minute"] != 30.0 || len(out["set"].(map[string]any)) != 0 {
		t.Fatalf("back to the default: %v", out)
	}
	expect(t, l.json("POST", "/v1/search", map[string]any{"q": "toronto"}, phone), http.StatusOK, "")
	for _, bad := range []string{`{"searches": 5}`, `{"search_per_minute": -1}`, `{"search_per_minute": 1000001}`, `[1]`} {
		limits("PATCH", bad, http.StatusBadRequest)
	}
}
