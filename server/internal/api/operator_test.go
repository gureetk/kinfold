// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/coder/websocket"

	"github.com/gureetk/kinfold/server/internal/api"
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
	if c := circles[0]; c["circle_id"] != b64(l.cid) || c["entries"] != 21.0 || c["members"] == 0.0 || c["closed"] != false {
		t.Errorf("the circle: %v", c)
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
