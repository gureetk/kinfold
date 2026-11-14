// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/coder/websocket"

	"github.com/gureetk/kinfold/server/internal/api"
	"github.com/gureetk/kinfold/server/internal/kcrypto"
	"github.com/gureetk/kinfold/server/internal/push"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
	"github.com/gureetk/kinfold/server/internal/wire"
)

const minute = 60_000

// grant signs a WatchGrant (PROTOCOL.md §14.1) with the watched device's key.
func grant(d *device, cid, watcher []byte, afterMin uint16, issuedAt, notAfter uint64) []byte {
	tbs := wire.Concat([]byte{0}, cid, d.id, watcher, wire.U16(afterMin), wire.U64(issuedAt), wire.U64(notAfter))
	return append(tbs, kcrypto.Sign(d.dsk, "watch-grant", tbs)...)
}

func (l *live) putWatch(by *device, watched *device, g []byte) *httpResult {
	rec := l.octets("PUT", "/v1/circles/"+b64(l.cid)+"/watches/"+b64(watched.id), g, l.login(by))
	return &httpResult{rec.Code, rec.Body.Bytes()}
}

type httpResult struct {
	code int
	body []byte
}

func (l *live) watches(by *device) []map[string]any {
	l.t.Helper()
	rec := l.do(call{method: "GET", path: "/v1/circles/" + b64(l.cid) + "/watches", token: l.login(by)})
	expect(l.t, rec, http.StatusOK, "")
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		l.t.Fatal(err)
	}
	return out
}

// await reads a stream until a message of the type comes, past records, cursors, log frames
// and the time.
func await(t *testing.T, c *websocket.Conn, want byte) []byte {
	t.Helper()
	for {
		typ, body := next(t, c)
		switch {
		case typ == want:
			return body
		case typ == 0x01 || typ == 0x02 || typ == 0x03 || typ == 0x06:
			continue
		default:
			t.Fatalf("message %#x while waiting for %#x: %s", typ, want, body)
		}
	}
}

func awaitEvent(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	var ev map[string]any
	if err := json.Unmarshal(await(t, c, 0x05), &ev); err != nil {
		t.Fatal(err)
	}
	return ev
}

// silence reads a silence push from a stream and checks it: signed by the server for this
// recipient, about this device, with when it was last heard.
func silence(t *testing.T, c *websocket.Conn, server ed25519.PublicKey, recipient, cid, watched []byte, lastSeen, now uint64) {
	t.Helper()
	p := await(t, c, 0x04)
	r := wire.NewReader(p)
	ver, ptype, sentAt, body := r.U8(), r.U8(), r.U64(), r.Vec16()
	tbs := p[:r.Pos()]
	sig := r.Take(64)
	if !r.Done() || ver != 0 || ptype != push.Silence || sentAt != now ||
		!bytes.Equal(body, wire.Concat(cid, watched, wire.U64(lastSeen))) {
		t.Fatalf("silence push: type %d, sent at %d, body %x", ptype, sentAt, body)
	}
	if !kcrypto.Verify(server, "push-sig", wire.Concat(recipient, tbs), sig) {
		t.Fatal("the push's signature")
	}
}

// The grants of the vectors: the valid ones are taken, the others refused.
func TestWatchGrantVectors(t *testing.T) {
	l := newLive(t, generous, api.StreamTimes{})
	wg := tv.Obj(tv.Load(t)["watch_grants"])
	l.clk.Set(tv.Num(wg["now"]))
	for _, c := range tv.Arr(wg["grants"]) {
		cc := tv.Obj(c)
		raw := tv.Hex(cc["grant"])
		watched, watcher := l.devs[string(raw[17:33])], raw[33:49]
		var by *device // the account's first phone; Jordan's second one isn't in the circle
		for _, d := range l.devs {
			if bytes.Equal(d.account, watcher) && strings.HasSuffix(d.label, "/phone") {
				by = d
			}
		}
		if watched == nil || by == nil {
			continue // a device or watcher the server can't have
		}
		res := l.putWatch(by, watched, raw)
		if want := tv.Bool(cc["valid"]); (res.code == http.StatusNoContent) != want {
			t.Errorf("%s: %d %s", tv.Str(cc["name"]), res.code, res.body)
		}
		if res.code == http.StatusNoContent { // the watcher ends it, so the next grant starts afresh
			expect(t, l.do(call{method: "DELETE", path: "/v1/circles/" + b64(l.cid) + "/watches/" + b64(watched.id), token: l.login(by)}),
				http.StatusNoContent, "")
		}
	}
}

func TestWatches(t *testing.T) {
	l := newLive(t, generous, api.StreamTimes{})
	jordan, alex, maya := byLabel(l.devs, "jordan/phone"), byLabel(l.devs, "alex/phone"), byLabel(l.devs, "maya/phone")
	start := l.clk.Now()
	g := grant(maya, l.cid, jordan.account, 15, start, start+10*1440*minute)

	// Who may register what.
	if r := l.putWatch(alex, maya, g); r.code != http.StatusForbidden {
		t.Errorf("a grant for someone else: %d", r.code)
	}
	if r := l.putWatch(jordan, alex, g); r.code != http.StatusUnprocessableEntity {
		t.Errorf("a grant for another device than the path's: %d", r.code)
	}
	for _, bad := range [][]byte{grant(maya, l.cid, jordan.account, 14, start, start+minute),
		grant(maya, l.cid, jordan.account, 15, start-minute, start), // run out
		grant(maya, l.cid, jordan.account, 15, start, start+35*1440*minute+1),
		grant(maya, l.cid, jordan.account, 15, start+10*minute+1, start+minute*20), // issued in the future
		grant(alex, l.cid, jordan.account, 15, start, start+minute)[:130]} {
		if r := l.putWatch(jordan, maya, bad); r.code != http.StatusUnprocessableEntity {
			t.Errorf("a bad grant: %d %s", r.code, r.body)
		}
	}
	forged := append([]byte(nil), g...)
	copy(forged[67:], kcrypto.Sign(alex.dsk, "watch-grant", g[:67])) // signed by another device
	if r := l.putWatch(jordan, maya, forged); r.code != http.StatusUnprocessableEntity {
		t.Errorf("a grant signed by another device: %d", r.code)
	}
	if r := l.putWatch(jordan, maya, g); r.code != http.StatusNoContent {
		t.Fatalf("register: %d %s", r.code, r.body)
	}
	if r := l.putWatch(jordan, maya, g); r.code != http.StatusNoContent {
		t.Fatalf("the same grant again: %d", r.code)
	}

	// The watcher and the watched see it; nobody else does.
	for d, n := range map[*device]int{jordan: 1, maya: 1, alex: 0} {
		if ws := l.watches(d); len(ws) != n {
			t.Errorf("%s sees %d watches", d.label, len(ws))
		} else if n == 1 && (ws[0]["watched_device_id"] != b64(maya.id) || ws[0]["after_min"] != float64(15) ||
			ws[0]["watcher_account_id"] != b64(jordan.account) || ws[0]["issued_at"] != float64(start)) {
			t.Errorf("%s: %v", d.label, ws[0])
		}
	}

	// Silence: never heard, so it counts from the registration. The device is woken first,
	// and two minutes later the watcher's phone is told, once.
	cj, _, _ := l.open(jordan, "")
	check := func() {
		t.Helper()
		if err := l.srv.CheckSilences(); err != nil {
			t.Fatal(err)
		}
	}
	l.clk.Set(start + 15*minute - 1)
	check()
	l.clk.Set(start + 15*minute) // woken
	check()
	l.clk.Set(start + 17*minute - 1)
	check()
	l.clk.Set(start + 17*minute)
	check()
	silence(t, cj, l.srv.ServerKey(), jordan.id, l.cid, maya.id, 0, l.clk.Now())
	l.clk.Set(start + 60*minute)
	check()

	// A circle envelope from the device starts the silence over.
	heard := l.clk.Now()
	l.post(envelopesFrom(t, maya)[0])
	l.clk.Set(heard + 17*minute)
	check() // woken
	l.clk.Set(heard + 19*minute)
	check()
	silence(t, cj, l.srv.ServerKey(), jordan.id, l.cid, maya.id, heard, l.clk.Now())

	// A grant issued later renews it; one issued earlier, or at the same moment, is refused,
	// whatever its not_after.
	newer := grant(maya, l.cid, jordan.account, 30, l.clk.Now(), start+20*1440*minute)
	if r := l.putWatch(jordan, maya, newer); r.code != http.StatusNoContent {
		t.Fatalf("a newer grant: %d", r.code)
	}
	for _, old := range [][]byte{g, grant(maya, l.cid, jordan.account, 45, l.clk.Now(), start+21*1440*minute),
		grant(maya, l.cid, jordan.account, 30, start+minute, start+34*1440*minute)} {
		if r := l.putWatch(jordan, maya, old); r.code != http.StatusConflict {
			t.Errorf("an older grant: %d %s", r.code, r.body)
		}
	}
	if ws := l.watches(maya); len(ws) != 1 || ws[0]["after_min"] != float64(30) {
		t.Errorf("after renewal: %v", ws)
	}

	// The watched account ends it; the watcher is told and can't bring it back with the
	// grant it holds.
	path := "/v1/circles/" + b64(l.cid) + "/watches/" + b64(maya.id) + "?watcher=" + b64(jordan.account)
	expect(t, l.do(call{method: "DELETE", path: path, token: l.login(alex)}), http.StatusForbidden, "forbidden")
	expect(t, l.do(call{method: "DELETE", path: path, token: l.login(maya)}), http.StatusNoContent, "")
	if ev := awaitEvent(t, cj); ev["type"] != "watch_ended" || ev["reason"] != "deleted" || ev["watched_device_id"] != b64(maya.id) {
		t.Fatalf("watch_ended: %v", ev)
	}
	if ws := l.watches(jordan); len(ws) != 0 {
		t.Error("a revoked watch is still listed")
	}
	expect(t, l.do(call{method: "DELETE", path: path, token: l.login(maya)}), http.StatusNotFound, "not_found")
	for _, old := range [][]byte{g, newer} {
		if r := l.putWatch(jordan, maya, old); r.code != http.StatusConflict {
			t.Errorf("a revoked grant registered again: %d", r.code)
		}
	}
	// A grant made after the revocation is taken.
	fresh := grant(maya, l.cid, jordan.account, 30, l.clk.Now()+1, start+30*1440*minute)
	if r := l.putWatch(jordan, maya, fresh); r.code != http.StatusNoContent {
		t.Fatalf("a fresh grant: %d %s", r.code, r.body)
	}
	// The watcher may end its own, and register it again.
	expect(t, l.do(call{method: "DELETE", path: "/v1/circles/" + b64(l.cid) + "/watches/" + b64(maya.id), token: l.login(jordan)}),
		http.StatusNoContent, "")
	if ev := awaitEvent(t, cj); ev["reason"] != "deleted" {
		t.Fatalf("watch_ended: %v", ev)
	}
	if r := l.putWatch(jordan, maya, fresh); r.code != http.StatusNoContent {
		t.Fatalf("again after the watcher's own delete: %d", r.code)
	}

	// A watch ends when its grant runs out.
	l.clk.Set(start + 30*1440*minute)
	check()
	if ev := awaitEvent(t, cj); ev["type"] != "watch_ended" || ev["reason"] != "expired" {
		t.Fatalf("expired: %v", ev)
	}
	if ws := l.watches(jordan); len(ws) != 0 {
		t.Error("an expired watch is still listed")
	}
}

// Only circle envelopes count: a direct one doesn't reset the silence.
func TestWatchDirectEnvelopes(t *testing.T) {
	l := newLive(t, generous, api.StreamTimes{})
	jordan, alex := byLabel(l.devs, "jordan/phone"), byLabel(l.devs, "alex/phone")
	start := l.clk.Now()
	if r := l.putWatch(jordan, alex, grant(alex, l.cid, jordan.account, 15, start, start+1440*minute)); r.code != http.StatusNoContent {
		t.Fatalf("register: %d", r.code)
	}
	cj, _, _ := l.open(jordan, "")
	l.clk.Set(start + 10*minute)
	var direct []byte
	for _, raw := range envelopesFrom(t, alex) {
		if raw[3] == 2 { // kind: direct
			direct = raw
		}
	}
	if direct == nil {
		t.Fatal("no direct envelope from Alex")
	}
	l.post(direct)
	l.clk.Set(start + 15*minute)
	l.srv.CheckSilences()
	l.clk.Set(start + 17*minute)
	l.srv.CheckSilences()
	silence(t, cj, l.srv.ServerKey(), jordan.id, l.cid, alex.id, 0, l.clk.Now())
}

// A watch on a device that leaves the circle ends, and the watcher is told.
func TestWatchDeviceRemoved(t *testing.T) {
	l := newLive(t, generous, api.StreamTimes{})
	jordan, alex := byLabel(l.devs, "jordan/phone"), byLabel(l.devs, "alex/phone")
	now := l.clk.Now()
	if r := l.putWatch(alex, jordan, grant(jordan, l.cid, alex.account, 15, now, now+1440*minute)); r.code != http.StatusNoContent {
		t.Fatalf("register: %d", r.code)
	}
	ca, _, _ := l.open(alex, "")
	for _, raw := range logCase(t, "accepted_recovery_kit_used") { // the second removes Jordan's lost phone
		l.clk.Set(createdAt(raw))
		expect(t, l.octets("POST", "/v1/circles/"+b64(l.cid)+"/log", raw, l.login(l.devs[string(raw[68:84])])), http.StatusCreated, "")
	}
	if ev := awaitEvent(t, ca); ev["type"] != "watch_ended" || ev["reason"] != "device_removed" || ev["watched_device_id"] != b64(jordan.id) {
		t.Fatalf("watch_ended: %v", ev)
	}
	if ws := l.watches(alex); len(ws) != 0 {
		t.Error("the watch on the removed phone is still listed")
	}
}

// When the watched account ends a watch, no grant issued before then brings it back, not
// even one the watcher never registered and that runs out later than anything it did. The
// server remembers the ending for 35 days, as long as such a grant can be valid, through a
// new grant, the watcher's own delete and the new watch running out.
func TestWatchRevocation(t *testing.T) {
	l := newLive(t, generous, api.StreamTimes{})
	jordan, maya := byLabel(l.devs, "jordan/phone"), byLabel(l.devs, "maya/phone")
	start := l.clk.Now()
	registered := grant(maya, l.cid, jordan.account, 60, start, start+7*1440*minute)
	held := grant(maya, l.cid, jordan.account, 60, start+minute, start+minute+35*1440*minute) // kept back
	put := func(g []byte, want int, what string) {
		t.Helper()
		if r := l.putWatch(jordan, maya, g); r.code != want {
			t.Errorf("%s, %d minutes after the ending: %d %s", what, (l.clk.Now()-start)/minute-2, r.code, r.body)
		}
	}
	put(registered, http.StatusNoContent, "register")
	l.clk.Set(start + 2*minute)
	ended := l.clk.Now()
	path := "/v1/circles/" + b64(l.cid) + "/watches/" + b64(maya.id)
	expect(t, l.do(call{method: "DELETE", path: path + "?watcher=" + b64(jordan.account), token: l.login(maya)}),
		http.StatusNoContent, "")
	atEnd := grant(maya, l.cid, jordan.account, 60, ended, ended+35*1440*minute)
	put(registered, http.StatusConflict, "the registered grant")
	put(held, http.StatusConflict, "a grant held back")
	put(atEnd, http.StatusConflict, "a grant issued as the watch ended")

	// The ending outlasts the grant that was registered.
	l.clk.Set(ended + 8*1440*minute)
	if _, err := l.srv.Sweep(); err != nil {
		t.Fatal(err)
	}
	put(held, http.StatusConflict, "a grant held back, after the registered one ran out")

	// Maya grants it again, and renews it. The held grant still can't replace the new
	// watch, nor come back once Jordan ends it himself, nor once it runs out.
	fresh := grant(maya, l.cid, jordan.account, 60, l.clk.Now(), l.clk.Now()+7*1440*minute)
	put(fresh, http.StatusNoContent, "a grant issued after the ending")
	put(held, http.StatusConflict, "a grant held back, over a new watch")
	l.clk.Set(l.clk.Now() + minute)
	renewed := grant(maya, l.cid, jordan.account, 60, l.clk.Now(), l.clk.Now()+7*1440*minute)
	put(renewed, http.StatusNoContent, "a renewal")
	expect(t, l.do(call{method: "DELETE", path: path, token: l.login(jordan)}), http.StatusNoContent, "")
	put(held, http.StatusConflict, "a grant held back, after the watcher's own delete")
	put(renewed, http.StatusNoContent, "the renewal again")
	l.clk.Set(ended + 16*1440*minute)
	if err := l.srv.CheckSilences(); err != nil {
		t.Fatal(err)
	}
	if ws := l.watches(jordan); len(ws) != 0 {
		t.Errorf("the new watch is still listed after it ran out: %v", ws)
	}
	put(held, http.StatusConflict, "a grant held back, after the new watch ran out")

	// The ending is forgotten only once every grant issued before it has run out.
	l.clk.Set(ended + 35*1440*minute - 2*minute)
	if _, err := l.srv.Sweep(); err != nil {
		t.Fatal(err)
	}
	put(held, http.StatusConflict, "a grant held back, in its last minute")
	l.clk.Set(ended + 35*1440*minute)
	if _, err := l.srv.Sweep(); err != nil {
		t.Fatal(err)
	}
	put(held, http.StatusUnprocessableEntity, "a grant held back, run out")
	put(atEnd, http.StatusUnprocessableEntity, "a grant issued as the watch ended, run out")
	put(grant(maya, l.cid, jordan.account, 60, l.clk.Now(), l.clk.Now()+1440*minute), http.StatusNoContent, "a new grant")
}

// envelopesFrom returns valid envelopes of the vectors at entry 20 sent by the device.
func envelopesFrom(t *testing.T, d *device) [][]byte {
	var out [][]byte
	for _, c := range tv.Arr(tv.Obj(tv.Load(t)["envelopes"])["valid"]) {
		cc := tv.Obj(c)
		raw := tv.Hex(cc["raw"])
		if tv.Int(cc["log_seq"]) == 20 && bytes.Equal(raw[20:36], d.id) {
			out = append(out, raw)
		}
	}
	return out
}
