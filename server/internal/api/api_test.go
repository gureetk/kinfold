// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gureetk/kinfold/server/internal/admin"
	"github.com/gureetk/kinfold/server/internal/api"
	"github.com/gureetk/kinfold/server/internal/clock"
	"github.com/gureetk/kinfold/server/internal/envelope"
	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/kcrypto"
	"github.com/gureetk/kinfold/server/internal/memberlog"
	"github.com/gureetk/kinfold/server/internal/store/memstore"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
	"github.com/gureetk/kinfold/server/internal/wire"
)

const url = "https://kinfold.example.org"

// env is a server with an injected clock and an in-memory store, called without a network.
type env struct {
	t   *testing.T
	clk *clock.Fake
	srv *api.Server
	adm http.Handler
}

func newEnv(t *testing.T, limits api.Limits) *env {
	seed := sha256.Sum256([]byte("kinfold api test server key"))
	key := ed25519.NewKeyFromSeed(seed[:])
	clk := clock.NewFake(1_793_635_200_000)
	st := memstore.New()
	e := &env{t: t, clk: clk, srv: api.New(api.Config{URL: url, Key: key, Clock: clk, Store: st, Limits: limits}),
		adm: (&admin.Admin{Store: st, Clock: clk, Key: key, URL: url}).Handler()}
	e.admin("PATCH", "/settings", `{"member_tokens": true, "web_devices": true}`)
	return e
}

func (e *env) admin(method, path, body string) map[string]any {
	e.t.Helper()
	rec := httptest.NewRecorder()
	e.adm.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	if rec.Code >= 300 {
		e.t.Fatalf("admin %s %s: %d %s", method, path, rec.Code, rec.Body)
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

type call struct {
	method, path string
	body         []byte
	ctype        string
	token        []byte
	header       map[string]string
}

func (e *env) do(c call) *httptest.ResponseRecorder {
	req := httptest.NewRequest(c.method, c.path, bytes.NewReader(c.body))
	req.Header.Set("Kinfold-Api", "1")
	if c.ctype != "" {
		req.Header.Set("Content-Type", c.ctype)
	}
	if c.token != nil {
		req.Header.Set("Authorization", "Bearer "+wire.EncodeB64u(c.token))
	}
	for k, v := range c.header {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	return rec
}

func (e *env) octets(method, path string, body, token []byte) *httptest.ResponseRecorder {
	return e.do(call{method: method, path: path, body: body, ctype: "application/octet-stream", token: token})
}

func (e *env) json(method, path string, v any, token []byte) *httptest.ResponseRecorder {
	b, _ := json.Marshal(v)
	return e.do(call{method: method, path: path, body: b, ctype: "application/json", token: token})
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON: %s", rec.Body)
	}
	return out
}

func expect(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) map[string]any {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("got %d %s, want %d %s", rec.Code, rec.Body, status, code)
	}
	if code == "" {
		return nil
	}
	out := decode(t, rec)
	if out["error"] != code {
		t.Fatalf("got error %v, want %s", out["error"], code)
	}
	return out
}

func frames(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = wire.AppendFrame(out, p)
	}
	return out
}

func b64(b []byte) string { return wire.EncodeB64u(b) }

// ---- the people of the vectors ----

type device struct {
	label   string
	id      []byte
	kind    uint8
	dsk     ed25519.PrivateKey
	cert    []byte
	bundle  []byte
	person  string
	chain   []byte
	account []byte
}

func devices(t *testing.T) map[string]*device {
	out := map[string]*device{}
	for name, p := range tv.Obj(tv.Load(t)["identities"]) {
		pp := tv.Obj(p)
		for _, dv := range tv.Obj(pp["devices"]) {
			d := tv.Obj(dv)
			dev := &device{label: tv.Str(d["label"]), id: tv.Hex(d["device_id"]), kind: uint8(tv.Num(d["kind"])),
				dsk: ed25519.NewKeyFromSeed(tv.Hex(d["dsk_seed"])), cert: tv.Hex(d["cert"]), person: name,
				chain: tv.Hex(pp["chain"]), account: tv.Hex(pp["account_id"])}
			if bs := tv.Arr(d["bundles"]); len(bs) > 0 {
				dev.bundle = tv.Hex(bs[0])
			}
			out[string(dev.id)] = dev
		}
	}
	return out
}

// register registers every device of the vectors: each person's phone with a token, then
// the person's other devices from that phone's session.
func (e *env) register(devs map[string]*device) {
	e.t.Helper()
	phones := map[string]*device{}
	for _, d := range devs {
		if d.kind == identity.Phone && (phones[d.person] == nil || d.label < phones[d.person].label) {
			phones[d.person] = d
		}
	}
	for _, p := range phones {
		tok, _ := wire.DecodeB64u(e.admin("POST", "/tokens", `{}`)["token"].(string))
		expect(e.t, e.octets("POST", "/v1/accounts", frames(p.cert, p.chain, p.bundle, tok), nil), http.StatusCreated, "")
	}
	for _, d := range devs {
		p := phones[d.person]
		if d == p {
			continue
		}
		body := frames(d.cert, d.bundle)
		if d.kind == identity.Recovery {
			body = frames(d.cert)
		}
		expect(e.t, e.octets("POST", "/v1/devices", body, e.login(p)), http.StatusCreated, "")
	}
}

// login runs the login of PROTOCOL.md §13.2 for a device.
func (e *env) login(d *device) []byte {
	e.t.Helper()
	ch := decode(e.t, e.json("POST", "/v1/auth/challenge", map[string]string{"device_id": b64(d.id)}, nil))
	challenge, _ := wire.DecodeB64u(ch["challenge"].(string))
	sig := kcrypto.Sign(d.dsk, "auth", e.srv.ServerKey(), challenge, d.id)
	rec := e.json("POST", "/v1/auth/session", map[string]string{"device_id": b64(d.id), "challenge": b64(challenge),
		"device_sig": b64(sig)}, nil)
	expect(e.t, rec, http.StatusOK, "")
	tok, _ := wire.DecodeB64u(decode(e.t, rec)["token"].(string))
	return tok
}

func byLabel(devs map[string]*device, label string) *device {
	for _, d := range devs {
		if d.label == label {
			return d
		}
	}
	panic("no device " + label)
}

func createdAt(raw []byte) uint64 { return wire.NewReader(raw[60:68]).U64() }

// replayMainLog posts entries 0 to upto of the main log through the API, each by its author
// at its own created_at, and returns the circle ID.
func (e *env) replayMainLog(devs map[string]*device, upto int) []byte {
	e.t.Helper()
	var cid []byte
	for i, ev := range tv.Arr(tv.Obj(tv.Load(e.t)["log"])["entries"])[:upto+1] {
		raw := tv.Hex(tv.Obj(ev)["raw"])
		e.clk.Set(createdAt(raw))
		tok := e.login(devs[string(raw[68:84])])
		if i == 0 {
			expect(e.t, e.octets("POST", "/v1/circles", raw, tok), http.StatusCreated, "")
			cid = kcrypto.H("circle-id", raw)[:16]
			continue
		}
		rec := e.octets("POST", "/v1/circles/"+b64(cid)+"/log", raw, tok)
		if rec.Code != http.StatusCreated {
			e.t.Fatalf("entry %d: %d %s", i, rec.Code, rec.Body)
		}
		if out := decode(e.t, rec); out["seq"] != float64(i) || out["head"] != b64(memberlog.Hash(raw)) {
			e.t.Fatalf("entry %d: %v", i, out)
		}
	}
	return cid
}

// generous are limits for tests that log in many times at one instant of the fake clock.
var generous = api.Limits{ChallengesPerDevice: 1 << 20, ChallengesPerAddress: 1 << 20, EnvelopesPerMinute: 1 << 20,
	EnvelopesPerHour: 1 << 20}

// logCase returns the entries of a case of the vectors' member log.
func logCase(t *testing.T, name string) [][]byte {
	for _, c := range tv.Arr(tv.Obj(tv.Load(t)["log"])["cases"]) {
		if cc := tv.Obj(c); tv.Str(cc["name"]) == name {
			var out [][]byte
			for _, e := range tv.Arr(cc["entries"]) {
				out = append(out, tv.Hex(tv.Obj(e)["raw"]))
			}
			return out
		}
	}
	t.Fatalf("no log case %s", name)
	return nil
}

// joinMessage is a JoinRequest or JoinResult as far as the server can see one.
func joinMessage(invite []byte, n byte) []byte {
	return wire.Concat([]byte{0}, invite, bytes.Repeat([]byte{n}, 12), wire.Vec32(bytes.Repeat([]byte{n}, 40)))
}

// ---- tests ----

// The main log of the vectors goes through the API entry by entry, each from a session of
// its author's device: every entry type, every device kind and a rotated identity key.
func TestMainLogThroughTheAPI(t *testing.T) {
	e := newEnv(t, generous)
	devs := devices(t)
	e.register(devs)
	cid := e.replayMainLog(devs, 20)

	tok := e.login(byLabel(devs, "jordan/phone"))
	rec := e.do(call{method: "GET", path: "/v1/circles/" + b64(cid) + "/log", token: tok})
	expect(t, rec, http.StatusOK, "")
	fs, err := wire.Frames(rec.Body.Bytes(), 1024, memberlog.MaxEntry)
	if err != nil || len(fs) != 21 || rec.Header().Get("Kinfold-Seq") != "20" {
		t.Fatalf("log: %d entries, %v", len(fs), err)
	}
	rec = e.do(call{method: "GET", path: "/v1/circles/" + b64(cid) + "/log?after=18&limit=1", token: tok})
	if fs, _ := wire.Frames(rec.Body.Bytes(), 10, memberlog.MaxEntry); len(fs) != 1 {
		t.Fatal("after and limit")
	}

	// The vectors' envelopes at entry 20, posted by their senders at the vectors' clock. Each
	// vector assumes an empty replay record, so only those a server refuses are posted
	// before the valid ones; refused envelopes leave no trace.
	envs := tv.Obj(tv.Load(t)["envelopes"])
	e.clk.Set(tv.Num(envs["receiver_now"]))
	sessions := map[string][]byte{}
	post := func(raw []byte) *httptest.ResponseRecorder {
		sender := devs[string(raw[20:36])]
		if sessions[sender.label] == nil {
			sessions[sender.label] = e.login(sender)
		}
		return e.octets("POST", "/v1/circles/"+b64(cid)+"/envelopes", raw, sessions[sender.label])
	}
	for _, group := range []string{"invalid", "server_rejects"} {
		for _, c := range tv.Arr(envs[group]) {
			cc := tv.Obj(c)
			raw := tv.Hex(cc["raw"])
			want, _ := cc["server_error"].(string)
			if tv.Int(cc["log_seq"]) != 20 || want == "" || len(raw) < 36 || devs[string(raw[20:36])] == nil ||
				devs[string(raw[20:36])].kind == identity.Recovery {
				continue
			}
			rec := post(raw)
			if rec.Code != http.StatusUnprocessableEntity || decode(t, rec)["error"] != want || decode(t, rec)["seq"] != float64(20) {
				t.Errorf("%s %s: %d %s, want 422 %s", group, tv.Str(cc["name"]), rec.Code, rec.Body, want)
			}
		}
	}
	// Valid vectors reuse a sender's seq: posted one after another, the first is stored and
	// the rest are replays, as they must be.
	addressed, posted := map[string]int{}, map[string]bool{}
	for _, c := range tv.Arr(envs["valid"]) {
		cc := tv.Obj(c)
		if tv.Int(cc["log_seq"]) != 20 {
			continue
		}
		raw := tv.Hex(cc["raw"])
		env, err := envelope.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		key := fmt.Sprintf("%x/%d", env.Sender, env.Seq)
		rec := post(raw)
		if posted[key] {
			if rec.Code != http.StatusUnprocessableEntity || decode(t, rec)["error"] != "replay" {
				t.Errorf("valid %s again under the same seq: %d %s", tv.Str(cc["name"]), rec.Code, rec.Body)
			}
			continue
		}
		posted[key] = true
		if rec.Code != http.StatusCreated {
			t.Errorf("valid %s: %d %s", tv.Str(cc["name"]), rec.Code, rec.Body)
		}
		for _, r := range env.Recipients() {
			addressed[string(r)]++
		}
	}
	if len(addressed) == 0 {
		t.Fatal("no valid envelope at entry 20")
	}
	// Every device finds exactly what was addressed to it; a removed one finds nothing.
	for id, d := range devs {
		if !identity.Receiving(d.kind) || d.label == "sam/phone" || d.label == "riley/phone" || d.label == "jordan/phone2" {
			continue
		}
		rec := e.do(call{method: "GET", path: "/v1/inbox", token: e.login(d)})
		expect(t, rec, http.StatusOK, "")
		fs, _ := wire.Frames(rec.Body.Bytes(), 256, 1<<20)
		if len(fs) != addressed[id] {
			t.Errorf("%s: %d records, %d addressed to it", d.label, len(fs), addressed[id])
		}
		for _, f := range fs {
			if wire.NewReader(f[:8]).U64() != e.clk.Now() {
				t.Errorf("%s: received_at", d.label)
			}
		}
	}
}

// bad_time needs the server's clock, so it is tested here with the clock injected: the
// entry is refused one millisecond past each side of the 10-minute window.
func TestBadTimeThroughTheAPI(t *testing.T) {
	e := newEnv(t, generous)
	devs := devices(t)
	e.register(devs)
	cid := e.replayMainLog(devs, 13)
	raw := tv.Hex(tv.Obj(tv.Arr(tv.Obj(tv.Load(t)["log"])["entries"])[14])["raw"])
	author := devs[string(raw[68:84])]
	at := createdAt(raw)
	for _, now := range []uint64{at + memberlog.ClockSkewMS + 1, at - memberlog.ClockSkewMS - 1} {
		e.clk.Set(now)
		out := expect(t, e.octets("POST", "/v1/circles/"+b64(cid)+"/log", raw, e.login(author)), http.StatusUnprocessableEntity, "bad_time")
		if out["seq"] != float64(13) {
			t.Errorf("bad_time carries the circle's seq: %v", out)
		}
	}
	e.clk.Set(at + memberlog.ClockSkewMS)
	expect(t, e.octets("POST", "/v1/circles/"+b64(cid)+"/log", raw, e.login(author)), http.StatusCreated, "")
}

func TestRequestMechanics(t *testing.T) {
	e := newEnv(t, api.Limits{})
	devs := devices(t)
	e.register(devs)
	phone := byLabel(devs, "jordan/phone")

	// Every response carries the server's time, errors included.
	rec := e.do(call{method: "GET", path: "/nothing/here"})
	expect(t, rec, http.StatusNotFound, "not_found")
	if rec.Header().Get("Kinfold-Time") != strconv.FormatUint(e.clk.Now(), 10) {
		t.Error("Kinfold-Time")
	}
	// API revisions.
	expect(t, e.do(call{method: "GET", path: "/v1/devices", header: map[string]string{"Kinfold-Api": ""}}), http.StatusBadRequest, "bad_request")
	out := expect(t, e.do(call{method: "GET", path: "/v1/devices", header: map[string]string{"Kinfold-Api": "0"}}), http.StatusUpgradeRequired, "update_required")
	if out["api_min"] != float64(1) {
		t.Error("api_min")
	}
	expect(t, e.do(call{method: "GET", path: "/v1/devices", header: map[string]string{"Kinfold-Api": "2"}}), http.StatusBadRequest, "bad_request")
	// Discovery needs no revision and no session.
	expect(t, e.do(call{method: "GET", path: "/.well-known/kinfold", header: map[string]string{"Kinfold-Api": ""}}), http.StatusOK, "")
	info, _ := wire.DecodeB64u(decode(t, e.do(call{method: "GET", path: "/.well-known/kinfold"}))["server_info"].(string))
	if si, ok := identity.ParseServerInfo(info); !ok || si.URL != url || !bytes.Equal(si.Key, e.srv.ServerKey()) {
		t.Error("server_info")
	}

	// Sessions.
	expect(t, e.do(call{method: "GET", path: "/v1/devices"}), http.StatusUnauthorized, "unauthorized")
	expect(t, e.do(call{method: "GET", path: "/v1/devices", token: []byte("not a session")}), http.StatusUnauthorized, "unauthorized")
	tok := e.login(phone)
	expect(t, e.do(call{method: "GET", path: "/v1/devices", token: tok}), http.StatusOK, "")
	e.clk.Advance(api.SessionLife)
	expect(t, e.do(call{method: "GET", path: "/v1/devices", token: tok}), http.StatusUnauthorized, "unauthorized")
	tok = e.login(phone)
	expect(t, e.do(call{method: "DELETE", path: "/v1/auth/session", token: tok}), http.StatusNoContent, "")
	expect(t, e.do(call{method: "GET", path: "/v1/devices", token: tok}), http.StatusUnauthorized, "unauthorized")

	// A challenge works once, for the device it names, for 60 seconds; an unknown device
	// gets one just the same.
	ch := decode(t, e.json("POST", "/v1/auth/challenge", map[string]string{"device_id": b64(phone.id)}, nil))
	c, _ := wire.DecodeB64u(ch["challenge"].(string))
	sig := kcrypto.Sign(phone.dsk, "auth", e.srv.ServerKey(), c, phone.id)
	bad := append([]byte(nil), sig...)
	bad[0] ^= 1
	session := func(sig []byte) *httptest.ResponseRecorder {
		return e.json("POST", "/v1/auth/session", map[string]string{"device_id": b64(phone.id), "challenge": b64(c), "device_sig": b64(sig)}, nil)
	}
	expect(t, session(bad), http.StatusUnauthorized, "unauthorized")
	expect(t, session(sig), http.StatusUnauthorized, "unauthorized") // spent by the failed attempt
	ch = decode(t, e.json("POST", "/v1/auth/challenge", map[string]string{"device_id": b64(phone.id)}, nil))
	c, _ = wire.DecodeB64u(ch["challenge"].(string))
	sig = kcrypto.Sign(phone.dsk, "auth", e.srv.ServerKey(), c, phone.id)
	e.clk.Advance(api.ChallengeLife)
	expect(t, session(sig), http.StatusUnauthorized, "unauthorized")
	unknown := decode(t, e.json("POST", "/v1/auth/challenge", map[string]string{"device_id": b64(make([]byte, 16))}, nil))
	if len(unknown) != 3 || unknown["challenge_sig"] == nil {
		t.Error("an unknown device's challenge looks different")
	}

	// Challenges are rate-limited per device: ten a minute.
	fresh := bytes.Repeat([]byte{0x5a}, 16)
	for i := 1; i <= 11; i++ {
		rec := e.json("POST", "/v1/auth/challenge", map[string]string{"device_id": b64(fresh)}, nil)
		if want := i <= 10; (rec.Code == http.StatusOK) != want {
			t.Fatalf("challenge %d: %d", i, rec.Code)
		}
		if i == 11 && rec.Header().Get("Retry-After") == "" {
			t.Error("no Retry-After")
		}
	}

	// Bodies: the content type is checked, and a body over the limit is 413.
	e.clk.Advance(api.ChallengeLife)
	tok = e.login(phone)
	expect(t, e.do(call{method: "POST", path: "/v1/circles", body: []byte("x"), ctype: "text/plain", token: tok}), http.StatusBadRequest, "bad_request")
	expect(t, e.octets("POST", "/v1/circles", make([]byte, memberlog.MaxEntry+1), tok), http.StatusRequestEntityTooLarge, "too_large")
	expect(t, e.octets("POST", "/v1/circles", make([]byte, 100), tok), http.StatusUnprocessableEntity, "malformed")

	// A web device may not create a circle (P only).
	for _, d := range devs {
		if d.kind == identity.Web {
			expect(t, e.octets("POST", "/v1/circles", make([]byte, 100), e.login(d)), http.StatusForbidden, "forbidden")
		}
	}

	// A server whose clock isn't synchronized answers nothing but /healthz.
	e.clk.SetSynced(false)
	expect(t, e.do(call{method: "GET", path: "/.well-known/kinfold"}), http.StatusServiceUnavailable, "unavailable")
	expect(t, e.do(call{method: "GET", path: "/healthz"}), http.StatusServiceUnavailable, "unavailable")
	e.clk.SetSynced(true)
	expect(t, e.do(call{method: "GET", path: "/healthz"}), http.StatusOK, "")
}

// A removed device can read the log up to and including the entry that removed it, for 30
// days, and the headers describe that entry (API.md §6).
func TestRemovedDeviceReadsItsRemoval(t *testing.T) {
	e := newEnv(t, generous)
	devs := devices(t)
	e.register(devs)
	cid := e.replayMainLog(devs, 13)
	tablet := byLabel(devs, "jordan/tablet") // added at entry 5, removed at entry 7
	tok := e.login(tablet)
	rec := e.do(call{method: "GET", path: "/v1/circles/" + b64(cid) + "/log", token: tok})
	expect(t, rec, http.StatusOK, "")
	fs, _ := wire.Frames(rec.Body.Bytes(), 1024, memberlog.MaxEntry)
	entry7 := tv.Hex(tv.Obj(tv.Arr(tv.Obj(tv.Load(t)["log"])["entries"])[7])["raw"])
	if len(fs) != 8 || !bytes.Equal(fs[7], entry7) || rec.Header().Get("Kinfold-Seq") != "7" ||
		rec.Header().Get("Kinfold-Head") != b64(memberlog.Hash(entry7)) {
		t.Fatalf("a removed device read %d entries, seq %s", len(fs), rec.Header().Get("Kinfold-Seq"))
	}
	rec = e.do(call{method: "GET", path: "/v1/circles/" + b64(cid) + "/log?after=7", token: tok})
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatal("nothing after the removal")
	}
	expect(t, e.do(call{method: "GET", path: "/v1/circles/" + b64(cid) + "/head", token: tok}), http.StatusNotFound, "not_found")
	e.clk.Advance(api.RemovedReadLife)
	tok = e.login(tablet)
	expect(t, e.do(call{method: "GET", path: "/v1/circles/" + b64(cid) + "/log", token: tok}), http.StatusNotFound, "not_found")
}

// In repair mode the normal path refuses appends and the repair path takes the entry that
// follows the head from any active device, whoever wrote it, at any age (API.md §6).
func TestRepairMode(t *testing.T) {
	e := newEnv(t, generous)
	devs := devices(t)
	e.register(devs)
	cid := e.replayMainLog(devs, 13)
	entries := tv.Arr(tv.Obj(tv.Load(t)["log"])["entries"])
	maya := byLabel(devs, "maya/phone")
	e.clk.Set(createdAt(tv.Hex(tv.Obj(entries[20])["raw"])) + 30*86_400_000)
	tok := e.login(maya)
	raw14 := tv.Hex(tv.Obj(entries[14])["raw"])
	expect(t, e.octets("POST", "/v1/circles/"+b64(cid)+"/log/repair", raw14, tok), http.StatusNotFound, "not_found")
	e.admin("POST", "/repair", `{"hours": 1}`)
	if disc := decode(t, e.do(call{method: "GET", path: "/.well-known/kinfold"})); disc["repair"] != true {
		t.Error("discovery doesn't report repair mode")
	}
	expect(t, e.octets("POST", "/v1/circles/"+b64(cid)+"/log", raw14, tok), http.StatusServiceUnavailable, "repair_mode")
	for i := 14; i <= 20; i++ { // Maya's phone re-posts what Jordan's and Alex's devices wrote, a month on
		rec := e.octets("POST", "/v1/circles/"+b64(cid)+"/log/repair", tv.Hex(tv.Obj(entries[i])["raw"]), tok)
		if rec.Code != http.StatusCreated {
			t.Fatalf("repair entry %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	e.admin("DELETE", "/repair", ``)
	expect(t, e.octets("POST", "/v1/circles/"+b64(cid)+"/log/repair", raw14, tok), http.StatusNotFound, "not_found")
}

func TestInvites(t *testing.T) {
	l := generous
	l.PendingInvites, l.WaitingRequests = 2, 2
	e := newEnv(t, l)
	devs := devices(t)
	e.register(devs)
	cid := e.replayMainLog(devs, 13)
	by := func(label string) *device { return byLabel(devs, label) }
	jordan, alex, maya, sam := e.login(by("jordan/phone")), e.login(by("alex/phone")), e.login(by("maya/phone")), e.login(by("sam/phone"))
	mk := func(n byte) []byte { return bytes.Repeat([]byte{n}, 16) }
	invite := func(id []byte, tok []byte) *httptest.ResponseRecorder {
		return e.json("POST", "/v1/invites", map[string]any{"circle_id": b64(cid), "invite_id": b64(id),
			"expires_at": e.clk.Now() + 3_600_000, "reg_token": true}, tok)
	}
	expect(t, invite(mk(1), maya), http.StatusForbidden, "forbidden") // only Jordan is an admin
	expect(t, invite(mk(1), alex), http.StatusForbidden, "forbidden")
	expect(t, invite(mk(1), jordan), http.StatusCreated, "")
	if tok := decode(t, invite(mk(1), jordan))["reg_token"]; tok == nil {
		t.Error("member tokens are on, but no token")
	}
	expect(t, invite(mk(2), jordan), http.StatusCreated, "")
	expect(t, invite(mk(3), jordan), http.StatusTooManyRequests, "rate_limited") // two pending

	join := joinMessage
	path, path2 := "/v1/invites/"+b64(mk(1)), "/v1/invites/"+b64(mk(2))
	expect(t, e.octets("POST", path+"/requests", join(mk(2), 1), sam), http.StatusUnprocessableEntity, "malformed") // another invite's ID
	expect(t, e.octets("POST", path+"/requests", join(mk(1), 1), sam), http.StatusCreated, "")
	expect(t, e.octets("POST", path+"/requests", join(mk(1), 1), sam), http.StatusCreated, "") // the same again
	expect(t, e.octets("POST", path+"/requests", join(mk(1), 2), sam), http.StatusCreated, "")
	expect(t, e.octets("POST", path+"/requests", join(mk(1), 3), sam), http.StatusTooManyRequests, "rate_limited")
	expect(t, e.do(call{method: "GET", path: path + "/requests", token: alex}), http.StatusForbidden, "forbidden")
	rec := e.do(call{method: "GET", path: path + "/requests", token: jordan})
	if fs, _ := wire.Frames(rec.Body.Bytes(), 10, 4096); len(fs) != 2 {
		t.Fatalf("%d requests", len(fs))
	}
	// Posting an invite again keeps its requests and the expiry it was first given.
	repost := func(id []byte, expires uint64) {
		expect(t, e.json("POST", "/v1/invites", map[string]any{"circle_id": b64(cid), "invite_id": b64(id),
			"expires_at": expires, "reg_token": true}, jordan), http.StatusCreated, "")
	}
	repost(mk(1), e.clk.Now()+7_200_000)
	rec = e.do(call{method: "GET", path: path + "/requests", token: jordan})
	if fs, _ := wire.Frames(rec.Body.Bytes(), 10, 4096); len(fs) != 2 {
		t.Fatalf("%d requests after posting the invite again", len(fs))
	}
	repost(mk(2), e.clk.Now()+1_800_000) // half an hour; the hour it was given stands

	// A reader waiting for the result is answered when it is written.
	got := make(chan *httptest.ResponseRecorder)
	go func() { got <- e.do(call{method: "GET", path: path + "/result?wait=10", token: sam}) }()
	time.Sleep(100 * time.Millisecond)
	result := join(mk(1), 9)
	expect(t, e.octets("PUT", path+"/result", result, jordan), http.StatusNoContent, "")
	select {
	case rec := <-got:
		if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), result) {
			t.Fatalf("waiting reader: %d", rec.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting reader wasn't woken")
	}
	expect(t, e.octets("PUT", path+"/result", result, jordan), http.StatusNoContent, "")
	expect(t, e.octets("PUT", path+"/result", join(mk(1), 8), jordan), http.StatusConflict, "slot_taken")
	expect(t, e.do(call{method: "GET", path: path + "/result", token: maya}), http.StatusForbidden, "forbidden") // asked nothing
	// 45 minutes on, past the half hour asked for the second time, the invite is still open.
	e.clk.Advance(2_700_000)
	expect(t, e.octets("POST", path2+"/requests", join(mk(2), 1), sam), http.StatusCreated, "")
	// A result is kept for a day after it is written.
	e.clk.Advance(api.ResultKeep)
	sam = e.login(by("sam/phone"))
	expect(t, e.do(call{method: "GET", path: path + "/result", token: sam}), http.StatusGone, "gone")

	// The inviter (or another admin) may delete an invite; it is then gone.
	jordan = e.login(by("jordan/phone"))
	expect(t, e.do(call{method: "DELETE", path: path2, token: e.login(by("maya/phone"))}), http.StatusForbidden, "forbidden")
	expect(t, e.do(call{method: "DELETE", path: path2, token: jordan}), http.StatusNoContent, "")
	expect(t, e.octets("POST", path2+"/requests", join(mk(2), 1), e.login(by("sam/phone"))), http.StatusGone, "gone")
	expect(t, e.do(call{method: "GET", path: "/v1/invites/" + b64(mk(7)) + "/requests", token: jordan}), http.StatusNotFound, "not_found")
}

// An inviter who leaves the circle takes its invites along: nobody else may read their
// requests. Another admin's invite stays open.
func TestInvitesEndWithTheInviter(t *testing.T) {
	e := newEnv(t, generous)
	devs := devices(t)
	e.register(devs)
	cid := e.replayMainLog(devs, 13)
	entries := logCase(t, "accepted_guardian_repair") // Alex is made an admin again, then Jordan leaves
	post := func(raw []byte) {
		e.clk.Set(createdAt(raw))
		expect(t, e.octets("POST", "/v1/circles/"+b64(cid)+"/log", raw, e.login(devs[string(raw[68:84])])), http.StatusCreated, "")
	}
	post(entries[0])
	jordan, alex, sam := e.login(byLabel(devs, "jordan/phone")), e.login(byLabel(devs, "alex/phone")), e.login(byLabel(devs, "sam/phone"))
	for n, tok := range map[byte][]byte{1: jordan, 2: alex} {
		id := bytes.Repeat([]byte{n}, 16)
		expect(t, e.json("POST", "/v1/invites", map[string]any{"circle_id": b64(cid), "invite_id": b64(id),
			"expires_at": e.clk.Now() + api.InviteMaxLife, "reg_token": true}, tok), http.StatusCreated, "")
		expect(t, e.octets("POST", "/v1/invites/"+b64(id)+"/requests", joinMessage(id, n), sam), http.StatusCreated, "")
	}
	post(entries[1])
	jordans, alexs := "/v1/invites/"+b64(bytes.Repeat([]byte{1}, 16)), "/v1/invites/"+b64(bytes.Repeat([]byte{2}, 16))
	expect(t, e.do(call{method: "GET", path: jordans + "/requests", token: e.login(byLabel(devs, "jordan/phone"))}), http.StatusGone, "gone")
	expect(t, e.octets("POST", jordans+"/requests", joinMessage(bytes.Repeat([]byte{1}, 16), 3), e.login(byLabel(devs, "sam/phone"))), http.StatusGone, "gone")
	rec := e.do(call{method: "GET", path: alexs + "/requests", token: e.login(byLabel(devs, "alex/phone"))})
	if fs, _ := wire.Frames(rec.Body.Bytes(), 10, 4096); rec.Code != http.StatusOK || len(fs) != 1 {
		t.Fatalf("Alex's invite: %d, %d requests", rec.Code, len(fs))
	}
}

// A refused upload counts against the limits like an accepted one: checking it costs
// signature verifications. A log entry posted again is known by its bytes and doesn't count;
// an envelope posted again is checked again and does.
func TestRefusalsCount(t *testing.T) {
	t.Run("log", func(t *testing.T) {
		l := generous
		l.AppendsPerDevice = 2
		e := newEnv(t, l)
		devs := devices(t)
		e.register(devs)
		genesis := tv.Hex(tv.Obj(tv.Arr(tv.Obj(tv.Load(t)["log"])["entries"])[0])["raw"])
		e.clk.Set(createdAt(genesis))
		tok := e.login(byLabel(devs, "jordan/phone"))
		bad := logCase(t, "fatal_genesis_bad_cert")[0]
		expect(t, e.octets("POST", "/v1/circles", genesis, tok), http.StatusCreated, "")
		expect(t, e.octets("POST", "/v1/circles", bad, tok), http.StatusUnprocessableEntity, "bad_cert")
		expect(t, e.octets("POST", "/v1/circles", bad, tok), http.StatusTooManyRequests, "rate_limited")
		// The same GENESIS again succeeds, past the limit and past the 10 minutes of bad_time.
		e.clk.Advance(memberlog.ClockSkewMS + 1)
		out := decode(t, e.octets("POST", "/v1/circles", genesis, tok))
		if out["circle_id"] != b64(kcrypto.H("circle-id", genesis)[:16]) {
			t.Fatalf("GENESIS again: %v", out)
		}
	})
	t.Run("envelopes", func(t *testing.T) {
		l := generous
		l.EnvelopesPerMinute = 2
		e := newEnv(t, l)
		devs := devices(t)
		e.register(devs)
		cid := e.replayMainLog(devs, 20)
		envs := tv.Obj(tv.Load(t)["envelopes"])
		e.clk.Set(tv.Num(envs["receiver_now"]))
		var first, second []byte // two valid envelopes from one sender under one seq
		bySeq := map[string][]byte{}
		for _, c := range tv.Arr(envs["valid"]) {
			cc := tv.Obj(c)
			if tv.Int(cc["log_seq"]) != 20 {
				continue
			}
			raw := tv.Hex(cc["raw"])
			env, err := envelope.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			key := fmt.Sprintf("%x/%d", env.Sender, env.Seq)
			if prev := bySeq[key]; prev != nil && !bytes.Equal(prev, raw) && first == nil {
				first, second = prev, raw
			}
			bySeq[key] = raw
		}
		if first == nil {
			t.Fatal("no two valid envelopes share a sender and a seq")
		}
		tok, path := e.login(devs[string(first[20:36])]), "/v1/circles/"+b64(cid)+"/envelopes"
		expect(t, e.octets("POST", path, first, tok), http.StatusCreated, "")
		expect(t, e.octets("POST", path, second, tok), http.StatusUnprocessableEntity, "replay")
		expect(t, e.octets("POST", path, first, tok), http.StatusTooManyRequests, "rate_limited")
		e.clk.Advance(60_000)
		expect(t, e.octets("POST", path, first, tok), http.StatusCreated, "")
	})
}

// Registration refuses what the log would refuse, and a token works once.
func TestRegistration(t *testing.T) {
	e := newEnv(t, api.Limits{})
	devs := devices(t)
	phone, web := byLabel(devs, "riley/phone"), byLabel(devs, "jordan/web")
	tok, _ := wire.DecodeB64u(e.admin("POST", "/tokens", `{}`)["token"].(string))
	expect(t, e.octets("POST", "/v1/accounts", frames(web.cert, nil, web.bundle, tok), nil), http.StatusUnprocessableEntity, "kind_not_allowed")
	expect(t, e.octets("POST", "/v1/accounts", frames(phone.cert, nil, phone.bundle, tok), nil), http.StatusUnprocessableEntity, "bad_cert") // Riley rotated: the chain is needed
	expect(t, e.octets("POST", "/v1/accounts", frames(phone.cert, phone.chain, phone.bundle, []byte("nope")), nil), http.StatusForbidden, "bad_token")
	e.clk.Set(wire.NewReader(phone.bundle[75:83]).U64()) // not_after: the bundle has run out
	expect(t, e.octets("POST", "/v1/accounts", frames(phone.cert, phone.chain, phone.bundle, tok), nil), http.StatusUnprocessableEntity, "bad_bundle")
	e.clk.Set(1_793_635_200_000)
	expect(t, e.octets("POST", "/v1/accounts", frames(phone.cert, phone.chain, phone.bundle, tok), nil), http.StatusCreated, "")
	expect(t, e.octets("POST", "/v1/accounts", frames(phone.cert, phone.chain, phone.bundle, tok), nil), http.StatusForbidden, "bad_token")
}
