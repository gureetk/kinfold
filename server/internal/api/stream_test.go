// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gureetk/kinfold/server/internal/api"
	"github.com/gureetk/kinfold/server/internal/envelope"
	"github.com/gureetk/kinfold/server/internal/memberlog"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// live is a server on a real listener, with the people of the vectors registered and the
// main log in place.
type live struct {
	*env
	base string
	devs map[string]*device
	cid  []byte
}

func newLive(t *testing.T, limits api.Limits, times api.StreamTimes, opts ...func(*api.Config)) *live {
	e := newEnv(t, limits, append([]func(*api.Config){func(c *api.Config) { c.Stream = times }}, opts...)...)
	devs := devices(t)
	e.register(devs)
	cid := e.replayMainLog(devs, 20)
	e.clk.Set(tv.Num(tv.Obj(tv.Load(t)["envelopes"])["receiver_now"]))
	hs := httptest.NewServer(e.srv)
	t.Cleanup(hs.Close)
	return &live{env: e, base: hs.URL, devs: devs, cid: cid}
}

func (l *live) dial(tok []byte, since string) (*websocket.Conn, *http.Response, error) {
	u := "ws" + strings.TrimPrefix(l.base, "http") + "/v1/stream"
	if since != "" {
		u += "?since=" + since
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h := http.Header{"Kinfold-Api": {"1"}}
	if tok != nil {
		h.Set("Authorization", "Bearer "+b64(tok))
	}
	return websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: h})
}

// open dials a device's stream and reads what comes first: the time, the records waiting
// and a cursor.
func (l *live) open(d *device, since string) (*websocket.Conn, [][]byte, string) {
	l.t.Helper()
	c, _, err := l.dial(l.login(d), since)
	if err != nil {
		l.t.Fatalf("%s: %v", d.label, err)
	}
	l.t.Cleanup(func() { c.CloseNow() })
	typ, body := next(l.t, c)
	if typ != 0x06 || wire.NewReader(body).U64() != l.clk.Now() || len(body) != 8 {
		l.t.Fatalf("%s: first message %#x, not the time", d.label, typ)
	}
	var records [][]byte
	for {
		typ, body := next(l.t, c)
		switch typ {
		case 0x01:
			records = append(records, body)
		case 0x02:
			return c, records, string(body)
		default:
			l.t.Fatalf("%s: message %#x before the first cursor", d.label, typ)
		}
	}
}

func next(t *testing.T, c *websocket.Conn) (byte, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	typ, b, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if typ != websocket.MessageBinary || len(b) == 0 {
		t.Fatalf("a message of type %v, %d bytes", typ, len(b))
	}
	return b[0], b[1:]
}

func event(t *testing.T, c *websocket.Conn) map[string]any {
	t.Helper()
	typ, body := next(t, c)
	var ev map[string]any
	if typ != 0x05 || json.Unmarshal(body, &ev) != nil {
		t.Fatalf("message %#x, not an event", typ)
	}
	return ev
}

// closedWith reads until the stream closes, and checks the code.
func closedWith(t *testing.T, c *websocket.Conn, code websocket.StatusCode) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		if _, _, err := c.Read(ctx); err != nil {
			if got := websocket.CloseStatus(err); got != code {
				t.Fatalf("closed with %d (%v), want %d", got, err, code)
			}
			return
		}
	}
}

// envelopesFor returns valid envelopes of the vectors at entry 20 that name the device, one
// per sender and seq.
func envelopesFor(t *testing.T, d *device) [][]byte {
	var out [][]byte
	seen := map[string]bool{}
	for _, c := range tv.Arr(tv.Obj(tv.Load(t)["envelopes"])["valid"]) {
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
		if seen[key] || !slices.ContainsFunc(env.Recipients(), func(r []byte) bool { return bytes.Equal(r, d.id) }) {
			continue
		}
		seen[key] = true
		out = append(out, raw)
	}
	return out
}

func (l *live) post(raw []byte) {
	l.t.Helper()
	sender := l.devs[string(raw[20:36])]
	expect(l.t, l.octets("POST", "/v1/circles/"+b64(l.cid)+"/envelopes", raw, l.login(sender)), http.StatusCreated, "")
}

// ---- tests ----

// A stream sends the time, what waits after the cursor, a cursor, then records as they are
// stored, each followed by a cursor; and nothing a device isn't sent.
func TestStreamRecords(t *testing.T) {
	l := newLive(t, generous, api.StreamTimes{})
	maya := byLabel(l.devs, "maya/phone")
	envs := envelopesFor(t, maya)
	if len(envs) < 3 {
		t.Fatalf("%d envelopes for Maya", len(envs))
	}
	l.post(envs[0])
	l.post(envs[1])

	c, records, cursor := l.open(maya, "")
	if len(records) != 2 || !bytes.Equal(records[0][8:], envs[0]) || !bytes.Equal(records[1][8:], envs[1]) ||
		wire.NewReader(records[0][:8]).U64() != l.clk.Now() {
		t.Fatalf("%d records waiting", len(records))
	}
	// The cursor is the inbox's: the inbox has nothing after it.
	rec := l.do(call{method: "GET", path: "/v1/inbox?since=" + cursor, token: l.login(maya)})
	if rec.Body.Len() != 0 || rec.Header().Get("Kinfold-Cursor") != cursor {
		t.Fatalf("the inbox after the stream's cursor: %d bytes", rec.Body.Len())
	}
	// A record stored now arrives at once, with a new cursor.
	l.post(envs[2])
	typ, body := next(t, c)
	if typ != 0x01 || !bytes.Equal(body[8:], envs[2]) {
		t.Fatalf("live: %#x", typ)
	}
	typ, body = next(t, c)
	if typ != 0x02 || string(body) == cursor {
		t.Fatalf("no new cursor after a live record: %#x", typ)
	}
	cursor = string(body)

	// Reconnecting with the cursor sends nothing again; with the first cursor, the rest.
	c.Close(websocket.StatusNormalClosure, "")
	_, records, again := l.open(maya, cursor)
	if len(records) != 0 || again != cursor {
		t.Fatalf("%d records after the last cursor", len(records))
	}
	rec = l.do(call{method: "GET", path: "/v1/inbox?limit=1", token: l.login(maya)})
	_, records, _ = l.open(maya, rec.Header().Get("Kinfold-Cursor"))
	if len(records) != 2 {
		t.Fatalf("%d records after the first", len(records))
	}
}

// An append tells every active device of the circle; a device it removes hears that
// instead, and gets no more of the circle's records.
func TestStreamLog(t *testing.T) {
	l := newLive(t, generous, api.StreamTimes{})
	maya, web := byLabel(l.devs, "maya/phone"), byLabel(l.devs, "jordan/web")
	cm, _, _ := l.open(maya, "")
	cw, _, _ := l.open(web, "")
	raw := logCase(t, "accepted_web_device_removes_itself")[0]
	l.clk.Set(createdAt(raw))
	expect(t, l.octets("POST", "/v1/circles/"+b64(l.cid)+"/log", raw, l.login(web)), http.StatusCreated, "")

	typ, body := next(t, cm)
	if typ != 0x03 || !bytes.Equal(body, wire.Concat(l.cid, wire.U64(21), memberlog.Hash(raw))) {
		t.Fatalf("log frame: %#x %x", typ, body)
	}
	ev := event(t, cw)
	if ev["type"] != "removed" || ev["circle_id"] != b64(l.cid) || ev["seq"] != float64(21) {
		t.Fatalf("removed: %v", ev)
	}
}

// The inviter's phones hear of a join request.
func TestStreamJoinRequest(t *testing.T) {
	l := newLive(t, generous, api.StreamTimes{})
	jordan := byLabel(l.devs, "jordan/phone")
	c, _, _ := l.open(jordan, "")
	id := bytes.Repeat([]byte{7}, 16)
	expect(t, l.json("POST", "/v1/invites", map[string]any{"circle_id": b64(l.cid), "invite_id": b64(id),
		"expires_at": l.clk.Now() + 3_600_000}, l.login(jordan)), http.StatusCreated, "")
	expect(t, l.octets("POST", "/v1/invites/"+b64(id)+"/requests", joinMessage(id, 1), l.login(byLabel(l.devs, "sam/phone"))), http.StatusCreated, "")
	if ev := event(t, c); ev["type"] != "join_request" || ev["invite_id"] != b64(id) {
		t.Fatalf("join_request: %v", ev)
	}
}

// How streams end: replaced, logged out, deregistered, rate limited, restarting.
func TestStreamEnds(t *testing.T) {
	l := newLive(t, api.Limits{ChallengesPerDevice: 1 << 20, ChallengesPerAddress: 1 << 20, StreamsPerMinute: 4}, api.StreamTimes{})
	maya, alex := byLabel(l.devs, "maya/phone"), byLabel(l.devs, "alex/phone")

	first, _, _ := l.open(maya, "")
	second, _, _ := l.open(maya, "")
	closedWith(t, first, api.CloseReplaced)

	// Logging out ends the stream of that session; another session's stream stays.
	tok := l.login(maya)
	c, _, err := l.dial(tok, "")
	if err != nil {
		t.Fatal(err)
	}
	next(t, c) // the time
	next(t, c) // the cursor
	closedWith(t, second, api.CloseReplaced)
	expect(t, l.do(call{method: "DELETE", path: "/v1/auth/session", token: tok}), http.StatusNoContent, "")
	closedWith(t, c, api.CloseSessionEnded)

	// A fifth connection in a minute is refused.
	third, _, _ := l.open(maya, "")
	if c, _, err := l.dial(l.login(maya), ""); err != nil {
		t.Fatal(err)
	} else {
		closedWith(t, c, api.CloseRateLimited)
	}
	third.CloseNow()

	// Deregistering a device ends its stream.
	tablet := byLabel(l.devs, "alex/tablet")
	ct, _, _ := l.open(tablet, "")
	expect(t, l.do(call{method: "DELETE", path: "/v1/devices/" + b64(tablet.id), token: l.login(alex)}), http.StatusNoContent, "")
	closedWith(t, ct, api.CloseSessionEnded)

	// Repair mode and a restart are told to every stream.
	ca, _, _ := l.open(alex, "")
	l.admin("POST", "/repair", `{"hours": 1}`)
	if ev := event(t, ca); ev["type"] != "notice" || ev["code"] != "repair_mode" {
		t.Fatalf("repair notice: %v", ev)
	}
	closed := make(chan struct{})
	go func() { l.srv.CloseStreams(5 * time.Second); close(closed) }()
	if ev := event(t, ca); ev["type"] != "notice" || ev["code"] != "restarting" {
		t.Fatalf("restart notice: %v", ev)
	}
	closedWith(t, ca, api.CloseRestarting)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("CloseStreams didn't return once the streams had closed")
	}
	// Once shutting down, a new stream is closed at once.
	if c, _, err := l.dial(l.login(alex), ""); err != nil {
		t.Fatal(err)
	} else {
		closedWith(t, c, api.CloseRestarting)
	}
}

// Who may open a stream, and what is refused before the upgrade.
func TestStreamRefusals(t *testing.T) {
	l := newLive(t, generous, api.StreamTimes{})
	if _, resp, err := l.dial(nil, ""); err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no session: %v", err)
	}
	kit := byLabel(l.devs, "jordan/recovery")
	if _, resp, err := l.dial(l.login(kit), ""); err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("a recovery device: %v", err)
	}
	if _, resp, err := l.dial(l.login(byLabel(l.devs, "maya/phone")), "nope"); err == nil || resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a bad cursor: %v", err)
	}
	// A plain GET is told the stream is a WebSocket, not that the app is too old.
	expect(t, l.do(call{method: "GET", path: "/v1/stream", token: l.login(byLabel(l.devs, "maya/phone"))}), http.StatusBadRequest, "bad_request")
}

// A device that sends nothing, not even a ping, is closed after the idle time; one that
// pings stays. A session that runs out closes its stream. The time comes again and again.
func TestStreamTimes(t *testing.T) {
	l := newLive(t, generous, api.StreamTimes{Time: 50 * time.Millisecond, Idle: 400 * time.Millisecond, Check: 20 * time.Millisecond})
	maya, alex := byLabel(l.devs, "maya/phone"), byLabel(l.devs, "alex/phone")
	quiet, _, _ := l.open(maya, "")
	pinging, _, _ := l.open(alex, "")
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() { // a ping needs a reader for its pong: the test's reads below
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				pinging.Ping(ctx)
				cancel()
			}
		}
	}()
	times := 0
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if typ, body := next(t, pinging); typ == 0x06 && len(body) == 8 {
			times++
		}
	}
	if times < 5 {
		t.Errorf("%d time messages in a second", times)
	}
	close(stop)
	<-stopped
	// The session's end, on the server's clock, comes before the idle time.
	l.clk.Advance(api.SessionLife)
	closedWith(t, pinging, api.CloseSessionEnded)
	closedWith(t, quiet, api.CloseIdle)
}
