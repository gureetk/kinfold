// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/gureetk/kinfold/server/internal/api"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// send writes one message from the device on its stream.
func send(t *testing.T, c *websocket.Conn, typ websocket.MessageType, msg []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, typ, msg); err != nil {
		t.Fatal(err)
	}
}

// streamPost posts an envelope on a stream and reads its result: the status and JSON the
// upload call would have answered.
func streamPost(t *testing.T, c *websocket.Conn, id uint32, wake byte, raw []byte) (int, map[string]any) {
	t.Helper()
	send(t, c, websocket.MessageBinary, wire.Concat([]byte{0x10}, wire.U32(id), []byte{wake}, raw))
	body := await(t, c, 0x11)
	r := wire.NewReader(body)
	if got := r.U32(); got != id {
		t.Fatalf("the result of post %d, for %d", got, id)
	}
	status := int(r.U16())
	var out map[string]any
	if err := json.Unmarshal(body[6:], &out); err != nil {
		t.Fatalf("the result's JSON: %q", body[6:])
	}
	return status, out
}

// Uploads over the stream (API.md §7, stream_post): each post is stored as the upload call
// would store it, and answered with what that call would have said.
func TestStreamPost(t *testing.T) {
	l := newLive(t, generous, api.StreamTimes{})
	jordan, maya := byLabel(l.devs, "jordan/phone"), byLabel(l.devs, "maya/phone")
	cj, _, _ := l.open(jordan, "")
	cm, _, _ := l.open(maya, "")
	f1 := envelopeNamed(t, "f1") // Jordan's phone's location, to every receiving device

	status, out := streamPost(t, cj, 7, 0, f1)
	if status != http.StatusCreated || out["received_at"] != float64(l.clk.Now()) {
		t.Fatalf("posted: %d %v", status, out)
	}
	if rec := await(t, cm, 0x01); !bytes.Equal(rec[8:], f1) {
		t.Fatal("Maya's stream didn't get the record")
	}
	first := out["received_at"]
	l.clk.Advance(1000)
	if status, out := streamPost(t, cj, 8, 0, f1); status != http.StatusCreated || out["received_at"] != first {
		t.Fatalf("posted twice: %d %v", status, out)
	}
	if rec := l.do(call{method: "GET", path: "/v1/inbox", token: l.login(maya)}); bytes.Count(rec.Body.Bytes(), f1) != 1 {
		t.Fatal("stored twice")
	}

	// What the upload call refuses, a post is refused alike.
	tampered := bytes.Clone(f1)
	tampered[len(tampered)-1] ^= 1
	elsewhere := bytes.Clone(f1)
	copy(elsewhere[4:20], bytes.Repeat([]byte{9}, 16))
	for _, tc := range []struct {
		wake   byte
		raw    []byte
		status int
		code   string
	}{
		{0, envelopeNamed(t, "f2"), http.StatusForbidden, "forbidden"}, // Jordan's browser's envelope
		{2, f1, http.StatusBadRequest, "bad_request"},                  // locate is for direct envelopes
		{3, f1, http.StatusBadRequest, "bad_request"},                  // no such wake
		{0, []byte("too short to be an envelope"), 422, "malformed"},   // no circle to name
		{0, tampered, 422, "bad_signature"},
		{0, elsewhere, http.StatusNotFound, "not_found"},                       // a circle Jordan isn't in
		{0, bytes.Repeat([]byte{1}, 40<<10), http.StatusNotFound, "not_found"}, // past the library's 32 KiB default
	} {
		status, out := streamPost(t, cj, 9, tc.wake, tc.raw)
		if status != tc.status || out["error"] != tc.code {
			t.Errorf("wake %d, %d bytes: %d %v", tc.wake, len(tc.raw), status, out)
		}
		if tc.code == "bad_signature" && (out["seq"] != 20.0 || out["head"] == nil) {
			t.Errorf("a refusal carries the circle's seq and head: %v", out)
		}
	}

	// A server whose clock isn't synchronized takes nothing.
	l.clk.SetSynced(false)
	if status, out := streamPost(t, cj, 10, 0, f1); status != http.StatusServiceUnavailable || out["error"] != "unavailable" {
		t.Errorf("unsynchronized: %d %v", status, out)
	}
	l.clk.SetSynced(true)
}

// A post past the limits gets 429 with retry_after, since a result has no headers; anything
// but a post message, or one over the size of an envelope, closes the stream.
func TestStreamPostLimits(t *testing.T) {
	limits := generous
	limits.EnvelopesPerMinute = 1
	l := newLive(t, limits, api.StreamTimes{})
	jordan := byLabel(l.devs, "jordan/phone")
	c, _, _ := l.open(jordan, "")
	f1 := envelopeNamed(t, "f1")
	if status, _ := streamPost(t, c, 1, 0, f1); status != http.StatusCreated {
		t.Fatalf("first: %d", status)
	}
	status, out := streamPost(t, c, 2, 0, f1)
	if status != http.StatusTooManyRequests || out["error"] != "rate_limited" || out["retry_after"] == nil {
		t.Fatalf("past the limit: %d %v", status, out)
	}

	for _, tc := range []struct {
		typ  websocket.MessageType
		msg  []byte
		code websocket.StatusCode
	}{
		{websocket.MessageText, []byte("hello"), websocket.StatusPolicyViolation},
		{websocket.MessageBinary, []byte{0x99, 0, 0, 0, 1, 0, 1}, websocket.StatusPolicyViolation},
		{websocket.MessageBinary, []byte{0x10, 0, 0, 0}, websocket.StatusPolicyViolation},
		{websocket.MessageBinary, make([]byte, 6+92232+1), websocket.StatusMessageTooBig},
	} {
		c, _, _ := l.open(jordan, "")
		send(t, c, tc.typ, tc.msg)
		closedWith(t, c, tc.code)
	}
	if disc := decode(t, l.do(call{method: "GET", path: "/.well-known/kinfold"})); !slices.Contains(disc["features"].([]any), any("stream_post")) {
		t.Fatalf("features: %v", disc["features"])
	}
}
