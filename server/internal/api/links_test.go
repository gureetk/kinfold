// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gureetk/kinfold/server/internal/api"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
)

// linkCase is one exchange of the vectors' device_link group.
type linkCase struct {
	direction                         int
	id                                []byte
	now                               uint64
	existing                          *device
	offer, commit, nonce, req, answer []byte
}

func linkCaseOf(t *testing.T, devs map[string]*device, name string) linkCase {
	c := tv.Obj(tv.Obj(tv.Load(t)["device_link"])[name])
	lc := linkCase{direction: int(tv.Int(c["direction"])), id: tv.Hex(c["link_id"]), now: tv.Num(c["now"]),
		existing: byLabel(devs, tv.Str(c["existing_device"])), commit: tv.Hex(c["commit_message"]),
		nonce: tv.Hex(c["nonce_message"]), req: tv.Hex(c["request"]), answer: tv.Hex(c["response"])}
	if tv.Has(c, "offer") {
		lc.offer = tv.Hex(c["offer"])
	}
	return lc
}

func (e *env) link(method string, lc linkCase, slot string, body, token []byte) *httptest.ResponseRecorder {
	path := "/v1/links/" + b64(lc.id) + "/" + slot
	if method == "GET" {
		return e.do(call{method: "GET", path: path, token: token})
	}
	return e.octets(method, path, body, token)
}

func (e *env) createLink(lc linkCase, life uint64, token []byte) *httptest.ResponseRecorder {
	return e.json("POST", "/v1/links", map[string]any{"link_id": b64(lc.id), "direction": lc.direction,
		"expires_at": e.clk.Now() + life}, token)
}

// The vectors' exchanges go through the mailbox slot by slot, each side reading what the
// other wrote.
func TestLinkExchanges(t *testing.T) {
	for _, name := range []string{"from_existing", "from_new", "from_existing_rotated"} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, generous)
			devs := devices(t)
			e.register(devs)
			lc := linkCaseOf(t, devs, name)
			e.clk.Set(lc.now)
			phone := e.login(lc.existing)
			got := func(slot string, token []byte, want []byte) {
				t.Helper()
				rec := e.link("GET", lc, slot, nil, token)
				if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), want) {
					t.Fatalf("read %s: %d", slot, rec.Code)
				}
			}
			put := func(slot string, body, token []byte) {
				t.Helper()
				expect(t, e.link("PUT", lc, slot, body, token), http.StatusNoContent, "")
			}
			if lc.direction == 1 {
				expect(t, e.createLink(lc, api.LinkLife1, phone), http.StatusCreated, "")
			} else {
				expect(t, e.createLink(lc, api.LinkLife2, nil), http.StatusCreated, "")
				expect(t, e.link("PUT", lc, "commit", lc.commit, nil), http.StatusConflict, "out_of_order")
				put("offer", lc.offer, phone)
				got("offer", nil, lc.offer)
			}
			expect(t, e.link("PUT", lc, "nonce", lc.nonce, phone), http.StatusConflict, "out_of_order")
			put("commit", lc.commit, nil)
			put("commit", lc.commit, nil) // the same again
			got("commit", phone, lc.commit)
			expect(t, e.link("PUT", lc, "request", lc.req, nil), http.StatusConflict, "out_of_order")
			put("nonce", lc.nonce, phone)
			got("nonce", nil, lc.nonce)
			expect(t, e.link("PUT", lc, "response", lc.answer, phone), http.StatusConflict, "out_of_order")
			put("request", lc.req, nil)
			got("request", phone, lc.req)
			put("response", lc.answer, phone)
			got("response", nil, lc.answer)
			// A minute after the response is first read, the mailbox has ended.
			e.clk.Advance(api.LinkAfterRead)
			expect(t, e.link("GET", lc, "response", nil, nil), http.StatusGone, "gone")
			if e.srv.SweepLinks() != 1 {
				t.Error("the ended mailbox wasn't swept")
			}
			expect(t, e.link("GET", lc, "response", nil, nil), http.StatusNotFound, "not_found")
		})
	}
}

// What the server refuses: other accounts, bytes it can tell are wrong, a second writer,
// and mailboxes that have run out.
func TestLinkRefusals(t *testing.T) {
	e := newEnv(t, generous)
	devs := devices(t)
	e.register(devs)
	lc := linkCaseOf(t, devs, "from_existing")
	e.clk.Set(lc.now)
	phone, alex, phone2 := e.login(lc.existing), e.login(byLabel(devs, "alex/phone")), e.login(byLabel(devs, "jordan/phone2"))

	expect(t, e.createLink(lc, api.LinkLife1, nil), http.StatusUnauthorized, "unauthorized")
	expect(t, e.createLink(lc, api.LinkLife1+1, phone), http.StatusBadRequest, "bad_request")
	expect(t, e.createLink(lc, api.LinkLife1, phone), http.StatusCreated, "")
	expect(t, e.link("PUT", lc, "offer", lc.commit, phone), http.StatusNotFound, "not_found") // no offer in direction 1
	expect(t, e.link("PUT", lc, "nothing", lc.commit, nil), http.StatusNotFound, "not_found")

	wrongType := append([]byte(nil), lc.commit...)
	wrongType[17] = 4 // a nonce message in the commit slot
	expect(t, e.link("PUT", lc, "commit", wrongType, nil), http.StatusUnprocessableEntity, "malformed")
	expect(t, e.link("PUT", lc, "commit", lc.commit[:len(lc.commit)-1], nil), http.StatusUnprocessableEntity, "malformed")
	expect(t, e.link("PUT", lc, "commit", make([]byte, 1025), nil), http.StatusRequestEntityTooLarge, "too_large")
	expect(t, e.link("PUT", lc, "commit", lc.commit, nil), http.StatusNoContent, "")
	other := append([]byte(nil), lc.commit...)
	other[len(other)-1] ^= 1
	expect(t, e.link("PUT", lc, "commit", other, nil), http.StatusConflict, "slot_taken")

	// Another account may neither read nor write; the new device's slots need no session,
	// the phone's need the mailbox's account.
	expect(t, e.link("GET", lc, "commit", nil, alex), http.StatusForbidden, "forbidden")
	expect(t, e.link("GET", lc, "commit", nil, nil), http.StatusUnauthorized, "unauthorized")
	expect(t, e.link("PUT", lc, "nonce", lc.nonce, alex), http.StatusForbidden, "forbidden")

	// A reader waiting for the nonce is answered when it is written.
	done := make(chan *httptest.ResponseRecorder)
	go func() {
		done <- e.do(call{method: "GET", path: "/v1/links/" + b64(lc.id) + "/nonce?wait=10"})
	}()
	time.Sleep(100 * time.Millisecond)
	expect(t, e.link("PUT", lc, "nonce", lc.nonce, phone), http.StatusNoContent, "")
	select {
	case rec := <-done:
		if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), lc.nonce) {
			t.Fatalf("waiting reader: %d", rec.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting reader wasn't woken")
	}
	expect(t, e.link("PUT", lc, "request", lc.req, nil), http.StatusNoContent, "")
	// The response must be signed by the device of the session that posts it.
	expect(t, e.link("PUT", lc, "response", lc.answer, phone2), http.StatusUnprocessableEntity, "malformed")

	// A mailbox ends at expires_at.
	e.clk.Advance(api.LinkLife1)
	expect(t, e.link("PUT", lc, "response", lc.answer, phone), http.StatusGone, "gone")
	e.srv.SweepLinks()
	expect(t, e.link("GET", lc, "request", nil, phone), http.StatusNotFound, "not_found")
}

// Direction 2 needs a server that takes web devices, and is limited per address.
func TestLinkDirection2(t *testing.T) {
	e := newEnv(t, generous)
	devs := devices(t)
	lc := linkCaseOf(t, devs, "from_new")
	e.admin("PATCH", "/settings", `{"web_devices": false}`)
	expect(t, e.createLink(lc, api.LinkLife2, nil), http.StatusForbidden, "forbidden")
	e.admin("PATCH", "/settings", `{"web_devices": true}`)
	expect(t, e.createLink(lc, api.LinkLife2+1, nil), http.StatusBadRequest, "bad_request")
	for i := range 4 { // the two refusals above count too
		lc.id = bytes.Repeat([]byte{byte(i)}, 16)
		expect(t, e.createLink(lc, api.LinkLife2, nil), http.StatusCreated, "")
	}
	lc.id = bytes.Repeat([]byte{9}, 16)
	expect(t, e.createLink(lc, api.LinkLife2, nil), http.StatusTooManyRequests, "rate_limited")
}
