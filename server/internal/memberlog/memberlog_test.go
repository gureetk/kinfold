// SPDX-License-Identifier: AGPL-3.0-or-later

package memberlog_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/gureetk/kinfold/server/internal/memberlog"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
)

func reasonOf(err error) string {
	var f *memberlog.Fatal
	if errors.As(err, &f) {
		return f.Reason
	}
	return ""
}

// run applies one vector entry in public mode and checks the outcome, the hash and the
// public state.
func run(t *testing.T, s *memberlog.State, e tv.V, tag string) *memberlog.State {
	t.Helper()
	raw := tv.Hex(e["raw"])
	ns, _, err := memberlog.Apply(s, raw)
	result := "accepted"
	if err != nil {
		result = "fatal"
	}
	wantReason, _ := e["public_reason"].(string)
	if result != tv.Str(e["public_result"]) || reasonOf(err) != wantReason {
		t.Errorf("%s: got %s %q, want %s %q", tag, result, reasonOf(err), tv.Str(e["public_result"]), wantReason)
	}
	if hex.EncodeToString(memberlog.Hash(raw)) != tv.Str(e["hash"]) {
		t.Errorf("%s: hash", tag)
	}
	if ns == nil {
		return s
	}
	if st, ok := e["state_after"]; ok {
		if got, want := tv.Normalize(ns.PublicJSON()), tv.PublicOnly(st); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: public state\n got %v\nwant %v", tag, got, want)
		}
	}
	return ns
}

func TestMainLogAndCases(t *testing.T) {
	lg := tv.Obj(tv.Load(t)["log"])
	s := memberlog.New()
	var states []*memberlog.State
	for _, e := range tv.Arr(lg["entries"]) {
		ee := tv.Obj(e)
		s = run(t, s, ee, fmt.Sprintf("seq %v", ee["seq"]))
		states = append(states, s)
	}
	if hex.EncodeToString(s.CircleID) != tv.Str(lg["circle_id"]) || s.Seq != tv.Int(lg["final_seq"]) {
		t.Fatal("circle_id or final seq")
	}
	cases := tv.Arr(lg["cases"])
	for _, c := range cases {
		cc := tv.Obj(c)
		cs := memberlog.New()
		if base := tv.Int(cc["base_seq"]); base >= 0 {
			cs = states[base]
		}
		for _, e := range tv.Arr(cc["entries"]) {
			cs = run(t, cs, tv.Obj(e), tv.Str(cc["name"]))
		}
	}
	if len(cases) != 206 {
		t.Errorf("%d cases; PROTOCOL.md §17 promises 206", len(cases))
	}
	// Apply never changes the state it is given.
	if got, want := tv.Normalize(states[13].PublicJSON()), tv.PublicOnly(tv.Obj(tv.Arr(lg["entries"])[13])["state_after"]); !reflect.DeepEqual(got, want) {
		t.Error("a case changed the state it started from")
	}
}

// bad_time depends on the server's clock, so no vector can cover it (§6.7). The clock is
// injected: an entry is checked at times on both sides of each 10-minute boundary.
func TestBadTimeWithInjectedClock(t *testing.T) {
	entries := tv.Arr(tv.Obj(tv.Load(t)["log"])["entries"])
	s := memberlog.New()
	for i, e := range entries[:14] {
		raw := tv.Hex(tv.Obj(e)["raw"])
		ns, entry, err := memberlog.Apply(s, raw)
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if i == 13 {
			at := entry.CreatedAt
			for _, c := range []struct {
				now    uint64
				repair bool
				want   string
			}{
				{at, false, ""},
				{at + memberlog.ClockSkewMS, false, ""},
				{at + memberlog.ClockSkewMS + 1, false, "bad_time"},
				{at - memberlog.ClockSkewMS, false, ""},
				{at - memberlog.ClockSkewMS - 1, false, "bad_time"},
				// Repair mode: any age, but never more than 10 minutes ahead.
				{at + 365*86_400_000, true, ""},
				{at - memberlog.ClockSkewMS, true, ""},
				{at - memberlog.ClockSkewMS - 1, true, "bad_time"},
			} {
				_, _, err := memberlog.Append(s, raw, c.now, c.repair)
				if got := reasonOf(err); got != c.want {
					t.Errorf("created_at %d, clock %d, repair %v: got %q, want %q", at, c.now, c.repair, got, c.want)
				}
			}
			// A fatal entry is reported as such whatever the clock says.
			bad := append([]byte(nil), raw...)
			bad[len(bad)-1] ^= 1
			if _, _, err := memberlog.Append(s, bad, at+3_600_000, false); reasonOf(err) != "bad_signature" {
				t.Errorf("a bad signature at a bad time: got %v", err)
			}
		}
		s = ns
	}
	if err := memberlog.CheckTime(^uint64(0), 0, true); reasonOf(err) != "bad_time" {
		t.Error("created_at at the end of the u64 range")
	}
	if err := memberlog.CheckTime(0, ^uint64(0), false); reasonOf(err) != "bad_time" {
		t.Error("a clock at the end of the u64 range")
	}
}

// fuzzStates are the empty log and the main log after entries 13 and 20.
func fuzzStates(f *testing.F) []*memberlog.State {
	out := []*memberlog.State{memberlog.New()}
	s := memberlog.New()
	for i, e := range tv.Arr(tv.Obj(tv.Load(f)["log"])["entries"]) {
		raw := tv.Hex(tv.Obj(e)["raw"])
		ns, _, err := memberlog.Apply(s, raw)
		if err != nil {
			f.Fatal(err)
		}
		s = ns
		if i == 13 || i == 20 {
			out = append(out, s)
		}
		f.Add(raw)
	}
	return out
}

func FuzzParseEntry(f *testing.F) {
	fuzzStates(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := memberlog.ParseEntry(raw)
		if err != nil {
			if r := reasonOf(err); r != "malformed" && r != "too_large" {
				t.Fatalf("ParseEntry failed with %q", r)
			}
			return
		}
		if len(e.Sig) != 64 || 88+4+len(e.Body)+64 != len(raw) {
			t.Fatal("entry framing")
		}
	})
}

func FuzzApply(f *testing.F) {
	states := fuzzStates(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, s := range states {
			before := tv.Normalize(s.PublicJSON())
			ns, e, err := memberlog.Apply(s, raw)
			if !reflect.DeepEqual(before, tv.Normalize(s.PublicJSON())) {
				t.Fatal("Apply changed the state it was given")
			}
			if err != nil {
				if reasonOf(err) == "" {
					t.Fatalf("a failure without a reason code: %v", err)
				}
				continue
			}
			if ns.Seq != int64(e.Seq) || ns.Seq != s.Seq+1 || len(ns.Members) > memberlog.MaxMembers {
				t.Fatal("accepted entry left an impossible state")
			}
			for _, m := range ns.Members {
				if len(m.Devices) == 0 || len(m.Devices) > memberlog.MaxDevices {
					t.Fatal("a member with no devices, or too many")
				}
			}
			// A circle whose last member left is closed (§6.4); any other has an admin.
			if len(ns.Members) > 0 && ns.Admins() == 0 {
				t.Fatal("a circle without an admin")
			}
			// The same entry can't be appended twice.
			if _, _, err := memberlog.Apply(ns, raw); reasonOf(err) != "bad_seq" && reasonOf(err) != "unexpected_genesis" {
				t.Fatalf("appending the same entry again: %v", err)
			}
		}
	})
}
