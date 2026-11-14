// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/gureetk/kinfold/server/internal/envelope"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
)

// seen is an in-memory replay record.
type seen map[string][32]byte

func (s seen) Digest(sender []byte, seq uint64) ([32]byte, bool) {
	d, ok := s[fmt.Sprintf("%x/%d", sender, seq)]
	return d, ok
}

func (s seen) record(e *envelope.Envelope) {
	s[fmt.Sprintf("%x/%d", e.Sender, e.Seq)] = sha256.Sum256(e.Raw)
}

func reasonOf(err error) string {
	var r *envelope.Refused
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

// check returns "stored", "duplicate" or the reason code, and records what it stores.
func check(lg *tv.Log, logSeq int64, rec seen, raw []byte, now uint64) string {
	e, out, err := envelope.Check(lg.States[logSeq], lg.Upto(logSeq), rec, raw, now)
	switch {
	case err != nil:
		return reasonOf(err)
	case out == envelope.Duplicate:
		return "duplicate"
	}
	rec.record(e)
	return "stored"
}

func TestEnvelopeVectors(t *testing.T) {
	lg := tv.MainLog(t)
	env := tv.Obj(tv.Load(t)["envelopes"])
	now := tv.Num(env["receiver_now"])
	for _, c := range tv.Arr(env["valid"]) {
		cc := tv.Obj(c)
		if got := check(lg, tv.Int(cc["log_seq"]), seen{}, tv.Hex(cc["raw"]), now); got != "stored" {
			t.Errorf("valid %s: %s", tv.Str(cc["name"]), got)
		}
	}
	for _, group := range []string{"invalid", "server_rejects"} {
		for _, c := range tv.Arr(env[group]) {
			cc := tv.Obj(c)
			want := "stored" // null: only a recipient can find the fault, so a server stores it
			if s, ok := cc["server_error"].(string); ok {
				want = s
			}
			if got := check(lg, tv.Int(cc["log_seq"]), seen{}, tv.Hex(cc["raw"]), now); got != want {
				t.Errorf("%s %s: got %s, want %s", group, tv.Str(cc["name"]), got, want)
			}
		}
	}
	rp := tv.Obj(env["server_repost"])
	rec := seen{}
	for i, raw := range tv.Arr(rp["sequence"]) {
		want := tv.Str(tv.Arr(rp["results"])[i])
		if got := check(lg, tv.Int(rp["log_seq"]), rec, tv.Hex(raw), now); got != want {
			t.Errorf("repost %d: got %s, want %s", i, got, want)
		}
	}
}

// The time limits of step 8 hold to the millisecond, and no sum overflows for a sent_at
// near the end of the u64 range.
func TestTimeLimits(t *testing.T) {
	lg := tv.MainLog(t)
	env := tv.Obj(tv.Load(t)["envelopes"])
	c := tv.Obj(tv.Arr(env["valid"])[0])
	raw, sentAt := tv.Hex(c["raw"]), tv.Num(c["sent_at"])
	for _, tc := range []struct {
		now  uint64
		want string
	}{
		{sentAt + envelope.MaxAgeMS, "stored"},
		{sentAt + envelope.MaxAgeMS + 1, "expired"},
		{sentAt - envelope.MaxAheadMS, "stored"},
		{sentAt - envelope.MaxAheadMS - 1, "bad_time"},
	} {
		if got := check(lg, tv.Int(c["log_seq"]), seen{}, raw, tc.now); got != tc.want {
			t.Errorf("clock %d: got %s, want %s", tc.now, got, tc.want)
		}
	}
}

func FuzzCheck(f *testing.F) {
	env := tv.Obj(tv.Load(f)["envelopes"])
	for _, g := range []string{"valid", "invalid", "server_rejects"} {
		for _, c := range tv.Arr(env[g]) {
			f.Add(tv.Hex(tv.Obj(c)["raw"]))
		}
	}
	lg := tv.MainLog(f)
	now := tv.Num(env["receiver_now"])
	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, seq := range []int64{13, 20} {
			rec := seen{}
			e, out, err := envelope.Check(lg.States[seq], lg.Upto(seq), rec, raw, now)
			if err != nil {
				if reasonOf(err) == "" {
					t.Fatalf("a refusal without a reason code: %v", err)
				}
				continue
			}
			if out != envelope.Store || len(e.Wraps) == 0 || len(e.Wraps) > envelope.MaxWraps {
				t.Fatal("an impossible envelope was accepted")
			}
			rec.record(e)
			if _, out, err := envelope.Check(lg.States[seq], lg.Upto(seq), rec, raw, now); err != nil || out != envelope.Duplicate {
				t.Fatalf("posting the same bytes again: %v", err)
			}
		}
	})
}
