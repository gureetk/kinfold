// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"strconv"
	"testing"
)

func TestLimiterWindows(t *testing.T) {
	l := newLimiter(Limits{})
	now := uint64(1_800_000_030_000) // half a minute into a window
	for i := range 3 {
		if ok, _ := l.allow("k", 2, minute, now); ok != (i < 2) {
			t.Fatalf("call %d", i)
		}
	}
	if _, wait := l.allow("k", 2, minute, now); wait != 30 {
		t.Errorf("wait %d s, want the 30 s left in the window", wait)
	}
	if ok, _ := l.allow("k", 2, minute, now+30_000); !ok {
		t.Error("the next window doesn't start afresh")
	}
}

// A key per call, as a flood from many addresses makes: closed windows are swept away, so
// the limiter holds about what the open windows need, not everything it has seen.
func TestLimiterForgetsClosedWindows(t *testing.T) {
	l := newLimiter(Limits{})
	now, most := uint64(1_800_000_000_000), 0
	for i := range 200_000 {
		l.allow("address/"+strconv.Itoa(i), 1, minute, now)
		now += 5 // 12,000 new keys in every minute
		most = max(most, len(l.count))
	}
	if most > 4*12_000 {
		t.Errorf("the limiter held %d windows at once", most)
	}
}
