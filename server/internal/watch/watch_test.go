// SPDX-License-Identifier: AGPL-3.0-or-later

package watch_test

import (
	"encoding/hex"
	"testing"

	tv "github.com/gureetk/kinfold/server/internal/testvec"
	"github.com/gureetk/kinfold/server/internal/watch"
)

func TestWatchGrants(t *testing.T) {
	wg := tv.Obj(tv.Load(t)["watch_grants"])
	s := tv.MainLog(t).States[tv.Int(wg["log_seq"])]
	now := tv.Num(wg["now"])
	for _, c := range tv.Arr(wg["grants"]) {
		cc := tv.Obj(c)
		if _, ok := watch.Valid(s, tv.Hex(cc["grant"]), now); ok != tv.Bool(cc["valid"]) {
			t.Errorf("%s: valid %v", tv.Str(cc["name"]), ok)
		}
	}
	first := tv.Hex(tv.Obj(tv.Arr(wg["grants"])[0])["grant"])
	g, ok := watch.Parse(first)
	f := tv.Obj(wg["fields"])
	if !ok || hex.EncodeToString(g.CircleID) != tv.Str(f["circle_id"]) ||
		hex.EncodeToString(g.WatchedDevice) != tv.Str(f["watched_device_id"]) ||
		hex.EncodeToString(g.WatcherAccount) != tv.Str(f["watcher_account_id"]) ||
		uint64(g.AfterMin) != tv.Num(f["after_min"]) || g.IssuedAt != tv.Num(f["issued_at"]) ||
		g.NotAfter != tv.Num(f["not_after"]) {
		t.Error("fields of the first grant")
	}
	// The grant is valid from 10 minutes before its issued_at until not_after.
	for _, c := range []struct {
		now  uint64
		want bool
	}{{g.IssuedAt - watch.SkewMS - 1, false}, {g.IssuedAt - watch.SkewMS, true}, {g.NotAfter - 1, true}, {g.NotAfter, false}} {
		if _, ok := watch.Valid(s, first, c.now); ok != c.want {
			t.Errorf("valid %v at %d ms from issued_at", ok, int64(c.now-g.IssuedAt))
		}
	}
}

func FuzzGrant(f *testing.F) {
	wg := tv.Obj(tv.Load(f)["watch_grants"])
	for _, c := range tv.Arr(wg["grants"]) {
		f.Add(tv.Hex(tv.Obj(c)["grant"]))
	}
	s := tv.MainLog(f).States[tv.Int(wg["log_seq"])]
	now := tv.Num(wg["now"])
	f.Fuzz(func(t *testing.T, raw []byte) {
		if g, ok := watch.Parse(raw); ok && len(g.Raw) != watch.GrantLen {
			t.Fatal("a grant parsed from the wrong number of bytes")
		}
		if g, ok := watch.Valid(s, raw, now); ok && (g.AfterMin < watch.MinAfterMin || g.NotAfter <= now ||
			g.NotAfter <= g.IssuedAt || g.NotAfter-g.IssuedAt > watch.MaxLifeMS) {
			t.Fatal("an impossible grant was valid")
		}
	})
}
