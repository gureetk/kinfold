// SPDX-License-Identifier: AGPL-3.0-or-later

// Package storetest holds the tests that every store.Store implementation must pass, so
// that the server behaves the same on each.
package storetest

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/gureetk/kinfold/server/internal/memberlog"
	"github.com/gureetk/kinfold/server/internal/store"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
)

// Run runs every test, each on a new, empty store from open.
func Run(t *testing.T, open func(t *testing.T) store.Store) {
	for _, c := range []struct {
		name string
		fn   func(*testing.T, store.Store)
	}{
		{"Records", records},
		{"Circles", circles},
		{"ClosedCircle", closedCircle},
		{"Envelopes", envelopes},
		{"Invites", invites},
		{"FailedUpdateLeavesNothing", failedUpdate},
		{"PanicLeavesNothing", panicking},
		{"Sweep", sweeping},
	} {
		t.Run(c.name, func(t *testing.T) { c.fn(t, open(t)) })
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func update(t *testing.T, s store.Store, fn func(store.Tx) error) {
	t.Helper()
	must(t, s.Update(fn))
}

func view(t *testing.T, s store.Store, fn func(store.Tx) error) {
	t.Helper()
	must(t, s.View(fn))
}

func id(n byte) []byte { return bytes.Repeat([]byte{n}, 16) }

// entries returns the raw entries of the vectors' main log and, after base, of a case.
func entries(t *testing.T, caseName string) [][]byte {
	log := tv.Obj(tv.Load(t)["log"])
	var out [][]byte
	for _, e := range tv.Arr(log["entries"]) {
		out = append(out, tv.Hex(tv.Obj(e)["raw"]))
	}
	if caseName == "" {
		return out
	}
	for _, c := range tv.Arr(log["cases"]) {
		if cc := tv.Obj(c); tv.Str(cc["name"]) == caseName {
			out = out[:tv.Int(cc["base_seq"])+1]
			for _, e := range tv.Arr(cc["entries"]) {
				out = append(out, tv.Hex(tv.Obj(e)["raw"]))
			}
			return out
		}
	}
	t.Fatalf("no log case %s", caseName)
	return nil
}

// states replays entries in public mode.
func states(t *testing.T, raws [][]byte) []*memberlog.State {
	var out []*memberlog.State
	s := memberlog.New()
	for i, raw := range raws {
		ns, _, err := memberlog.Apply(s, raw)
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		s = ns
		out = append(out, s)
	}
	return out
}

// load stores a circle from raws, entry i appended at time at+i.
func load(t *testing.T, s store.Store, raws [][]byte, at uint64) *memberlog.State {
	sts := states(t, raws)
	update(t, s, func(tx store.Tx) error {
		if err := tx.CreateCircle(store.Circle{ID: sts[0].CircleID, State: sts[0], CreatedAt: at}, raws[0]); err != nil {
			return err
		}
		for i := 1; i < len(raws); i++ {
			if err := tx.AppendEntry(sts[0].CircleID, raws[i], sts[i], at+uint64(i)); err != nil {
				return err
			}
		}
		return nil
	})
	return sts[len(sts)-1]
}

func sameState(t *testing.T, got, want *memberlog.State) {
	t.Helper()
	if got == nil || !reflect.DeepEqual(got.PublicJSON(), want.PublicJSON()) || got.RecvChanged != want.RecvChanged {
		t.Fatalf("state at seq %d differs from the one stored", want.Seq)
	}
}

// ---- tests ----

func records(t *testing.T, s store.Store) {
	view(t, s, func(tx store.Tx) error {
		if st, err := tx.Settings(); err != nil || st != (store.Settings{}) {
			t.Errorf("a new store's settings: %+v %v", st, err)
		}
		return nil
	})
	acc := store.Account{ID: id(1), IK: id(2), Chain: []byte("chain"), CreatedAt: 5}
	rec := store.Device{ID: id(3), Account: id(1), Kind: 4, DSK: id(5), Cert: []byte("cert"), CreatedAt: 6, LastSeenAt: 7}
	phone := store.Device{ID: id(4), Account: id(1), Kind: 1, DSK: id(6), Cert: []byte("cert"), Bundle: []byte("bundle")}
	update(t, s, func(tx store.Tx) error {
		must(t, tx.PutSettings(store.Settings{MemberTokens: true, RepairUntil: 1 << 50}))
		must(t, tx.PutToken(store.Token{Hash: id(8), CreatedAt: 2, ExpiresAt: 9}))
		must(t, tx.PutToken(store.Token{Hash: id(7), CreatedAt: 1, ExpiresAt: 9, Spent: true, Invite: id(9)}))
		must(t, tx.PutAccount(acc))
		must(t, tx.PutAccount(store.Account{ID: id(2), IK: id(2), Operator: true}))
		must(t, tx.PutDevice(phone))
		must(t, tx.PutDevice(rec))
		must(t, tx.PutDevice(store.Device{ID: id(9), Account: id(2), Kind: 1, DSK: id(1), Cert: []byte("c"), Bundle: []byte("b")}))
		must(t, tx.PutChallenge(store.Challenge{Challenge: id(10), Device: id(4), ExpiresAt: 60}))
		must(t, tx.PutSession(store.Session{Hash: id(11), Device: id(4), ExpiresAt: 100}))
		must(t, tx.PutSession(store.Session{Hash: id(12), Device: id(4), ExpiresAt: 100}))
		must(t, tx.PutSession(store.Session{Hash: id(13), Device: id(9), ExpiresAt: 100}))
		return nil
	})
	update(t, s, func(tx store.Tx) error {
		if st, _ := tx.Settings(); st != (store.Settings{MemberTokens: true, RepairUntil: 1 << 50}) {
			t.Errorf("settings: %+v", st)
		}
		toks, _ := tx.Tokens()
		if len(toks) != 2 || !bytes.Equal(toks[0].Hash, id(7)) || !toks[0].Spent || !bytes.Equal(toks[0].Invite, id(9)) ||
			toks[1].Invite != nil || toks[1].Spent {
			t.Errorf("tokens, oldest first: %+v", toks)
		}
		must(t, tx.DeleteToken(id(8)))
		if err := tx.DeleteToken(id(8)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("deleting a missing token: %v", err)
		}
		if _, err := tx.Token(id(8)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a deleted token: %v", err)
		}
		if a, err := tx.Account(id(1)); err != nil || !reflect.DeepEqual(a, acc) {
			t.Errorf("account: %+v %v", a, err)
		}
		if a, _ := tx.Account(id(2)); !a.Operator || len(a.Chain) != 0 {
			t.Errorf("operator: %+v", a)
		}
		devs, _ := tx.DevicesOf(id(1))
		if len(devs) != 2 || !reflect.DeepEqual(devs[0], rec) || !reflect.DeepEqual(devs[1], phone) || devs[0].Bundle != nil {
			t.Errorf("devices, by ID: %+v", devs)
		}
		must(t, tx.DeleteDevice(id(3)))
		if _, err := tx.Device(id(3)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a deleted device: %v", err)
		}
		must(t, tx.DeleteAccount(id(2)))
		if _, err := tx.Account(id(2)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a deleted account: %v", err)
		}
		// A challenge works once.
		if c, err := tx.TakeChallenge(id(10)); err != nil || !bytes.Equal(c.Device, id(4)) || c.ExpiresAt != 60 {
			t.Errorf("challenge: %+v %v", c, err)
		}
		if _, err := tx.TakeChallenge(id(10)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a challenge taken twice: %v", err)
		}
		must(t, tx.DeleteSession(id(11)))
		must(t, tx.DeleteSessionsOf(id(4)))
		for n, want := range map[byte]bool{11: false, 12: false, 13: true} {
			if _, err := tx.Session(id(n)); (err == nil) != want {
				t.Errorf("session %d: %v", n, err)
			}
		}
		return nil
	})
}

func circles(t *testing.T, s store.Store) {
	raws := entries(t, "")
	sts := states(t, raws)
	cid := sts[0].CircleID
	view(t, s, func(tx store.Tx) error {
		if _, err := tx.Circle(cid); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a missing circle: %v", err)
		}
		if _, err := tx.Entries(cid, -1, 10, 1<<20); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("entries of a missing circle: %v", err)
		}
		if _, _, err := tx.SeqOf(cid, id(1)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("SeqOf in a missing circle: %v", err)
		}
		return nil
	})
	load(t, s, raws[:8], 1000)
	update(t, s, func(tx store.Tx) error {
		// Each append is visible in the transaction that makes it.
		for i := 8; i < len(raws); i++ {
			must(t, tx.AppendEntry(cid, raws[i], sts[i], 1000+uint64(i)))
			c, err := tx.Circle(cid)
			must(t, err)
			sameState(t, c.State, sts[i])
		}
		return nil
	})
	view(t, s, func(tx store.Tx) error {
		c, err := tx.Circle(cid)
		must(t, err)
		sameState(t, c.State, sts[len(sts)-1])
		if !bytes.Equal(c.ID, cid) || c.CreatedAt != 1000 {
			t.Errorf("circle: %x %d", c.ID, c.CreatedAt)
		}
		all, _ := tx.Entries(cid, -1, 1024, 1<<20)
		if len(all) != len(raws) {
			t.Fatalf("%d entries", len(all))
		}
		for i, raw := range raws {
			if !bytes.Equal(all[i], raw) {
				t.Fatalf("entry %d", i)
			}
			if seq, ok, err := tx.SeqOf(cid, memberlog.Hash(raw)); err != nil || !ok || seq != int64(i) {
				t.Errorf("SeqOf entry %d: %d %v %v", i, seq, ok, err)
			}
		}
		if _, ok, err := tx.SeqOf(cid, id(1)); ok || err != nil {
			t.Errorf("SeqOf an unknown hash: %v %v", ok, err)
		}
		page, _ := tx.Entries(cid, 3, 2, 1<<20)
		if len(page) != 2 || !bytes.Equal(page[0], raws[4]) || !bytes.Equal(page[1], raws[5]) {
			t.Error("entries after 3, two of them")
		}
		page, _ = tx.Entries(cid, 3, 10, len(raws[4])+len(raws[5]))
		if len(page) != 2 {
			t.Errorf("a byte limit that fits two entries gave %d", len(page))
		}
		if page, _ = tx.Entries(cid, 3, 10, 1); len(page) != 1 {
			t.Errorf("a byte limit gives at least one entry, not %d", len(page))
		}
		if page, _ = tx.Entries(cid, int64(len(raws)-1), 10, 1<<20); len(page) != 0 {
			t.Error("entries after the head")
		}
		// Every member finds the circle; nobody else does.
		for acc := range sts[len(sts)-1].Members {
			cs, err := tx.CirclesOf([]byte(acc))
			if err != nil || len(cs) != 1 || !bytes.Equal(cs[0].ID, cid) {
				t.Errorf("CirclesOf a member: %d %v", len(cs), err)
			} else {
				sameState(t, cs[0].State, sts[len(sts)-1])
			}
		}
		if cs, _ := tx.CirclesOf(id(1)); len(cs) != 0 {
			t.Error("CirclesOf someone else")
		}
		return nil
	})
	rm := store.Removal{Circle: cid, Device: id(5), Seq: 7, At: 1007}
	update(t, s, func(tx store.Tx) error { return tx.PutRemoval(rm) })
	view(t, s, func(tx store.Tx) error {
		if r, err := tx.Removal(cid, id(5)); err != nil || !reflect.DeepEqual(r, rm) {
			t.Errorf("removal: %+v %v", r, err)
		}
		if _, err := tx.Removal(cid, id(6)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a missing removal: %v", err)
		}
		return nil
	})
}

// The last member leaves: the circle stays, with no one in it, until a sweep (below).
func closedCircle(t *testing.T, s store.Store) {
	raws := entries(t, "accepted_last_member_leaves")
	sts := states(t, raws)
	before := sts[13]
	load(t, s, raws, 1000)
	view(t, s, func(tx store.Tx) error {
		c, err := tx.Circle(sts[0].CircleID)
		must(t, err)
		sameState(t, c.State, sts[len(sts)-1])
		if len(c.State.Members) != 0 {
			t.Fatal("the circle isn't closed")
		}
		for acc := range before.Members {
			if cs, _ := tx.CirclesOf([]byte(acc)); len(cs) != 0 {
				t.Error("a member who left still finds the circle")
			}
		}
		return nil
	})
}

func envelopes(t *testing.T, s store.Store) {
	cid, other := id(1), id(2)
	me, you := id(3), id(4)
	update(t, s, func(tx store.Tx) error {
		var last uint64
		put := func(e store.Envelope) {
			seq, err := tx.PutEnvelope(e)
			must(t, err)
			if seq <= last {
				t.Fatalf("envelope seq %d after %d", seq, last)
			}
			last = seq
		}
		for i := 0; i < 5; i++ {
			put(store.Envelope{Circle: cid, Sender: you, Recipients: [][]byte{me, you}, ReceivedAt: 7, ExpiresAt: 1000, Raw: make([]byte, 100)})
			put(store.Envelope{Circle: other, Sender: you, Recipients: [][]byte{me}, ExpiresAt: 1000, Raw: make([]byte, 100)})
			put(store.Envelope{Circle: cid, Sender: me, Recipients: [][]byte{you}, ExpiresAt: 1000, Raw: []byte{1}})
		}
		put(store.Envelope{Circle: cid, Sender: you, Recipients: [][]byte{me}, ExpiresAt: 10, Raw: []byte{2}})
		return nil
	})
	view(t, s, func(tx store.Tx) error {
		page, more, _ := tx.Inbox(me, [][]byte{cid}, 0, 2, 1<<20, 50)
		if len(page) != 2 || !more || page[0].ReceivedAt != 7 || len(page[0].Raw) != 100 || !bytes.Equal(page[0].Circle, cid) {
			t.Fatalf("first page: %d, more %v", len(page), more)
		}
		rest, more, _ := tx.Inbox(me, [][]byte{cid}, page[1].Seq, 10, 1<<20, 50)
		if len(rest) != 3 || more || rest[0].Seq <= page[1].Seq {
			t.Fatalf("rest: %d, more %v (the expired one left out)", len(rest), more)
		}
		both, _, _ := tx.Inbox(me, [][]byte{other, cid}, 0, 100, 1<<20, 50)
		if len(both) != 10 || !slices.IsSortedFunc(both, func(a, b store.Envelope) int { return int(a.Seq) - int(b.Seq) }) {
			t.Fatalf("two circles: %d, in order of arrival", len(both))
		}
		small, more, _ := tx.Inbox(me, [][]byte{cid}, 0, 10, 150, 50)
		if len(small) != 1 || !more {
			t.Fatalf("a byte limit: %d, more %v", len(small), more)
		}
		if early, _, _ := tx.Inbox(me, [][]byte{cid}, 0, 10, 1<<20, 9); len(early) != 6 {
			t.Fatalf("before the short one expires: %d", len(early))
		}
		if none, more, _ := tx.Inbox(me, nil, 0, 10, 1<<20, 50); len(none) != 0 || more {
			t.Fatal("no circles, no records")
		}
		return nil
	})
	// The replay record takes any u64 seq.
	big := uint64(1)<<63 + 5
	r := store.SeenRecord{Digest: [32]byte{9}, ReceivedAt: 11, KeepUntil: 12}
	update(t, s, func(tx store.Tx) error { return tx.PutSeen(cid, you, big, r) })
	view(t, s, func(tx store.Tx) error {
		if got, ok, err := tx.Seen(cid, you, big); err != nil || !ok || got != r {
			t.Errorf("seen: %+v %v %v", got, ok, err)
		}
		for _, k := range []struct {
			c, s []byte
			n    uint64
		}{{other, you, big}, {cid, me, big}, {cid, you, 5}} {
			if _, ok, _ := tx.Seen(k.c, k.s, k.n); ok {
				t.Error("a record under another key")
			}
		}
		return nil
	})
}

func invites(t *testing.T, s store.Store) {
	a := store.Invite{ID: id(2), Circle: id(1), Account: id(3), ExpiresAt: 100}
	b := store.Invite{ID: id(1), Circle: id(1), Account: id(3), ExpiresAt: 200, Requests: [][]byte{[]byte("r1"), []byte("r2")},
		Askers: [][]byte{id(4)}, Used: true, Result: []byte("result"), ResultAt: 150, Ended: true}
	update(t, s, func(tx store.Tx) error {
		must(t, tx.PutInvite(a))
		must(t, tx.PutInvite(b))
		return tx.PutInvite(store.Invite{ID: id(3), Circle: id(9), Account: id(3), ExpiresAt: 100})
	})
	view(t, s, func(tx store.Tx) error {
		if got, err := tx.Invite(id(1)); err != nil || !reflect.DeepEqual(got, b) {
			t.Errorf("invite: %+v %v", got, err)
		}
		got, _ := tx.Invite(id(2))
		if len(got.Requests) != 0 || len(got.Askers) != 0 || got.Result != nil || got.Used || got.Ended {
			t.Errorf("an empty invite: %+v", got)
		}
		if _, err := tx.Invite(id(4)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("a missing invite: %v", err)
		}
		of, _ := tx.InvitesOf(id(1))
		if len(of) != 2 || !bytes.Equal(of[0].ID, id(1)) || !bytes.Equal(of[1].ID, id(2)) {
			t.Errorf("InvitesOf, by ID: %d", len(of))
		}
		return nil
	})
	// Writing an invite again replaces it.
	b.Requests, b.Result = nil, nil
	update(t, s, func(tx store.Tx) error { return tx.PutInvite(b) })
	view(t, s, func(tx store.Tx) error {
		if got, _ := tx.Invite(id(1)); len(got.Requests) != 0 || got.Result != nil {
			t.Errorf("a replaced invite: %+v", got)
		}
		return nil
	})
}

// A transaction that fails leaves nothing behind, whatever it wrote.
func failedUpdate(t *testing.T, s store.Store) {
	raws := entries(t, "")
	sts := states(t, raws[:2])
	cid := sts[0].CircleID
	update(t, s, func(tx store.Tx) error {
		must(t, tx.PutToken(store.Token{Hash: id(1), ExpiresAt: 10}))
		must(t, tx.PutAccount(store.Account{ID: id(1), IK: id(1)}))
		return tx.CreateCircle(store.Circle{ID: cid, State: sts[0]}, raws[0])
	})
	boom := errors.New("boom")
	err := s.Update(func(tx store.Tx) error {
		tok, _ := tx.Token(id(1))
		tok.Spent = true
		must(t, tx.PutToken(tok))
		must(t, tx.DeleteAccount(id(1)))
		must(t, tx.PutAccount(store.Account{ID: id(2), IK: id(2)}))
		must(t, tx.PutSettings(store.Settings{MemberTokens: true}))
		must(t, tx.AppendEntry(cid, raws[1], sts[1], 5))
		if _, err := tx.PutEnvelope(store.Envelope{Circle: cid, Sender: id(4), Recipients: [][]byte{id(4)}, ExpiresAt: 100, Raw: []byte{1}}); err != nil {
			t.Fatal(err)
		}
		must(t, tx.PutSeen(cid, id(4), 1, store.SeenRecord{}))
		must(t, tx.PutInvite(store.Invite{ID: id(5), Circle: cid, Account: id(1)}))
		if _, err := tx.TakeChallenge(id(6)); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("a missing challenge")
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Update returned %v", err)
	}
	unchanged(t, s, cid, raws[0])

	// The next envelope still gets a number above any it has given out.
	var seq uint64
	update(t, s, func(tx store.Tx) (err error) {
		seq, err = tx.PutEnvelope(store.Envelope{Circle: cid, Sender: id(4), Recipients: [][]byte{id(4)}, ExpiresAt: 100, Raw: []byte{1}})
		return err
	})
	if seq == 0 {
		t.Error("envelope seq 0")
	}
}

func unchanged(t *testing.T, s store.Store, cid, genesis []byte) {
	t.Helper()
	view(t, s, func(tx store.Tx) error {
		if tok, _ := tx.Token(id(1)); tok.Spent {
			t.Error("the token stayed spent")
		}
		if _, err := tx.Account(id(1)); err != nil {
			t.Error("the deleted account stayed deleted")
		}
		if _, err := tx.Account(id(2)); err == nil {
			t.Error("the new account stayed")
		}
		if st, _ := tx.Settings(); st.MemberTokens {
			t.Error("the settings stayed")
		}
		c, err := tx.Circle(cid)
		must(t, err)
		es, _ := tx.Entries(cid, -1, 10, 1<<20)
		if c.State.Seq != 0 || len(es) != 1 || !bytes.Equal(es[0], genesis) {
			t.Error("the appended entry stayed")
		}
		if cs, _ := tx.CirclesOf([]byte(firstMember(c.State))); len(cs) != 1 || cs[0].State.Seq != 0 {
			t.Error("CirclesOf shows the appended entry")
		}
		if envs, _, _ := tx.Inbox(id(4), [][]byte{cid}, 0, 10, 1<<20, 0); len(envs) != 0 {
			t.Error("the envelope stayed")
		}
		if _, ok, _ := tx.Seen(cid, id(4), 1); ok {
			t.Error("the replay record stayed")
		}
		if _, err := tx.Invite(id(5)); err == nil {
			t.Error("the invite stayed")
		}
		return nil
	})
}

func firstMember(s *memberlog.State) string {
	for acc := range s.Members {
		return acc
	}
	return ""
}

// A transaction that panics leaves nothing behind either, and the store keeps working.
func panicking(t *testing.T, s store.Store) {
	raws := entries(t, "")
	sts := states(t, raws[:2])
	cid := sts[0].CircleID
	update(t, s, func(tx store.Tx) error {
		must(t, tx.PutToken(store.Token{Hash: id(1), ExpiresAt: 10}))
		must(t, tx.PutAccount(store.Account{ID: id(1), IK: id(1)}))
		return tx.CreateCircle(store.Circle{ID: cid, State: sts[0]}, raws[0])
	})
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("no panic")
			}
		}()
		s.Update(func(tx store.Tx) error {
			must(t, tx.DeleteAccount(id(1)))
			must(t, tx.PutAccount(store.Account{ID: id(2), IK: id(2)}))
			must(t, tx.AppendEntry(cid, raws[1], sts[1], 5))
			panic("boom")
		})
	}()
	unchanged(t, s, cid, raws[0])
	update(t, s, func(tx store.Tx) error { return tx.AppendEntry(cid, raws[1], sts[1], 5) })
}

func sweeping(t *testing.T, s store.Store) {
	const now = 1_000_000
	r := store.Retention{Removals: 1000, Results: 100, ClosedCircles: 5000}
	raws := entries(t, "accepted_last_member_leaves")
	closed := load(t, s, raws, now-6000)
	closedAt := uint64(now-6000) + uint64(len(raws)-1) // when the last entry was appended
	open := load(t, s, entries(t, "accepted_genesis_bad_details"), now-9000)
	cid, oid := closed.CircleID, open.CircleID
	if bytes.Equal(cid, oid) {
		t.Fatal("one circle")
	}
	update(t, s, func(tx store.Tx) error {
		for i, exp := range []uint64{now, now + 1} { // the first runs out now, the second not yet
			n := byte(10 * (i + 1))
			must(t, tx.PutChallenge(store.Challenge{Challenge: id(n), Device: id(1), ExpiresAt: exp}))
			must(t, tx.PutSession(store.Session{Hash: id(n), Device: id(1), ExpiresAt: exp}))
			must(t, tx.PutToken(store.Token{Hash: id(n), ExpiresAt: exp}))
			if _, err := tx.PutEnvelope(store.Envelope{Circle: oid, Sender: id(2), Recipients: [][]byte{id(1)}, ExpiresAt: exp, Raw: []byte{n}}); err != nil {
				return err
			}
			must(t, tx.PutSeen(oid, id(1), uint64(n), store.SeenRecord{KeepUntil: exp}))
			must(t, tx.PutRemoval(store.Removal{Circle: oid, Device: id(n), At: exp - r.Removals}))
			// Invites: expired, with and without a result kept long enough or not.
			must(t, tx.PutInvite(store.Invite{ID: id(n), Circle: oid, Account: id(3), ExpiresAt: exp}))
			must(t, tx.PutInvite(store.Invite{ID: id(n + 1), Circle: oid, Account: id(3), ExpiresAt: now - 1, Result: []byte{1}, ResultAt: exp - r.Results}))
		}
		// Everything that names the closed circle goes with it, however fresh.
		if _, err := tx.PutEnvelope(store.Envelope{Circle: cid, Sender: id(2), Recipients: [][]byte{id(1)}, ExpiresAt: now + 9, Raw: []byte{1}}); err != nil {
			return err
		}
		must(t, tx.PutSeen(cid, id(1), 1, store.SeenRecord{KeepUntil: now + 9}))
		must(t, tx.PutRemoval(store.Removal{Circle: cid, Device: id(1), At: now}))
		return tx.PutInvite(store.Invite{ID: id(99), Circle: cid, Account: id(3), ExpiresAt: now + 9})
	})
	// Before the closed circle's time is up, nothing has run out.
	var n store.Swept
	update(t, s, func(tx store.Tx) (err error) { n, err = tx.Sweep(closedAt+r.ClosedCircles-1, r); return })
	if n != (store.Swept{}) {
		t.Errorf("swept %+v before anything ran out", n)
	}
	update(t, s, func(tx store.Tx) (err error) { n, err = tx.Sweep(now, r); return })
	want := store.Swept{Challenges: 1, Sessions: 1, Tokens: 1, Envelopes: 2, Seen: 2, Removals: 2, Invites: 3, Circles: 1}
	if n != want {
		t.Errorf("swept %+v, want %+v", n, want)
	}
	update(t, s, func(tx store.Tx) error {
		if _, err := tx.TakeChallenge(id(10)); !errors.Is(err, store.ErrNotFound) {
			t.Error("a challenge that ran out")
		}
		if _, err := tx.TakeChallenge(id(20)); err != nil {
			t.Error("a challenge that hasn't run out")
		}
		for _, k := range []byte{10, 20} {
			_, errS := tx.Session(id(k))
			_, errT := tx.Token(id(k))
			_, okSeen, _ := tx.Seen(oid, id(1), uint64(k))
			_, errR := tx.Removal(oid, id(k))
			_, errI := tx.Invite(id(k))
			_, errI2 := tx.Invite(id(k + 1))
			if alive := k == 20; (errS == nil) != alive || (errT == nil) != alive || okSeen != alive || (errR == nil) != alive ||
				(errI == nil) != alive || (errI2 == nil) != alive {
				t.Errorf("records %d: %v %v %v %v %v %v", k, errS, errT, okSeen, errR, errI, errI2)
			}
		}
		if envs, _, _ := tx.Inbox(id(1), [][]byte{oid, cid}, 0, 10, 1<<20, 0); len(envs) != 1 || envs[0].Raw[0] != 20 {
			t.Errorf("%d envelopes left", len(envs))
		}
		if _, err := tx.Circle(cid); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the closed circle: %v", err)
		}
		if _, err := tx.Entries(cid, -1, 10, 1<<20); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("the closed circle's entries: %v", err)
		}
		if _, err := tx.Circle(oid); err != nil {
			t.Errorf("the open circle: %v", err)
		}
		return nil
	})
	// A circle with members is never swept.
	update(t, s, func(tx store.Tx) (err error) { n, err = tx.Sweep(now+1_000_000_000, r); return })
	if n.Circles != 0 {
		t.Error("swept a circle with members")
	}
}
