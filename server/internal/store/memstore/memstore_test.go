// SPDX-License-Identifier: AGPL-3.0-or-later

package memstore_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/gureetk/kinfold/server/internal/memberlog"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/store/memstore"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
)

// A transaction that fails leaves nothing behind, whatever it wrote.
func TestFailedUpdateLeavesNothing(t *testing.T) {
	entries := tv.Arr(tv.Obj(tv.Load(t)["log"])["entries"])
	g, e1 := tv.Hex(tv.Obj(entries[0])["raw"]), tv.Hex(tv.Obj(entries[1])["raw"])
	s0, _, _ := memberlog.Apply(memberlog.New(), g)
	s1, _, _ := memberlog.Apply(s0, e1)
	cid := s0.CircleID

	st := memstore.New()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.Update(func(tx store.Tx) error {
		must(tx.PutToken(store.Token{Hash: []byte("t1"), ExpiresAt: 10}))
		must(tx.PutAccount(store.Account{ID: []byte("a1")}))
		return tx.CreateCircle(store.Circle{ID: cid, State: s0}, g)
	}))

	boom := errors.New("boom")
	err := st.Update(func(tx store.Tx) error {
		tok, _ := tx.Token([]byte("t1"))
		tok.Spent = true
		must(tx.PutToken(tok))
		must(tx.DeleteAccount([]byte("a1")))
		must(tx.PutAccount(store.Account{ID: []byte("a2")}))
		must(tx.PutSettings(store.Settings{MemberTokens: true}))
		must(tx.AppendEntry(cid, e1, s1))
		if _, err := tx.PutEnvelope(store.Envelope{Circle: cid, Recipients: [][]byte{[]byte("d")}, ExpiresAt: 100}); err != nil {
			t.Fatal(err)
		}
		must(tx.PutSeen(cid, []byte("d"), 1, store.SeenRecord{}))
		_, err := tx.TakeChallenge([]byte("none"))
		if !errors.Is(err, store.ErrNotFound) {
			t.Fatal("a missing challenge")
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Update returned %v", err)
	}
	st.View(func(tx store.Tx) error {
		if tok, _ := tx.Token([]byte("t1")); tok.Spent {
			t.Error("the token stayed spent")
		}
		if _, err := tx.Account([]byte("a1")); err != nil {
			t.Error("the deleted account stayed deleted")
		}
		if _, err := tx.Account([]byte("a2")); err == nil {
			t.Error("the new account stayed")
		}
		if s, _ := tx.Settings(); s.MemberTokens {
			t.Error("the settings stayed")
		}
		c, _ := tx.Circle(cid)
		es, _ := tx.Entries(cid, -1, 10, 1<<20)
		if c.State.Seq != 0 || len(es) != 1 || !bytes.Equal(es[0], g) {
			t.Error("the appended entry stayed")
		}
		if _, ok, _ := tx.SeqOf(cid, memberlog.Hash(e1)); ok {
			t.Error("the appended entry's hash stayed")
		}
		if envs, _, _ := tx.Inbox([]byte("d"), [][]byte{cid}, 0, 10, 1<<20, 0); len(envs) != 0 {
			t.Error("the envelope stayed")
		}
		if _, ok, _ := tx.Seen(cid, []byte("d"), 1); ok {
			t.Error("the replay record stayed")
		}
		return nil
	})

	// The next envelope gets the next number: none was used up by the failed transaction.
	var seq uint64
	must(st.Update(func(tx store.Tx) (err error) {
		seq, err = tx.PutEnvelope(store.Envelope{Circle: cid, Recipients: [][]byte{[]byte("d")}, ExpiresAt: 100})
		return err
	}))
	if seq != 1 {
		t.Errorf("envelope seq %d after a rollback", seq)
	}
}

func TestInboxPages(t *testing.T) {
	st := memstore.New()
	cid, other := []byte("circle"), []byte("other")
	st.Update(func(tx store.Tx) error {
		for i := 0; i < 5; i++ {
			tx.PutEnvelope(store.Envelope{Circle: cid, Recipients: [][]byte{[]byte("me")}, ExpiresAt: 1000, Raw: make([]byte, 100)})
			tx.PutEnvelope(store.Envelope{Circle: other, Recipients: [][]byte{[]byte("me")}, ExpiresAt: 1000, Raw: make([]byte, 100)})
			tx.PutEnvelope(store.Envelope{Circle: cid, Recipients: [][]byte{[]byte("you")}, ExpiresAt: 1000})
		}
		tx.PutEnvelope(store.Envelope{Circle: cid, Recipients: [][]byte{[]byte("me")}, ExpiresAt: 10})
		return nil
	})
	st.View(func(tx store.Tx) error {
		page, more, _ := tx.Inbox([]byte("me"), [][]byte{cid}, 0, 2, 1<<20, 50)
		if len(page) != 2 || !more {
			t.Fatalf("first page: %d, more %v", len(page), more)
		}
		rest, more, _ := tx.Inbox([]byte("me"), [][]byte{cid}, page[1].Seq, 10, 1<<20, 50)
		if len(rest) != 3 || more {
			t.Fatalf("rest: %d, more %v (the expired one left out)", len(rest), more)
		}
		small, more, _ := tx.Inbox([]byte("me"), [][]byte{cid}, 0, 10, 150, 50)
		if len(small) != 1 || !more {
			t.Fatalf("a byte limit: %d, more %v", len(small), more)
		}
		return nil
	})
}
