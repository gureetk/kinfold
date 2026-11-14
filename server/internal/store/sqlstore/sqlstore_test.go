// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlstore_test

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gureetk/kinfold/server/internal/memberlog"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/store/sqlstore"
	"github.com/gureetk/kinfold/server/internal/store/storetest"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
)

func open(t *testing.T, path string) *sqlstore.Store {
	t.Helper()
	s, err := sqlstore.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStore(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return open(t, filepath.Join(t.TempDir(), "kinfold.db")) })
}

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// mainLog returns the vectors' main log and the public state after each entry.
func mainLog(t *testing.T) ([][]byte, []*memberlog.State) {
	var raws [][]byte
	for _, e := range tv.Arr(tv.Obj(tv.Load(t)["log"])["entries"]) {
		raws = append(raws, tv.Hex(tv.Obj(e)["raw"]))
	}
	return raws, tv.MainLog(t).States
}

func put(t *testing.T, s store.Store, raws [][]byte, sts []*memberlog.State, from, to int) {
	mustDo(t, s.Update(func(tx store.Tx) error {
		for i := from; i < to; i++ {
			if i == 0 {
				mustDo(t, tx.CreateCircle(store.Circle{ID: sts[0].CircleID, State: sts[0], CreatedAt: 1}, raws[0]))
			} else {
				mustDo(t, tx.AppendEntry(sts[0].CircleID, raws[i], sts[i], uint64(i)))
			}
		}
		return nil
	}))
}

func stateAt(t *testing.T, tx store.Tx, cid []byte) *memberlog.State {
	t.Helper()
	c, err := tx.Circle(cid)
	mustDo(t, err)
	return c.State
}

// What is written survives closing the file, and a circle's state comes back by replaying
// its log.
func TestReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kinfold.db")
	raws, sts := mainLog(t)
	cid := sts[0].CircleID
	s := open(t, path)
	put(t, s, raws, sts, 0, len(raws))
	mustDo(t, s.Update(func(tx store.Tx) error {
		mustDo(t, tx.PutSettings(store.Settings{WebDevices: true}))
		return tx.PutToken(store.Token{Hash: []byte("token"), ExpiresAt: 9})
	}))
	mustDo(t, s.Close())

	s = open(t, path)
	mustDo(t, s.View(func(tx store.Tx) error {
		got := stateAt(t, tx, cid)
		if !reflect.DeepEqual(got.PublicJSON(), sts[len(sts)-1].PublicJSON()) || got.RecvChanged != sts[len(sts)-1].RecvChanged {
			t.Error("the replayed state differs")
		}
		if st, _ := tx.Settings(); !st.WebDevices {
			t.Error("settings")
		}
		if _, err := tx.Token([]byte("token")); err != nil {
			t.Error("token")
		}
		return nil
	}))
}

// A read sees one snapshot from start to end, and a write doesn't wait for it: WAL mode.
// The state of a circle follows the snapshot too, even when memory holds a newer one.
func TestSnapshots(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "kinfold.db"))
	raws, sts := mainLog(t)
	cid := sts[0].CircleID
	put(t, s, raws, sts, 0, 10)
	mustDo(t, s.View(func(tx store.Tx) error {
		if stateAt(t, tx, cid).Seq != 9 {
			t.Fatal("seq")
		}
		done := make(chan error)
		go func() {
			done <- s.Update(func(tx store.Tx) error {
				mustDo(t, tx.PutSettings(store.Settings{MemberTokens: true}))
				return tx.AppendEntry(cid, raws[10], sts[10], 10)
			})
		}()
		select {
		case err := <-done:
			mustDo(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("the write waited for the read")
		}
		if st, _ := tx.Settings(); st.MemberTokens {
			t.Error("the read saw a later write")
		}
		if got := stateAt(t, tx, cid); got.Seq != 9 || !reflect.DeepEqual(got.PublicJSON(), sts[9].PublicJSON()) {
			t.Errorf("the read's circle is at seq %d", got.Seq)
		}
		return nil
	}))
	mustDo(t, s.View(func(tx store.Tx) error {
		if stateAt(t, tx, cid).Seq != 10 {
			t.Error("a new read doesn't see the write")
		}
		return nil
	}))
}

// Writers and readers at once: no "database is locked", and every write lands.
func TestConcurrency(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "kinfold.db"))
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := range 25 {
				errs <- s.Update(func(tx store.Tx) error {
					return tx.PutToken(store.Token{Hash: []byte(fmt.Sprintf("%d/%d", g, i)), ExpiresAt: 1})
				})
			}
		}()
		go func() {
			defer wg.Done()
			for range 25 {
				errs <- s.View(func(tx store.Tx) error { _, err := tx.Tokens(); return err })
			}
		}()
	}
	go func() { wg.Wait(); close(errs) }()
	for err := range errs {
		mustDo(t, err)
	}
	mustDo(t, s.View(func(tx store.Tx) error {
		if toks, _ := tx.Tokens(); len(toks) != 200 {
			t.Errorf("%d tokens", len(toks))
		}
		return nil
	}))
}

// A log that no longer verifies, changed on disk behind the server's back, is an error,
// never a state.
func TestTamperedLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kinfold.db")
	raws, sts := mainLog(t)
	cid := sts[0].CircleID
	s := open(t, path)
	put(t, s, raws, sts, 0, 5)
	mustDo(t, s.Close())

	db, err := sql.Open("sqlite3", "file:"+path)
	mustDo(t, err)
	bad := append([]byte(nil), raws[3]...)
	bad[len(bad)-1] ^= 1 // the signature
	_, err = db.Exec(`UPDATE entries SET raw = ? WHERE circle = ? AND seq = 3`, bad, cid)
	mustDo(t, err)
	db.Close()

	s = open(t, path)
	err = s.View(func(tx store.Tx) error { _, err := tx.Circle(cid); return err })
	if err == nil || !strings.Contains(err.Error(), "entry 3") {
		t.Fatalf("a tampered log: %v", err)
	}
}

// The database file is the server's user's alone. (The server's umask covers the files
// SQLite adds next to it.)
func TestFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kinfold.db")
	s := open(t, path)
	mustDo(t, s.Update(func(tx store.Tx) error { return tx.PutSettings(store.Settings{WebDevices: true}) }))
	fi, err := os.Stat(path)
	mustDo(t, err)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the database has mode %v", fi.Mode().Perm())
	}
}

// A database from a newer server is refused, not changed.
func TestNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kinfold.db")
	mustDo(t, open(t, path).Close())
	db, err := sql.Open("sqlite3", "file:"+path)
	mustDo(t, err)
	_, err = db.Exec(`PRAGMA user_version = 99`)
	mustDo(t, err)
	db.Close()
	if s, err := sqlstore.Open(path); err == nil || !strings.Contains(err.Error(), "newer") {
		if s != nil {
			s.Close()
		}
		t.Fatalf("opened a newer database: %v", err)
	}
}
