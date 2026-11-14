// SPDX-License-Identifier: AGPL-3.0-or-later

// Package testvec loads spec/vectors/kinfold-v0.json for tests. Only test files import it.
package testvec

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gureetk/kinfold/server/internal/memberlog"
)

// V is a JSON object from the vectors.
type V = map[string]any

var (
	once   sync.Once
	loaded V
	err    error
)

// Path finds the vectors file: $KINFOLD_VECTORS, or spec/vectors/kinfold-v0.json in the
// nearest directory above the working directory that has one.
func Path() (string, error) {
	if p := os.Getenv("KINFOLD_VECTORS"); p != "" {
		return p, nil
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		p := filepath.Join(dir, "spec", "vectors", "kinfold-v0.json")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

// Load returns the parsed vectors, read once per test binary.
func Load(t testing.TB) V {
	t.Helper()
	once.Do(func() {
		var p string
		if p, err = Path(); err != nil {
			return
		}
		var b []byte
		if b, err = os.ReadFile(p); err != nil {
			return
		}
		err = json.Unmarshal(b, &loaded)
	})
	if err != nil {
		t.Fatalf("loading the test vectors: %v", err)
	}
	return loaded
}

func Obj(v any) V            { return v.(map[string]any) }
func Arr(v any) []any        { return v.([]any) }
func Str(v any) string       { return v.(string) }
func Num(v any) uint64       { return uint64(v.(float64)) }
func Int(v any) int64        { return int64(v.(float64)) }
func Bool(v any) bool        { return v.(bool) }
func Has(m V, k string) bool { _, ok := m[k]; return ok }

// Hex decodes a hex string field.
func Hex(v any) []byte {
	b, err := hex.DecodeString(v.(string))
	if err != nil {
		panic(err)
	}
	return b
}

// Normalize round-trips a value through encoding/json, so that values built in Go compare
// equal to values read from the vectors.
func Normalize(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

// PublicOnly drops the private fields from a vectors state, leaving what a server keeps.
func PublicOnly(state any) any {
	m := Normalize(state).(map[string]any)
	for _, k := range []string{"name", "flags", "private_unknown_from", "state_hash"} {
		delete(m, k)
	}
	for _, mem := range Arr(m["members"]) {
		for _, k := range []string{"role", "teen_until", "guardians", "rules", "pauses"} {
			delete(Obj(mem), k)
		}
	}
	return m
}

// Log is a circle log as a server holds it: the public state after each entry, and where
// each entry hash sits.
type Log struct {
	States []*memberlog.State // States[seq]
	Index  map[string]int64   // entry hash -> seq
}

// SeqOf implements envelope.Heads.
func (l *Log) SeqOf(hash []byte) (int64, bool) {
	s, ok := l.Index[string(hash)]
	return s, ok
}

// MainLog replays the main log of the vectors in public mode.
func MainLog(t testing.TB) *Log {
	t.Helper()
	l := &Log{Index: map[string]int64{}}
	s := memberlog.New()
	for _, e := range Arr(Obj(Load(t)["log"])["entries"]) {
		raw := Hex(Obj(e)["raw"])
		ns, _, err := memberlog.Apply(s, raw)
		if err != nil {
			t.Fatalf("main log entry %v: %v", Obj(e)["seq"], err)
		}
		s = ns
		l.States = append(l.States, s)
		l.Index[string(memberlog.Hash(raw))] = s.Seq
	}
	return l
}

// Upto returns the log as it stood after entry seq: a copy that the caller may extend.
func (l *Log) Upto(seq int64) *Log {
	out := &Log{States: append([]*memberlog.State(nil), l.States[:seq+1]...), Index: map[string]int64{}}
	for h, s := range l.Index {
		if s <= seq {
			out.Index[h] = s
		}
	}
	return out
}
