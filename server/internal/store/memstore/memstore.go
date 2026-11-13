// SPDX-License-Identifier: AGPL-3.0-or-later

// Package memstore keeps everything in memory. It is for tests and for trying the server
// out: nothing survives a restart.
package memstore

import (
	"bytes"
	"slices"
	"sort"
	"sync"

	"github.com/gureetk/kinfold/server/internal/memberlog"
	"github.com/gureetk/kinfold/server/internal/store"
)

type circleLog struct {
	c        store.Circle
	entries  [][]byte
	index    map[string]int64 // entry hash -> seq
	closedAt uint64           // when its last member left; 0 while it has members
}

// Store is an in-memory store.Store.
type Store struct {
	mu         sync.RWMutex
	settings   store.Settings
	tokens     map[string]store.Token
	accounts   map[string]store.Account
	devices    map[string]store.Device
	challenges map[string]store.Challenge
	sessions   map[string]store.Session
	circles    map[string]*circleLog
	removals   map[string]store.Removal // circle ‖ device
	envelopes  []store.Envelope         // in order of arrival
	nextSeq    uint64
	seen       map[string]seenRecord // circle ‖ sender ‖ seq
	invites    map[string]store.Invite
	watches    map[string]store.Watch // circle ‖ device ‖ watcher
	heard      map[string]heardAt     // circle ‖ device
}

type heardAt struct {
	circle string
	at     uint64
}

// New returns an empty store.
func New() *Store {
	return &Store{tokens: map[string]store.Token{}, accounts: map[string]store.Account{},
		devices: map[string]store.Device{}, challenges: map[string]store.Challenge{},
		sessions: map[string]store.Session{}, circles: map[string]*circleLog{},
		removals: map[string]store.Removal{}, seen: map[string]seenRecord{}, invites: map[string]store.Invite{},
		watches: map[string]store.Watch{}, heard: map[string]heardAt{}, nextSeq: 1}
}

// tx records how to undo each write, so that a failed Update leaves nothing behind.
type tx struct {
	s        *Store
	readOnly bool
	undo     []func()
}

func (s *Store) Update(fn func(store.Tx) error) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &tx{s: s}
	done := false
	defer func() { // also when fn panics
		if !done {
			for i := len(t.undo) - 1; i >= 0; i-- {
				t.undo[i]()
			}
		}
	}()
	err = fn(t)
	done = err == nil
	return err
}

func (s *Store) View(fn func(store.Tx) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fn(&tx{s: s, readOnly: true})
}

func (t *tx) writing() {
	if t.readOnly {
		panic("memstore: write in a read-only transaction")
	}
}

// set and del write a map entry and record how to undo it.
func set[V any](t *tx, m map[string]V, k string, v V) {
	t.writing()
	old, had := m[k]
	t.undo = append(t.undo, func() {
		if had {
			m[k] = old
		} else {
			delete(m, k)
		}
	})
	m[k] = v
}

func del[V any](t *tx, m map[string]V, k string) {
	t.writing()
	old, had := m[k]
	if !had {
		return
	}
	t.undo = append(t.undo, func() { m[k] = old })
	delete(m, k)
}

func get[V any](m map[string]V, k []byte) (V, error) {
	v, ok := m[string(k)]
	if !ok {
		return v, store.ErrNotFound
	}
	return v, nil
}

func cat(parts ...[]byte) string { return string(bytes.Join(parts, nil)) }

// ---- settings and tokens ----

func (t *tx) Settings() (store.Settings, error) { return t.s.settings, nil }

func (t *tx) PutSettings(v store.Settings) error {
	t.writing()
	old := t.s.settings
	t.undo = append(t.undo, func() { t.s.settings = old })
	t.s.settings = v
	return nil
}

func (t *tx) PutToken(v store.Token) error        { set(t, t.s.tokens, string(v.Hash), v); return nil }
func (t *tx) Token(h []byte) (store.Token, error) { return get(t.s.tokens, h) }
func (t *tx) DeleteToken(h []byte) error {
	if _, ok := t.s.tokens[string(h)]; !ok {
		return store.ErrNotFound
	}
	del(t, t.s.tokens, string(h))
	return nil
}

func (t *tx) Tokens() ([]store.Token, error) {
	var out []store.Token
	for _, v := range t.s.tokens {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out, nil
}

// ---- accounts, devices, challenges, sessions ----

func (t *tx) PutAccount(v store.Account) error         { set(t, t.s.accounts, string(v.ID), v); return nil }
func (t *tx) Account(id []byte) (store.Account, error) { return get(t.s.accounts, id) }
func (t *tx) DeleteAccount(id []byte) error            { del(t, t.s.accounts, string(id)); return nil }

func (t *tx) PutDevice(v store.Device) error         { set(t, t.s.devices, string(v.ID), v); return nil }
func (t *tx) Device(id []byte) (store.Device, error) { return get(t.s.devices, id) }
func (t *tx) DeleteDevice(id []byte) error           { del(t, t.s.devices, string(id)); return nil }

func (t *tx) DevicesOf(account []byte) ([]store.Device, error) {
	var out []store.Device
	for _, d := range t.s.devices {
		if bytes.Equal(d.Account, account) {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].ID, out[j].ID) < 0 })
	return out, nil
}

func (t *tx) PutChallenge(v store.Challenge) error {
	set(t, t.s.challenges, string(v.Challenge), v)
	return nil
}

func (t *tx) TakeChallenge(c []byte) (store.Challenge, error) {
	v, err := get(t.s.challenges, c)
	if err == nil {
		del(t, t.s.challenges, string(c))
	}
	return v, err
}

func (t *tx) PutSession(v store.Session) error        { set(t, t.s.sessions, string(v.Hash), v); return nil }
func (t *tx) Session(h []byte) (store.Session, error) { return get(t.s.sessions, h) }
func (t *tx) DeleteSession(h []byte) error            { del(t, t.s.sessions, string(h)); return nil }

func (t *tx) DeleteSessionsOf(device []byte) error {
	for k, v := range t.s.sessions {
		if bytes.Equal(v.Device, device) {
			del(t, t.s.sessions, k)
		}
	}
	return nil
}

// ---- circles ----

func (t *tx) CreateCircle(c store.Circle, genesis []byte) error {
	set(t, t.s.circles, string(c.ID), &circleLog{c: c, entries: [][]byte{genesis},
		index: map[string]int64{string(memberlog.Hash(genesis)): 0}})
	return nil
}

func (t *tx) Circle(id []byte) (store.Circle, error) {
	l, err := get(t.s.circles, id)
	if err != nil {
		return store.Circle{}, err
	}
	return l.c, nil
}

func (t *tx) AppendEntry(circle, raw []byte, s *memberlog.State, at uint64) error {
	t.writing()
	l, err := get(t.s.circles, circle)
	if err != nil {
		return err
	}
	if s.Seq != int64(len(l.entries)) {
		panic("memstore: entries appended out of order")
	}
	oldState, oldClosed, h := l.c.State, l.closedAt, string(memberlog.Hash(raw))
	t.undo = append(t.undo, func() {
		l.c.State, l.closedAt = oldState, oldClosed
		l.entries = l.entries[:len(l.entries)-1]
		delete(l.index, h)
	})
	l.entries = append(l.entries, raw)
	l.index[h] = s.Seq
	l.c.State = s
	if len(s.Members) == 0 && l.closedAt == 0 {
		l.closedAt = at
	}
	return nil
}

func (t *tx) Entries(circle []byte, after int64, limit, maxBytes int) ([][]byte, error) {
	l, err := get(t.s.circles, circle)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	size := 0
	for seq := after + 1; seq < int64(len(l.entries)) && len(out) < limit; seq++ {
		e := l.entries[seq]
		if len(out) > 0 && size+len(e) > maxBytes {
			break
		}
		out = append(out, e)
		size += len(e)
	}
	return out, nil
}

func (t *tx) SeqOf(circle, hash []byte) (int64, bool, error) {
	l, err := get(t.s.circles, circle)
	if err != nil {
		return 0, false, err
	}
	s, ok := l.index[string(hash)]
	return s, ok, nil
}

func (t *tx) CirclesOf(account []byte) ([]store.Circle, error) {
	var out []store.Circle
	for _, l := range t.s.circles {
		if l.c.State.Member(account) != nil {
			out = append(out, l.c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].ID, out[j].ID) < 0 })
	return out, nil
}

func (t *tx) PutRemoval(v store.Removal) error {
	set(t, t.s.removals, cat(v.Circle, v.Device), v)
	return nil
}

func (t *tx) Removal(circle, device []byte) (store.Removal, error) {
	return get(t.s.removals, []byte(cat(circle, device)))
}

// ---- envelopes ----

func (t *tx) PutEnvelope(v store.Envelope) (uint64, error) {
	t.writing()
	v.Seq = t.s.nextSeq
	t.s.nextSeq++
	t.s.envelopes = append(t.s.envelopes, v)
	t.undo = append(t.undo, func() {
		t.s.envelopes = t.s.envelopes[:len(t.s.envelopes)-1]
		t.s.nextSeq--
	})
	return v.Seq, nil
}

func (t *tx) Inbox(device []byte, circles [][]byte, after uint64, limit, maxBytes int, now uint64) ([]store.Envelope, bool, error) {
	var out []store.Envelope
	size := 0
	i := sort.Search(len(t.s.envelopes), func(i int) bool { return t.s.envelopes[i].Seq > after })
	for ; i < len(t.s.envelopes); i++ {
		e := t.s.envelopes[i]
		if now >= e.ExpiresAt || !slices.ContainsFunc(circles, func(c []byte) bool { return bytes.Equal(c, e.Circle) }) ||
			!slices.ContainsFunc(e.Recipients, func(r []byte) bool { return bytes.Equal(r, device) }) {
			continue
		}
		if len(out) == limit || (len(out) > 0 && size+8+len(e.Raw) > maxBytes) {
			return out, true, nil
		}
		out = append(out, e)
		size += 8 + len(e.Raw)
	}
	return out, false, nil
}

func seenKey(circle, sender []byte, seq uint64) string {
	return cat(circle, sender, []byte{byte(seq >> 56), byte(seq >> 48), byte(seq >> 40), byte(seq >> 32),
		byte(seq >> 24), byte(seq >> 16), byte(seq >> 8), byte(seq)})
}

// seenRecord is a replay record with the circle it belongs to.
type seenRecord struct {
	circle string
	store.SeenRecord
}

func (t *tx) Seen(circle, sender []byte, seq uint64) (store.SeenRecord, bool, error) {
	r, ok := t.s.seen[seenKey(circle, sender, seq)]
	return r.SeenRecord, ok, nil
}

func (t *tx) PutSeen(circle, sender []byte, seq uint64, r store.SeenRecord) error {
	set(t, t.s.seen, seenKey(circle, sender, seq), seenRecord{string(circle), r})
	return nil
}

// ---- invites ----

func (t *tx) PutInvite(v store.Invite) error         { set(t, t.s.invites, string(v.ID), v); return nil }
func (t *tx) Invite(id []byte) (store.Invite, error) { return get(t.s.invites, id) }

func (t *tx) InvitesOf(circle []byte) ([]store.Invite, error) {
	var out []store.Invite
	for _, v := range t.s.invites {
		if bytes.Equal(v.Circle, circle) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].ID, out[j].ID) < 0 })
	return out, nil
}

// ---- watches ----

func (t *tx) PutWatch(v store.Watch) error {
	set(t, t.s.watches, cat(v.Circle, v.Device, v.Watcher), v)
	return nil
}

func (t *tx) Watch(circle, device, watcher []byte) (store.Watch, error) {
	return get(t.s.watches, []byte(cat(circle, device, watcher)))
}

func (t *tx) DeleteWatch(circle, device, watcher []byte) error {
	del(t, t.s.watches, cat(circle, device, watcher))
	return nil
}

func (t *tx) watches(keep func(store.Watch) bool) []store.Watch {
	var out []store.Watch
	for _, v := range t.s.watches {
		if keep(v) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return cat(a.Circle, a.Device, a.Watcher) < cat(b.Circle, b.Device, b.Watcher)
	})
	return out
}

func (t *tx) WatchesIn(circle []byte) ([]store.Watch, error) {
	return t.watches(func(v store.Watch) bool { return bytes.Equal(v.Circle, circle) }), nil
}

func (t *tx) Watches() ([]store.Watch, error) {
	return t.watches(func(store.Watch) bool { return true }), nil
}

func (t *tx) Heard(circle, device []byte, at uint64) error {
	set(t, t.s.heard, cat(circle, device), heardAt{string(circle), at})
	for k, v := range t.s.watches {
		if bytes.Equal(v.Circle, circle) && bytes.Equal(v.Device, device) {
			v.Since, v.WokeAt, v.Alerted = at, 0, false
			set(t, t.s.watches, k, v)
		}
	}
	return nil
}

func (t *tx) LastHeard(circle, device []byte) (uint64, bool, error) {
	h, ok := t.s.heard[cat(circle, device)]
	return h.at, ok, nil
}

// ---- sweeping ----

// sweep deletes the entries of m for which gone is true, and counts them.
func sweep[V any](t *tx, m map[string]V, gone func(V) bool) int {
	n := 0
	for k, v := range m {
		if gone(v) {
			del(t, m, k)
			n++
		}
	}
	return n
}

func (t *tx) Sweep(now uint64, r store.Retention) (store.Swept, error) {
	t.writing()
	var n store.Swept
	n.Challenges = sweep(t, t.s.challenges, func(v store.Challenge) bool { return now >= v.ExpiresAt })
	n.Sessions = sweep(t, t.s.sessions, func(v store.Session) bool { return now >= v.ExpiresAt })
	n.Tokens = sweep(t, t.s.tokens, func(v store.Token) bool { return now >= v.ExpiresAt })
	n.Seen = sweep(t, t.s.seen, func(v seenRecord) bool { return now >= v.KeepUntil })
	n.Removals = sweep(t, t.s.removals, func(v store.Removal) bool { return now >= v.At+r.Removals })
	n.Invites = sweep(t, t.s.invites, func(v store.Invite) bool {
		return now >= v.ExpiresAt && (v.Result == nil || now >= v.ResultAt+r.Results)
	})
	n.Watches = sweep(t, t.s.watches, func(v store.Watch) bool { return v.Revoked && now >= v.NotAfter })
	// A closed circle goes with everything that names it.
	gone := map[string]bool{}
	n.Circles = sweep(t, t.s.circles, func(l *circleLog) bool {
		if l.closedAt != 0 && now >= l.closedAt+r.ClosedCircles {
			gone[string(l.c.ID)] = true
			return true
		}
		return false
	})
	if len(gone) > 0 {
		n.Removals += sweep(t, t.s.removals, func(v store.Removal) bool { return gone[string(v.Circle)] })
		n.Invites += sweep(t, t.s.invites, func(v store.Invite) bool { return gone[string(v.Circle)] })
		n.Seen += sweep(t, t.s.seen, func(v seenRecord) bool { return gone[v.circle] })
		n.Watches += sweep(t, t.s.watches, func(v store.Watch) bool { return gone[string(v.Circle)] })
		sweep(t, t.s.heard, func(v heardAt) bool { return gone[v.circle] })
	}
	// Envelopes are a slice in order of arrival.
	old := t.s.envelopes
	var kept []store.Envelope
	for _, e := range old {
		if now >= e.ExpiresAt || gone[string(e.Circle)] {
			n.Envelopes++
		} else {
			kept = append(kept, e)
		}
	}
	if n.Envelopes > 0 {
		t.undo = append(t.undo, func() { t.s.envelopes = old })
		t.s.envelopes = kept
	}
	return n, nil
}
