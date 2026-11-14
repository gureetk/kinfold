// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sqlstore keeps what the server holds (API.md §15) in an SQLite file in WAL mode,
// so that reads don't wait for writes. One connection writes and every write is synced to
// disk before it is acknowledged. The driver is pure Go: SQLite compiled to WebAssembly and
// translated to Go, which keeps all of SQLite's memory inside one bounds-checked slice.
//
// A circle's public state isn't stored. It is replayed from the circle's log, the signed
// record it comes from, and kept in memory once replayed.
package sqlstore

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	_ "github.com/ncruces/go-sqlite3/driver"

	"github.com/gureetk/kinfold/server/internal/memberlog"
	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/wire"
)

//go:embed schema.sql
var schema string

// schemaVersion is the user_version of a database with this schema.
const schemaVersion = 1

// readers is how many connections may read at once.
const readers = 4

// Store is a store.Store in an SQLite file.
type Store struct {
	w, r *sql.DB
	wmu  sync.Mutex // held through a write transaction and the update of states after it

	mu     sync.Mutex
	states map[string]*memberlog.State // the latest state known of each circle, by ID
}

// Open opens the database at path, creating it if need be.
func Open(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// Only the server's user may read the file.
	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	dsn := func(params url.Values) string {
		return (&url.URL{Scheme: "file", Path: abs, RawQuery: params.Encode()}).String()
	}
	w, err := sql.Open("sqlite3", dsn(url.Values{"_txlock": {"immediate"},
		"_pragma": {"busy_timeout(10000)", "foreign_keys(on)", "synchronous(full)"}}))
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	w.SetConnMaxLifetime(0)
	var mode string
	if err := w.QueryRow(`PRAGMA journal_mode = wal`).Scan(&mode); err != nil || mode != "wal" {
		w.Close()
		return nil, fmt.Errorf("sqlstore: %s: can't use WAL mode (%q, %v)", path, mode, err)
	}
	if err := migrate(w); err != nil {
		w.Close()
		return nil, fmt.Errorf("sqlstore: %s: %w", path, err)
	}
	r, err := sql.Open("sqlite3", dsn(url.Values{"_pragma": {"busy_timeout(10000)", "query_only(on)"}}))
	if err != nil {
		w.Close()
		return nil, err
	}
	r.SetMaxOpenConns(readers)
	r.SetMaxIdleConns(readers)
	return &Store{w: w, r: r, states: map[string]*memberlog.State{}}, nil
}

func migrate(w *sql.DB) error {
	var v int
	if err := w.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	switch {
	case v == schemaVersion:
		return nil
	case v > schemaVersion:
		return fmt.Errorf("the database has schema version %d, newer than this server's %d", v, schemaVersion)
	case v != 0:
		return fmt.Errorf("the database has schema version %d, which this server can't upgrade", v)
	}
	tx, err := w.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(schema); err != nil {
		return err
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion)); err != nil {
		return err
	}
	return tx.Commit()
}

// Close closes the database.
func (s *Store) Close() error {
	return errors.Join(s.r.Close(), s.w.Close())
}

// tx is a transaction. pending holds the states of circles this transaction changed.
type tx struct {
	s       *Store
	q       *sql.Tx
	pending map[string]*memberlog.State
	gone    [][]byte // circles this transaction deleted
}

func (s *Store) Update(fn func(store.Tx) error) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	q, err := s.w.Begin()
	if err != nil {
		return err
	}
	defer q.Rollback() // does nothing after a commit; also runs when fn panics
	t := &tx{s: s, q: q, pending: map[string]*memberlog.State{}}
	if err := fn(t); err != nil {
		return err
	}
	if err := q.Commit(); err != nil {
		return err
	}
	// Still holding wmu, so states are remembered in the order they were committed.
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, st := range t.pending {
		s.states[id] = st
	}
	for _, id := range t.gone {
		delete(s.states, string(id))
	}
	return nil
}

func (s *Store) View(fn func(store.Tx) error) error {
	q, err := s.r.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer q.Rollback()
	return fn(&tx{s: s, q: q})
}

// Integers are stored as SQLite's signed 64 bits; a u64 keeps its bits.
func i64(u uint64) int64 { return int64(u) }

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

// nilIfEmpty keeps "absent" as nil whatever the driver returns for an empty value.
func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// frames and unframes store a list of byte strings in one column.
func frames(list [][]byte) []byte {
	out := []byte{}
	for _, b := range list {
		out = wire.AppendFrame(out, b)
	}
	return out
}

func unframes(b []byte) ([][]byte, error) {
	if len(b) == 0 {
		return nil, nil
	}
	return wire.Frames(b, 1<<20, 1<<30)
}

// ---- settings and tokens ----

func (t *tx) Settings() (store.Settings, error) {
	var s store.Settings
	var until int64
	err := t.q.QueryRow(`SELECT member_tokens, web_devices, repair_until FROM settings WHERE id = 1`).
		Scan(&s.MemberTokens, &s.WebDevices, &until)
	s.RepairUntil = uint64(until)
	return s, err
}

func (t *tx) PutSettings(s store.Settings) error {
	_, err := t.q.Exec(`UPDATE settings SET member_tokens = ?, web_devices = ?, repair_until = ? WHERE id = 1`,
		s.MemberTokens, s.WebDevices, i64(s.RepairUntil))
	return err
}

const tokenCols = `hash, created_at, expires_at, spent, invite`

func scanToken(row interface{ Scan(...any) error }) (store.Token, error) {
	var v store.Token
	var created, expires int64
	err := row.Scan(&v.Hash, &created, &expires, &v.Spent, &v.Invite)
	v.CreatedAt, v.ExpiresAt, v.Invite = uint64(created), uint64(expires), nilIfEmpty(v.Invite)
	return v, notFound(err)
}

func (t *tx) PutToken(v store.Token) error {
	_, err := t.q.Exec(`INSERT OR REPLACE INTO tokens (`+tokenCols+`) VALUES (?, ?, ?, ?, ?)`,
		v.Hash, i64(v.CreatedAt), i64(v.ExpiresAt), v.Spent, nilIfEmpty(v.Invite))
	return err
}

func (t *tx) Token(hash []byte) (store.Token, error) {
	return scanToken(t.q.QueryRow(`SELECT `+tokenCols+` FROM tokens WHERE hash = ?`, hash))
}

func (t *tx) Tokens() ([]store.Token, error) {
	rows, err := t.q.Query(`SELECT ` + tokenCols + ` FROM tokens ORDER BY created_at, hash`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Token
	for rows.Next() {
		v, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (t *tx) DeleteToken(hash []byte) error {
	return deleteOne(t.q.Exec(`DELETE FROM tokens WHERE hash = ?`, hash))
}

// deleteOne turns a delete that found nothing into ErrNotFound.
func deleteOne(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return errors.Join(err, store.ErrNotFound)
	}
	return nil
}

// ---- accounts, devices, challenges, sessions ----

func (t *tx) PutAccount(v store.Account) error {
	_, err := t.q.Exec(`INSERT OR REPLACE INTO accounts (id, ik, chain, operator, created_at) VALUES (?, ?, ?, ?, ?)`,
		v.ID, v.IK, nilIfEmpty(v.Chain), v.Operator, i64(v.CreatedAt))
	return err
}

func (t *tx) Account(id []byte) (store.Account, error) {
	var v store.Account
	var created int64
	err := t.q.QueryRow(`SELECT id, ik, chain, operator, created_at FROM accounts WHERE id = ?`, id).
		Scan(&v.ID, &v.IK, &v.Chain, &v.Operator, &created)
	v.CreatedAt, v.Chain = uint64(created), nilIfEmpty(v.Chain)
	return v, notFound(err)
}

func (t *tx) DeleteAccount(id []byte) error {
	_, err := t.q.Exec(`DELETE FROM accounts WHERE id = ?`, id)
	return err
}

const deviceCols = `id, account, kind, dsk, cert, bundle, created_at, last_seen_at`

func scanDevice(row interface{ Scan(...any) error }) (store.Device, error) {
	var v store.Device
	var created, seen int64
	err := row.Scan(&v.ID, &v.Account, &v.Kind, &v.DSK, &v.Cert, &v.Bundle, &created, &seen)
	v.CreatedAt, v.LastSeenAt, v.Bundle = uint64(created), uint64(seen), nilIfEmpty(v.Bundle)
	return v, notFound(err)
}

func (t *tx) PutDevice(v store.Device) error {
	_, err := t.q.Exec(`INSERT OR REPLACE INTO devices (`+deviceCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.Account, v.Kind, v.DSK, v.Cert, nilIfEmpty(v.Bundle), i64(v.CreatedAt), i64(v.LastSeenAt))
	return err
}

func (t *tx) Device(id []byte) (store.Device, error) {
	return scanDevice(t.q.QueryRow(`SELECT `+deviceCols+` FROM devices WHERE id = ?`, id))
}

func (t *tx) DevicesOf(account []byte) ([]store.Device, error) {
	rows, err := t.q.Query(`SELECT `+deviceCols+` FROM devices WHERE account = ? ORDER BY id`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Device
	for rows.Next() {
		v, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (t *tx) DeleteDevice(id []byte) error {
	_, err := t.q.Exec(`DELETE FROM devices WHERE id = ?`, id)
	return err
}

func (t *tx) PutChallenge(v store.Challenge) error {
	_, err := t.q.Exec(`INSERT OR REPLACE INTO challenges (challenge, device, expires_at) VALUES (?, ?, ?)`,
		v.Challenge, v.Device, i64(v.ExpiresAt))
	return err
}

func (t *tx) TakeChallenge(c []byte) (store.Challenge, error) {
	v := store.Challenge{}
	var expires int64
	err := t.q.QueryRow(`DELETE FROM challenges WHERE challenge = ? RETURNING challenge, device, expires_at`, c).
		Scan(&v.Challenge, &v.Device, &expires)
	v.ExpiresAt = uint64(expires)
	return v, notFound(err)
}

func (t *tx) PutSession(v store.Session) error {
	_, err := t.q.Exec(`INSERT OR REPLACE INTO sessions (hash, device, expires_at) VALUES (?, ?, ?)`,
		v.Hash, v.Device, i64(v.ExpiresAt))
	return err
}

func (t *tx) Session(hash []byte) (store.Session, error) {
	v := store.Session{}
	var expires int64
	err := t.q.QueryRow(`SELECT hash, device, expires_at FROM sessions WHERE hash = ?`, hash).Scan(&v.Hash, &v.Device, &expires)
	v.ExpiresAt = uint64(expires)
	return v, notFound(err)
}

func (t *tx) DeleteSession(hash []byte) error {
	_, err := t.q.Exec(`DELETE FROM sessions WHERE hash = ?`, hash)
	return err
}

func (t *tx) DeleteSessionsOf(device []byte) error {
	_, err := t.q.Exec(`DELETE FROM sessions WHERE device = ?`, device)
	return err
}

// ---- circles ----

func (t *tx) CreateCircle(c store.Circle, genesis []byte) error {
	s := c.State
	if s.Seq != 0 {
		return errors.New("sqlstore: a circle starts at entry 0")
	}
	if _, err := t.q.Exec(`INSERT INTO circles (id, seq, head, created_at) VALUES (?, 0, ?, ?)`,
		c.ID, memberlog.Hash(genesis), i64(c.CreatedAt)); err != nil {
		return err
	}
	return t.stored(c.ID, genesis, s, c.CreatedAt)
}

func (t *tx) AppendEntry(circle, raw []byte, s *memberlog.State, at uint64) error {
	res, err := t.q.Exec(`UPDATE circles SET seq = ?, head = ?,
		closed_at = CASE WHEN closed_at IS NULL AND ? THEN ? ELSE closed_at END
		WHERE id = ? AND seq = ?`, s.Seq, memberlog.Hash(raw), len(s.Members) == 0, i64(at), circle, s.Seq-1)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.Join(err, fmt.Errorf("sqlstore: entry %d doesn't follow the circle's head", s.Seq))
	}
	return t.stored(circle, raw, s, at)
}

// stored records an entry, the circle's members after it, and its state.
func (t *tx) stored(circle, raw []byte, s *memberlog.State, at uint64) error {
	if _, err := t.q.Exec(`INSERT INTO entries (circle, seq, hash, raw, appended_at) VALUES (?, ?, ?, ?, ?)`,
		circle, s.Seq, memberlog.Hash(raw), raw, i64(at)); err != nil {
		return err
	}
	if _, err := t.q.Exec(`DELETE FROM members WHERE circle = ?`, circle); err != nil {
		return err
	}
	for acc := range s.Members {
		if _, err := t.q.Exec(`INSERT INTO members (account, circle) VALUES (?, ?)`, []byte(acc), circle); err != nil {
			return err
		}
	}
	t.pending[string(circle)] = s
	return nil
}

func (t *tx) Circle(id []byte) (store.Circle, error) {
	var seq, created int64
	if err := t.q.QueryRow(`SELECT seq, created_at FROM circles WHERE id = ?`, id).Scan(&seq, &created); err != nil {
		return store.Circle{}, notFound(err)
	}
	st, err := t.state(id, seq)
	if err != nil {
		return store.Circle{}, err
	}
	return store.Circle{ID: id, State: st, CreatedAt: uint64(created)}, nil
}

// state returns the circle's state after entry seq: from this transaction, from memory, or
// replayed from the log, starting from what memory holds when it can.
func (t *tx) state(id []byte, seq int64) (*memberlog.State, error) {
	if st := t.pending[string(id)]; st != nil {
		return st, nil
	}
	t.s.mu.Lock()
	known := t.s.states[string(id)]
	t.s.mu.Unlock()
	if known != nil && known.Seq == seq {
		return known, nil
	}
	st := memberlog.New()
	if known != nil && known.Seq < seq {
		st = known
	}
	rows, err := t.q.Query(`SELECT raw FROM entries WHERE circle = ? AND seq > ? AND seq <= ? ORDER BY seq`, id, st.Seq, seq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		next, _, err := memberlog.Apply(st, raw)
		if err != nil {
			return nil, fmt.Errorf("sqlstore: circle %x: the stored log fails at entry %d: %w", id, st.Seq+1, err)
		}
		st = next
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if st.Seq != seq {
		return nil, fmt.Errorf("sqlstore: circle %x: the stored log ends at entry %d, not %d", id, st.Seq, seq)
	}
	// Remember it unless memory already holds something newer: a reader may be looking at
	// an older snapshot than the last write.
	t.s.mu.Lock()
	if cur := t.s.states[string(id)]; cur == nil || cur.Seq < st.Seq {
		t.s.states[string(id)] = st
	}
	t.s.mu.Unlock()
	return st, nil
}

func (t *tx) Entries(circle []byte, after int64, limit, maxBytes int) ([][]byte, error) {
	if err := t.circleExists(circle); err != nil {
		return nil, err
	}
	rows, err := t.q.Query(`SELECT raw FROM entries WHERE circle = ? AND seq > ? ORDER BY seq LIMIT ?`, circle, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	size := 0
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if len(out) > 0 && size+len(raw) > maxBytes {
			break
		}
		out = append(out, raw)
		size += len(raw)
	}
	return out, rows.Err()
}

func (t *tx) circleExists(id []byte) error {
	var one int
	return notFound(t.q.QueryRow(`SELECT 1 FROM circles WHERE id = ?`, id).Scan(&one))
}

func (t *tx) SeqOf(circle, hash []byte) (int64, bool, error) {
	var seq int64
	err := t.q.QueryRow(`SELECT seq FROM entries WHERE circle = ? AND hash = ?`, circle, hash).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, t.circleExists(circle)
	}
	return seq, err == nil, err
}

func (t *tx) CirclesOf(account []byte) ([]store.Circle, error) {
	rows, err := t.q.Query(`SELECT circle FROM members WHERE account = ? ORDER BY circle`, account)
	if err != nil {
		return nil, err
	}
	var ids [][]byte
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]store.Circle, 0, len(ids))
	for _, id := range ids {
		c, err := t.Circle(id)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func (t *tx) PutRemoval(v store.Removal) error {
	_, err := t.q.Exec(`INSERT OR REPLACE INTO removals (circle, device, seq, at) VALUES (?, ?, ?, ?)`,
		v.Circle, v.Device, v.Seq, i64(v.At))
	return err
}

func (t *tx) Removal(circle, device []byte) (store.Removal, error) {
	v := store.Removal{}
	var at int64
	err := t.q.QueryRow(`SELECT circle, device, seq, at FROM removals WHERE circle = ? AND device = ?`, circle, device).
		Scan(&v.Circle, &v.Device, &v.Seq, &at)
	v.At = uint64(at)
	return v, notFound(err)
}

// ---- envelopes ----

func (t *tx) PutEnvelope(v store.Envelope) (uint64, error) {
	res, err := t.q.Exec(`INSERT INTO envelopes (circle, sender, received_at, expires_at, raw) VALUES (?, ?, ?, ?, ?)`,
		v.Circle, v.Sender, i64(v.ReceivedAt), i64(v.ExpiresAt), v.Raw)
	if err != nil {
		return 0, err
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for _, r := range v.Recipients {
		if _, err := t.q.Exec(`INSERT OR IGNORE INTO deliveries (device, seq) VALUES (?, ?)`, r, seq); err != nil {
			return 0, err
		}
	}
	return uint64(seq), nil
}

func (t *tx) Inbox(device []byte, circles [][]byte, after uint64, limit, maxBytes int, now uint64) ([]store.Envelope, bool, error) {
	in := map[string]bool{}
	for _, c := range circles {
		in[string(c)] = true
	}
	rows, err := t.q.Query(`SELECT e.seq, e.circle, e.sender, e.received_at, e.expires_at, e.raw
		FROM deliveries d JOIN envelopes e ON e.seq = d.seq
		WHERE d.device = ? AND d.seq > ? AND e.expires_at > ?
		ORDER BY d.seq`, device, i64(after), i64(now))
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []store.Envelope
	size := 0
	for rows.Next() {
		var e store.Envelope
		var seq, received, expires int64
		if err := rows.Scan(&seq, &e.Circle, &e.Sender, &received, &expires, &e.Raw); err != nil {
			return nil, false, err
		}
		if !in[string(e.Circle)] {
			continue
		}
		if len(out) == limit || (len(out) > 0 && size+8+len(e.Raw) > maxBytes) {
			return out, true, nil
		}
		e.Seq, e.ReceivedAt, e.ExpiresAt = uint64(seq), uint64(received), uint64(expires)
		out = append(out, e)
		size += 8 + len(e.Raw)
	}
	return out, false, rows.Err()
}

func (t *tx) Seen(circle, sender []byte, seq uint64) (store.SeenRecord, bool, error) {
	var r store.SeenRecord
	var digest []byte
	var received, keep int64
	err := t.q.QueryRow(`SELECT digest, received_at, keep_until FROM seen WHERE circle = ? AND sender = ? AND seq = ?`,
		circle, sender, i64(seq)).Scan(&digest, &received, &keep)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	if err != nil {
		return r, false, err
	}
	copy(r.Digest[:], digest)
	r.ReceivedAt, r.KeepUntil = uint64(received), uint64(keep)
	return r, true, nil
}

func (t *tx) PutSeen(circle, sender []byte, seq uint64, r store.SeenRecord) error {
	_, err := t.q.Exec(`INSERT OR REPLACE INTO seen (circle, sender, seq, digest, received_at, keep_until)
		VALUES (?, ?, ?, ?, ?, ?)`, circle, sender, i64(seq), r.Digest[:], i64(r.ReceivedAt), i64(r.KeepUntil))
	return err
}

// ---- invites ----

const inviteCols = `id, circle, account, expires_at, requests, askers, used, result, result_at, ended`

func scanInvite(row interface{ Scan(...any) error }) (store.Invite, error) {
	var v store.Invite
	var expires, resultAt int64
	var requests, askers []byte
	if err := row.Scan(&v.ID, &v.Circle, &v.Account, &expires, &requests, &askers, &v.Used, &v.Result, &resultAt, &v.Ended); err != nil {
		return v, notFound(err)
	}
	var err1, err2 error
	v.Requests, err1 = unframes(requests)
	v.Askers, err2 = unframes(askers)
	v.ExpiresAt, v.ResultAt, v.Result = uint64(expires), uint64(resultAt), nilIfEmpty(v.Result)
	return v, errors.Join(err1, err2)
}

func (t *tx) PutInvite(v store.Invite) error {
	_, err := t.q.Exec(`INSERT OR REPLACE INTO invites (`+inviteCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.Circle, v.Account, i64(v.ExpiresAt), frames(v.Requests), frames(v.Askers), v.Used, nilIfEmpty(v.Result),
		i64(v.ResultAt), v.Ended)
	return err
}

func (t *tx) Invite(id []byte) (store.Invite, error) {
	return scanInvite(t.q.QueryRow(`SELECT `+inviteCols+` FROM invites WHERE id = ?`, id))
}

func (t *tx) InvitesOf(circle []byte) ([]store.Invite, error) {
	rows, err := t.q.Query(`SELECT `+inviteCols+` FROM invites WHERE circle = ? ORDER BY id`, circle)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []store.Invite
	for rows.Next() {
		v, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---- sweeping ----

func (t *tx) Sweep(now uint64, r store.Retention) (store.Swept, error) {
	var n store.Swept
	var err error
	count := func(c *int, query string, args ...any) {
		if err != nil {
			return
		}
		var res sql.Result
		if res, err = t.q.Exec(query, args...); err == nil {
			var k int64
			k, err = res.RowsAffected()
			*c += int(k)
		}
	}
	at := i64(now)
	count(&n.Challenges, `DELETE FROM challenges WHERE expires_at <= ?`, at)
	count(&n.Sessions, `DELETE FROM sessions WHERE expires_at <= ?`, at)
	count(&n.Tokens, `DELETE FROM tokens WHERE expires_at <= ?`, at)
	count(&n.Seen, `DELETE FROM seen WHERE keep_until <= ?`, at)
	count(&n.Removals, `DELETE FROM removals WHERE at <= ? - ?`, at, i64(r.Removals))
	count(&n.Invites, `DELETE FROM invites WHERE expires_at <= ? AND (result IS NULL OR result_at <= ? - ?)`, at, at, i64(r.Results))
	if err != nil {
		return n, err
	}
	// A closed circle goes with everything that names it: its log goes by cascade.
	rows, err := t.q.Query(`DELETE FROM circles WHERE closed_at <= ? - ? RETURNING id`, at, i64(r.ClosedCircles))
	if err != nil {
		return n, err
	}
	var gone [][]byte
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return n, err
		}
		gone = append(gone, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return n, err
	}
	n.Circles = len(gone)
	for _, id := range gone {
		count(&n.Seen, `DELETE FROM seen WHERE circle = ?`, id)
		count(&n.Removals, `DELETE FROM removals WHERE circle = ?`, id)
		count(&n.Invites, `DELETE FROM invites WHERE circle = ?`, id)
		count(&n.Envelopes, `DELETE FROM envelopes WHERE circle = ?`, id)
		delete(t.pending, string(id))
	}
	count(&n.Envelopes, `DELETE FROM envelopes WHERE expires_at <= ?`, at)
	t.gone = append(t.gone, gone...)
	return n, err
}
