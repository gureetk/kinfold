// SPDX-License-Identifier: AGPL-3.0-or-later

// Package difftest compares the server's protocol packages with the Python reference
// (reference/python) on generated and mutated inputs (PROTOCOL.md §17): log entries in
// public mode, the server's envelope checks and watch grants. Most inputs are built and
// signed with the vectors' keys, so that they get past the signature checks and reach the
// rules behind them; the rest are byte-level mutations. Accepted entries become new states,
// so the run walks beyond the vectors' own logs.
//
// It needs a Python with reference/python/requirements.txt installed:
//
//	KINFOLD_PYTHON=../.venv/bin/python go test ./internal/difftest
//
// KINFOLD_DIFF_N sets how many inputs of each kind (default 2000) and KINFOLD_DIFF_SEED
// the seed (default 1). Without KINFOLD_PYTHON the test is skipped.
package difftest_test

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/gureetk/kinfold/server/internal/envelope"
	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/kcrypto"
	"github.com/gureetk/kinfold/server/internal/memberlog"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
	"github.com/gureetk/kinfold/server/internal/watch"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// ---- the Python side ----

type oracle struct {
	in  *bufio.Writer
	out *bufio.Scanner
	id  int
}

func startOracle(t *testing.T) *oracle {
	py := os.Getenv("KINFOLD_PYTHON")
	if py == "" {
		t.Skip("set KINFOLD_PYTHON to a Python with reference/python/requirements.txt installed")
	}
	vec, err := tv.Path()
	if err != nil {
		t.Fatal(err)
	}
	vec, _ = filepath.Abs(vec)
	ref := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(vec))), "reference", "python")
	cmd := exec.Command(py, "-I", "testdata/oracle.py", ref, vec)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		cmd.Wait()
	})
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	return &oracle{in: bufio.NewWriter(stdin), out: sc}
}

func (o *oracle) ask(t *testing.T, q map[string]any) map[string]any {
	t.Helper()
	o.id++
	q["id"] = o.id
	b, _ := json.Marshal(q)
	o.in.Write(b)
	o.in.WriteByte('\n')
	if err := o.in.Flush(); err != nil {
		t.Fatalf("writing to the reference: %v", err)
	}
	if !o.out.Scan() {
		t.Fatalf("the reference stopped answering: %v", o.out.Err())
	}
	var a map[string]any
	if err := json.Unmarshal(o.out.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	if e, ok := a["error"]; ok {
		t.Fatalf("the Python reference raised on %v:\n%v", q, e)
	}
	return a
}

// ---- the people and keys of the vectors ----

type device struct {
	person  *person
	kind    uint8
	id      []byte
	dsk     ed25519.PrivateKey
	cert    []byte // from the vectors; nil for devices made here
	bundles [][]byte
}

type person struct {
	account []byte
	iks     []ed25519.PrivateKey // oldest first
	chain   []byte
	devices []*device
}

type world struct {
	people  []*person
	devices map[string]*device            // by device ID
	iks     map[string]ed25519.PrivateKey // by identity public key
	entries [][]byte                      // every entry in the vectors, for mutation
	envs    [][]byte
	grants  [][]byte
	now     uint64
}

func pub(k ed25519.PrivateKey) []byte { return k.Public().(ed25519.PublicKey) }

func newWorld(t *testing.T) *world {
	v := tv.Load(t)
	w := &world{devices: map[string]*device{}, iks: map[string]ed25519.PrivateKey{},
		now: tv.Num(tv.Obj(v["envelopes"])["receiver_now"])}
	for _, pv := range tv.Obj(v["identities"]) {
		pp := tv.Obj(pv)
		p := &person{account: tv.Hex(pp["account_id"]), chain: tv.Hex(pp["chain"])}
		for _, s := range tv.Arr(pp["ik_seeds"]) {
			k := ed25519.NewKeyFromSeed(tv.Hex(s))
			p.iks = append(p.iks, k)
			w.iks[string(pub(k))] = k
		}
		for _, dv := range tv.Obj(pp["devices"]) {
			d := tv.Obj(dv)
			dev := &device{person: p, kind: uint8(tv.Num(d["kind"])), id: tv.Hex(d["device_id"]),
				dsk: ed25519.NewKeyFromSeed(tv.Hex(d["dsk_seed"])), cert: tv.Hex(d["cert"])}
			for _, b := range tv.Arr(d["bundles"]) {
				dev.bundles = append(dev.bundles, tv.Hex(b))
			}
			p.devices = append(p.devices, dev)
			w.devices[string(dev.id)] = dev
		}
		w.people = append(w.people, p)
	}
	lg := tv.Obj(v["log"])
	for _, e := range tv.Arr(lg["entries"]) {
		w.entries = append(w.entries, tv.Hex(tv.Obj(e)["raw"]))
	}
	for _, c := range tv.Arr(lg["cases"]) {
		for _, e := range tv.Arr(tv.Obj(c)["entries"]) {
			w.entries = append(w.entries, tv.Hex(tv.Obj(e)["raw"]))
		}
	}
	env := tv.Obj(v["envelopes"])
	for _, g := range []string{"valid", "invalid", "server_rejects"} {
		for _, c := range tv.Arr(env[g]) {
			w.envs = append(w.envs, tv.Hex(tv.Obj(c)["raw"]))
		}
	}
	for _, g := range tv.Arr(tv.Obj(v["watch_grants"])["grants"]) {
		w.grants = append(w.grants, tv.Hex(tv.Obj(g)["grant"]))
	}
	return w
}

// ---- builders ----

func randBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func chance(r *rand.Rand, p float64) bool { return r.Float64() < p }

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

func makeCert(ik ed25519.PrivateKey, account, dsk []byte, kind uint8, issued uint64) []byte {
	tbs := wire.Concat([]byte{0}, wire.U16(1), account, dsk, []byte{kind}, wire.U64(issued), pub(ik))
	return append(tbs, kcrypto.Sign(ik, "device-cert", tbs[:60])...)
}

func makeBundle(dsk ed25519.PrivateKey, account, dek []byte, nb, na uint64) []byte {
	tbs := wire.Concat([]byte{0}, wire.U16(1), account, identity.DeviceID(pub(dsk)), dek, wire.U64(nb), wire.U64(na),
		[]byte{0}, wire.U32(0))
	return append(tbs, kcrypto.Sign(dsk, "key-bundle", tbs)...)
}

// newDevice makes a device for p, with a certificate under the identity key ik.
func (w *world) newDevice(r *rand.Rand, p *person, ik ed25519.PrivateKey, kind uint8, at uint64) *device {
	d := &device{person: p, kind: kind, dsk: ed25519.NewKeyFromSeed(randBytes(r, 32))}
	d.id = identity.DeviceID(pub(d.dsk))
	d.cert = makeCert(ik, p.account, pub(d.dsk), kind, at)
	w.devices[string(d.id)] = d
	return d
}

// freshBundle is a bundle for d, usually valid and current at time at.
func freshBundle(r *rand.Rand, d *device, account []byte, at uint64) []byte {
	dek := randBytes(r, 32)
	dek[31] &= 0x7f
	if chance(r, 0.05) {
		dek = make([]byte, 32) // a low-order key (§3.5)
	}
	nb := at - uint64(r.IntN(3_600_000))
	na := nb + 1 + uint64(r.Int64N(14*identity.DayMS))
	switch r.IntN(20) {
	case 0:
		nb, na = at+700_000, at+800_000 // not yet current
	case 1:
		na = nb + 35*identity.DayMS + 1 // too long
	case 2:
		nb, na = at-2*identity.DayMS, at // expired at `at`
	case 3:
		nb, na = r.Uint64(), r.Uint64() // anything, near the end of the range included
	}
	return makeBundle(d.dsk, account, dek, nb, na)
}

// ---- states held on both sides ----

type gstate struct {
	name  string
	s     *memberlog.State
	index map[string]int64
	heads [][]byte
	last  uint64 // created_at of the last entry
}

func (g *gstate) SeqOf(h []byte) (int64, bool) { s, ok := g.index[string(h)]; return s, ok }

func (g *gstate) extend(name string, s *memberlog.State, raw []byte, at uint64) *gstate {
	n := &gstate{name: name, s: s, index: make(map[string]int64, len(g.index)+1), heads: append(g.heads[:len(g.heads):len(g.heads)], memberlog.Hash(raw)), last: at}
	for k, v := range g.index {
		n.index[k] = v
	}
	n.index[string(memberlog.Hash(raw))] = s.Seq
	return n
}

func mainStates(t *testing.T) []*gstate {
	out := []*gstate{{name: "empty", s: memberlog.New(), index: map[string]int64{}}}
	g := out[0]
	for i, e := range tv.Arr(tv.Obj(tv.Load(t)["log"])["entries"]) {
		raw := tv.Hex(tv.Obj(e)["raw"])
		s, entry, err := memberlog.Apply(g.s, raw)
		if err != nil {
			t.Fatal(err)
		}
		g = g.extend(fmt.Sprintf("m%d", i), s, raw, entry.CreatedAt)
		out = append(out, g)
	}
	return out
}

// ---- log entries ----

func members(s *memberlog.State) []*memberlog.Member {
	var out []*memberlog.Member
	for _, k := range sortedKeys(s.Members) {
		out = append(out, s.Members[k])
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	for i := range ks { // insertion sort: maps here are small
		for j := i; j > 0 && ks[j] < ks[j-1]; j-- {
			ks[j], ks[j-1] = ks[j-1], ks[j]
		}
	}
	return ks
}

func activeDevices(s *memberlog.State) []*memberlog.Device {
	var out []*memberlog.Device
	for _, m := range members(s) {
		for _, k := range sortedKeys(m.Devices) {
			out = append(out, m.Devices[k])
		}
	}
	return out
}

// wrapsFor names devices with their current key IDs, perturbed now and then.
func wrapsFor(r *rand.Rand, devs []*memberlog.Device, extra []byte) []byte {
	var ws [][]byte
	for _, d := range devs {
		ws = append(ws, wire.Concat(d.ID, d.Bundle.KeyID(), randBytes(r, 80)))
	}
	switch r.IntN(12) {
	case 0:
		if len(ws) > 0 {
			ws = ws[1:]
		}
	case 1:
		if extra != nil {
			ws = append(ws, wire.Concat(extra, randBytes(r, 88)))
		}
	case 2:
		if len(ws) > 1 {
			ws[0], ws[1] = ws[1], ws[0]
		}
	case 3:
		if len(ws) > 0 {
			ws[0][16] ^= 1 // a stale key ID
		}
	case 4:
		ws = append(ws, randBytes(r, 104))
	}
	return wire.Concat(ws...)
}

func epochFields(r *rand.Rand, devs []*memberlog.Device, extra []byte) []byte {
	if chance(r, 0.5) {
		return wire.Concat(make([]byte, 32), wire.Vec32(nil))
	}
	return wire.Concat(randBytes(r, 32), wire.Vec32(wrapsFor(r, devs, extra)))
}

func (w *world) ikOf(m *memberlog.Member) ed25519.PrivateKey { return w.iks[string(m.IK)] }

// entry builds a log entry for state g. Most are signed by a device the state knows.
func (w *world) entry(r *rand.Rand, g *gstate) []byte {
	s := g.s
	at := g.last + uint64(r.IntN(600_000))
	if chance(r, 0.02) {
		at = r.Uint64()
	}
	if chance(r, 0.15) { // a mutated entry from the vectors, re-signed now and then
		raw := append([]byte(nil), pick(r, w.entries)...)
		for n := 1 + r.IntN(3); n > 0 && len(raw) > 0; n-- {
			raw[r.IntN(len(raw))] ^= byte(1 << r.IntN(8))
		}
		if d := w.devices[string(raw[min(len(raw), 68):min(len(raw), 84)])]; d != nil && len(raw) > 64 && chance(r, 0.5) {
			copy(raw[len(raw)-64:], kcrypto.Sign(d.dsk, "log-entry", raw[:len(raw)-64]))
		}
		return raw
	}

	var t uint8
	if s.CircleID == nil {
		t = memberlog.Genesis
	} else {
		t = uint8(2 + r.IntN(11))
	}
	if chance(r, 0.02) {
		t = pick(r, []uint8{0, 1, 13, 255})
	}
	// The author: a device of the circle, any device of the vectors, or a stranger.
	var author *device
	devs := activeDevices(s)
	switch {
	case len(devs) > 0 && chance(r, 0.9):
		author = w.devices[string(pick(r, devs).ID)]
	case chance(r, 0.5):
		author = w.devices[pick(r, sortedKeys(w.devices))]
	}
	var am *memberlog.Member
	if author != nil {
		am = s.Member(author.person.account)
	}
	body := w.body(r, g, t, author, am, at)

	cid, seq, prev, epoch := s.CircleID, uint64(s.Seq+1), s.Head, s.Epoch
	if cid == nil {
		cid, seq, prev, epoch = make([]byte, 16), 0, make([]byte, 32), 0
	}
	switch r.IntN(25) {
	case 0:
		seq += uint64(r.IntN(3)) - 1
	case 1:
		prev = randBytes(r, 32)
	case 2:
		cid = randBytes(r, 16)
	case 3:
		epoch += uint32(r.IntN(3)) - 1
	}
	authorID := randBytes(r, 16)
	if author != nil {
		authorID = author.id
	}
	if t == memberlog.Genesis && len(body) >= 156 && chance(r, 0.95) {
		authorID = identity.DeviceID(body[19:51]) // the founder certificate's device
		author = w.devices[string(authorID)]
	}
	hdr := wire.Concat([]byte{0}, wire.U16(1), []byte{t}, cid, wire.U64(seq), prev, wire.U64(at), authorID, wire.U32(epoch))
	if chance(r, 0.01) {
		hdr[0] = 1
	}
	tbs := wire.Concat(hdr, wire.Vec32(body))
	sig := randBytes(r, 64)
	if author != nil && chance(r, 0.97) {
		sig = kcrypto.Sign(author.dsk, "log-entry", tbs)
	}
	return append(tbs, sig...)
}

func (w *world) body(r *rand.Rand, g *gstate, t uint8, author *device, am *memberlog.Member, at uint64) []byte {
	s := g.s
	details := func() []byte {
		if chance(r, 0.03) {
			return randBytes(r, memberlog.DetailsLen-1+2*r.IntN(2))
		}
		return randBytes(r, memberlog.DetailsLen)
	}
	// someone: a person of the vectors and a phone or tablet of theirs, usually a new one.
	someone := func() (*person, ed25519.PrivateKey, *device, []byte) {
		p := pick(r, w.people)
		ik := p.iks[len(p.iks)-1]
		chain := p.chain
		if chance(r, 0.1) && len(p.iks) > 1 {
			ik, chain = p.iks[0], nil // a key the account has rotated away from
		}
		kind := uint8(1 + r.IntN(2))
		if chance(r, 0.1) {
			kind = uint8(r.IntN(7))
		}
		d := w.newDevice(r, p, ik, kind, at)
		if chance(r, 0.05) {
			d.cert[60] ^= 1 // a broken signature
		}
		return p, ik, d, chain
	}
	switch t {
	case memberlog.Genesis:
		_, _, d, chain := someone()
		return wire.Concat(d.cert, wire.Vec16(chain), freshBundle(r, d, d.person.account, at), randBytes(r, 32), details())
	case memberlog.AddMember:
		p, ik, d, chain := someone()
		if chance(r, 0.1) && len(p.devices) > 0 && p.devices[0].cert != nil {
			d = p.devices[0] // a device that may already be in the circle
		}
		bundle := freshBundle(r, d, p.account, at)
		invite := randBytes(r, 16)
		if used := sortedKeys(s.UsedInvites); len(used) > 0 && chance(r, 0.1) {
			invite = []byte(pick(r, used))
		}
		terms := randBytes(r, 32)
		consent := kcrypto.Sign(ik, "join-consent", wire.Concat(s.CircleID, invite, d.cert, bundle, terms))
		switch r.IntN(12) {
		case 0:
			consent = randBytes(r, 64)
		case 1: // consent to other terms
			consent = kcrypto.Sign(ik, "join-consent", wire.Concat(s.CircleID, invite, d.cert, bundle, randBytes(r, 32)))
		}
		admin := byte(r.IntN(2))
		if chance(r, 0.02) {
			admin = 2
		}
		return wire.Concat(d.cert, wire.Vec16(chain), bundle, invite, terms, consent, []byte{admin}, details())
	case memberlog.RemoveMember:
		target := randBytes(r, 16)
		if ms := members(s); len(ms) > 0 && chance(r, 0.9) {
			target = pick(r, ms).Account
		}
		rest := s.ReceivingDevices(func(d *memberlog.Device) bool { return string(d.Account) == string(target) })
		return wire.Concat(target, epochFields(r, rest, nil))
	case memberlog.AddDevice, memberlog.AddRecovery:
		var d *device
		var account []byte
		if am != nil && chance(r, 0.8) {
			ik := w.ikOf(am)
			if ik == nil || chance(r, 0.05) {
				ik = ed25519.NewKeyFromSeed(randBytes(r, 32))
			}
			kind := uint8(1 + r.IntN(4))
			if t == memberlog.AddRecovery || chance(r, 0.05) {
				kind = identity.Recovery
			}
			d, account = w.newDevice(r, author.person, ik, kind, at), am.Account
			if existing := author.person.devices; chance(r, 0.25) && len(existing) > 0 {
				d = pick(r, existing) // perhaps already in the circle, perhaps under an older key
			}
		} else {
			_, _, d, _ = someone()
			account = d.person.account
		}
		if t == memberlog.AddRecovery {
			return d.cert
		}
		return wire.Concat(d.cert, freshBundle(r, d, account, at))
	case memberlog.RemoveDevice:
		target := randBytes(r, 16)
		if devs := activeDevices(s); len(devs) > 0 && chance(r, 0.9) {
			target = pick(r, devs).ID
		}
		rest := s.ReceivingDevices(func(d *memberlog.Device) bool { return string(d.ID) == string(target) })
		return wire.Concat(target, epochFields(r, rest, target))
	case memberlog.UpdateKey:
		if author == nil {
			return randBytes(r, 152)
		}
		if len(author.bundles) > 0 && chance(r, 0.2) {
			return pick(r, author.bundles)
		}
		account := author.person.account
		if chance(r, 0.05) {
			account = randBytes(r, 16)
		}
		return freshBundle(r, author, account, at)
	case memberlog.Policy:
		return details()
	case memberlog.Rekey:
		return wire.Concat(randBytes(r, 32), wire.Vec32(wrapsFor(r, s.ReceivingDevices(nil), randBytes(r, 16))))
	case memberlog.SetAdmin:
		target := randBytes(r, 16)
		if ms := members(s); len(ms) > 0 && chance(r, 0.9) {
			target = pick(r, ms).Account
		}
		return wire.Concat(target, []byte{byte(r.IntN(2) + r.IntN(50)/49)})
	case memberlog.SetOptions:
		return wire.U32(pick(r, []uint32{0, 1, 2, 3, 4, 7, 1 << 31}))
	case memberlog.RotateIdentity:
		var oldK ed25519.PrivateKey
		account := randBytes(r, 16)
		if am != nil {
			oldK, account = w.ikOf(am), am.Account
		}
		if oldK == nil || chance(r, 0.05) {
			oldK = ed25519.NewKeyFromSeed(randBytes(r, 32))
		}
		newK := ed25519.NewKeyFromSeed(randBytes(r, 32))
		if chance(r, 0.2) {
			newK = pick(r, pick(r, w.people).iks) // someone's key, perhaps a member's
		}
		w.iks[string(pub(newK))] = newK
		tbs := wire.Concat(account, pub(oldK), pub(newK))
		link := wire.Concat(pub(oldK), pub(newK), kcrypto.Sign(oldK, "identity-rotate", tbs), kcrypto.Sign(newK, "identity-rotate", tbs))
		if chance(r, 0.05) {
			link[100] ^= 1
		}
		return link
	}
	return randBytes(r, r.IntN(200))
}

// ---- envelopes ----

func (w *world) envelope(r *rand.Rand, g *gstate) []byte {
	s := g.s
	if chance(r, 0.1) {
		raw := append([]byte(nil), pick(r, w.envs)...)
		raw[r.IntN(len(raw))] ^= byte(1 << r.IntN(8))
		return raw
	}
	recv := s.ReceivingDevices(nil)
	var sender *device
	switch {
	case len(recv) > 0 && chance(r, 0.85):
		sender = w.devices[string(pick(r, recv).ID)]
	case chance(r, 0.5):
		sender = w.devices[pick(r, sortedKeys(w.devices))]
	}
	senderID := randBytes(r, 16)
	if sender != nil {
		senderID = sender.id
	}
	kind := byte(1 + r.IntN(2))
	if chance(r, 0.03) {
		kind = byte(r.IntN(256))
	}
	cid := s.CircleID
	if cid == nil || chance(r, 0.03) {
		cid = randBytes(r, 16)
	}
	sentAt := w.now + pick(r, []uint64{0, 1, ^uint64(0) - envelope.MaxAgeMS + 1, ^uint64(0) - envelope.MaxAgeMS,
		envelope.MaxAheadMS, envelope.MaxAheadMS + 1, uint64(r.Int64N(10 * identity.DayMS))})
	if chance(r, 0.03) {
		sentAt = r.Uint64()
	}
	ttl := pick(r, []uint32{60, 59, 2_592_000, 2_592_001, 3_600, r.Uint32()})
	head := s.Head
	switch r.IntN(10) {
	case 0:
		head = randBytes(r, 32)
	case 1, 2:
		if len(g.heads) > 0 {
			head = pick(r, g.heads)
		}
	}
	var named []*memberlog.Device
	if kind == 1 || chance(r, 0.5) {
		named = s.ReceivingDevices(func(d *memberlog.Device) bool { return string(d.ID) == string(senderID) })
	} else {
		for _, d := range recv {
			if chance(r, 0.5) {
				named = append(named, d)
			}
		}
	}
	var extra []byte
	if devs := activeDevices(s); len(devs) > 0 {
		extra = pick(r, devs).ID // perhaps the sender, perhaps a recovery device
	}
	wraps := wrapsFor(r, named, extra)
	hdr := wire.Concat([]byte{0}, wire.U16(1), []byte{kind}, cid, senderID, wire.U64(uint64(r.IntN(4))), wire.U64(sentAt),
		wire.U32(ttl), head)
	if chance(r, 0.01) {
		hdr[2] = 2
	}
	tbs := wire.Concat(hdr, wire.Vec32(wraps), wire.Vec32(randBytes(r, 16+r.IntN(48))))
	sig := randBytes(r, 64)
	if sender != nil && chance(r, 0.97) {
		sig = kcrypto.Sign(sender.dsk, "envelope", tbs)
	}
	return append(tbs, sig...)
}

// ---- watch grants ----

func (w *world) grant(r *rand.Rand, g *gstate) []byte {
	s := g.s
	if chance(r, 0.1) {
		raw := append([]byte(nil), pick(r, w.grants)...)
		raw[r.IntN(len(raw))] ^= byte(1 << r.IntN(8))
		return raw
	}
	cid := s.CircleID
	if cid == nil || chance(r, 0.05) {
		cid = randBytes(r, 16)
	}
	var watched *device
	if devs := activeDevices(s); len(devs) > 0 && chance(r, 0.9) {
		watched = w.devices[string(pick(r, devs).ID)]
	} else {
		watched = w.devices[pick(r, sortedKeys(w.devices))]
	}
	if watched == nil {
		watched = w.devices[pick(r, sortedKeys(w.devices))]
	}
	watcher := pick(r, w.people).account
	if ms := members(s); len(ms) > 0 && chance(r, 0.8) {
		watcher = pick(r, ms).Account
	}
	after := pick(r, []uint16{15, 14, 1440, 1441, 60, uint16(r.Uint32())})
	notAfter := w.now + pick(r, []uint64{1, 0, watch.MaxLifeMS, watch.MaxLifeMS + 1, uint64(r.Int64N(40 * identity.DayMS))})
	if chance(r, 0.05) {
		notAfter = w.now - uint64(r.IntN(1000))
	}
	tbs := wire.Concat([]byte{0}, cid, watched.id, watcher, wire.U16(after), wire.U64(notAfter))
	if chance(r, 0.01) {
		tbs[0] = 1
	}
	sig := randBytes(r, 64)
	if chance(r, 0.97) {
		sig = kcrypto.Sign(watched.dsk, "watch-grant", tbs)
	}
	return append(tbs, sig...)
}

// ---- the run ----

type seenMap map[string][32]byte

func (m seenMap) Digest(sender []byte, seq uint64) ([32]byte, bool) {
	d, ok := m[fmt.Sprintf("%x/%d", sender, seq)]
	return d, ok
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}

func TestDifferential(t *testing.T) {
	o := startOracle(t)
	w := newWorld(t)
	n := envInt("KINFOLD_DIFF_N", 2000)
	seed := uint64(envInt("KINFOLD_DIFF_SEED", 1))
	r := rand.New(rand.NewPCG(seed, 0x6b696e666f6c64))
	pool := mainStates(t)
	counts := map[string]int{}

	for i := 0; i < n; i++ {
		g := pick(r, pool)
		if i < 2*len(pool) {
			g = pool[i%len(pool)]
		}
		raw := w.entry(r, g)
		keep := ""
		if len(pool) < 300 && chance(r, 0.5) {
			keep = fmt.Sprintf("k%d", i)
		}
		a := o.ask(t, map[string]any{"op": "apply", "state": g.name, "raw": hex.EncodeToString(raw), "keep": keep})
		ns, e, err := memberlog.Apply(g.s, raw)
		result, reason := "accepted", ""
		var f *memberlog.Fatal
		if errors.As(err, &f) {
			result, reason = "fatal", f.Reason
		} else if err != nil {
			t.Fatal(err)
		}
		pyReason, _ := a["reason"].(string)
		if result != a["result"] || reason != pyReason {
			t.Fatalf("log entry %d on %s: Go %s %q, Python %v %q\nentry %x", i, g.name, result, reason, a["result"], pyReason, raw)
		}
		counts["log "+result+" "+reason]++
		if ns == nil {
			continue
		}
		if got := tv.Normalize(ns.PublicJSON()); !reflect.DeepEqual(got, a["state"]) {
			t.Fatalf("log entry %d on %s: public states differ\n  Go %v\nPython %v\nentry %x", i, g.name, got, a["state"], raw)
		}
		if keep != "" {
			pool = append(pool, g.extend(keep, ns, raw, e.CreatedAt))
		}
	}

	for i := 0; i < n; i++ {
		g := pick(r, pool)
		raw := w.envelope(r, g)
		seen := seenMap{}
		var pySeen [][]any
		if len(raw) >= 44 && chance(r, 0.2) {
			digest := sha256.Sum256(raw)
			if chance(r, 0.5) {
				digest[0] ^= 1
			}
			seen[fmt.Sprintf("%x/%d", raw[20:36], wire.NewReader(raw[36:44]).U64())] = digest
			pySeen = append(pySeen, []any{hex.EncodeToString(raw[20:36]), wire.NewReader(raw[36:44]).U64(), hex.EncodeToString(digest[:])})
		}
		if pySeen == nil {
			pySeen = [][]any{}
		}
		a := o.ask(t, map[string]any{"op": "envelope", "state": g.name, "raw": hex.EncodeToString(raw), "now": w.now, "seen": pySeen})
		_, out, err := envelope.Check(g.s, g, seen, raw, w.now)
		got := map[envelope.Outcome]string{envelope.Store: "stored", envelope.Duplicate: "duplicate"}[out]
		var ref *envelope.Refused
		if errors.As(err, &ref) {
			got = ref.Reason
		} else if err != nil {
			t.Fatal(err)
		}
		if got != a["result"] {
			t.Fatalf("envelope %d on %s: Go %s, Python %v\nenvelope %x", i, g.name, got, a["result"], raw)
		}
		counts["envelope "+got]++
	}

	for i := 0; i < n/2; i++ {
		g := pick(r, pool)
		raw := w.grant(r, g)
		a := o.ask(t, map[string]any{"op": "grant", "state": g.name, "raw": hex.EncodeToString(raw), "now": w.now})
		_, ok := watch.Valid(g.s, raw, w.now)
		if ok != a["valid"] {
			t.Fatalf("grant %d on %s: Go %v, Python %v\ngrant %x", i, g.name, ok, a["valid"], raw)
		}
		counts[fmt.Sprintf("grant valid=%v", ok)]++
	}

	t.Logf("%d states reached; outcomes:", len(pool))
	for _, k := range sortedKeys(counts) {
		t.Logf("  %-40s %d", k, counts[k])
	}
}
