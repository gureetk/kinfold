// SPDX-License-Identifier: Apache-2.0

// Command kinfold-vectors checks the parts of the Kinfold v0 test vectors that
// a server must enforce ("public mode", PROTOCOL.md §6.2 and §17), using only
// the Go standard library: primitives, identities, every member-log entry and
// case with its public outcome and public state, the envelope checks a server
// makes, and server identity and login. It is the seed of the server's
// protocol package.
//
// Usage: go run . ../../spec/vectors/kinfold-v0.json
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
)

// ---- primitives (§3) ----

const prefix = "kinfold/v0/"

func vec16(b []byte) []byte {
	out := make([]byte, 2, 2+len(b))
	binary.BigEndian.PutUint16(out, uint16(len(b)))
	return append(out, b...)
}

func label(purpose string) []byte { return vec16([]byte(prefix + purpose)) }

func H(purpose string, data ...[]byte) []byte {
	h := sha256.New()
	h.Write(label(purpose))
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

func verify(pub []byte, purpose string, data, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), append(label(purpose), data...), sig)
}

func kdfLabel(ikm, info []byte, n int) []byte { // HKDF-SHA256 with a zero salt
	ext := hmac.New(sha256.New, make([]byte, 32))
	ext.Write(ikm)
	prk := ext.Sum(nil)
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

// ---- encoding (§2) ----

type reader struct {
	b   []byte
	p   int
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n < 0 || r.p+n > len(r.b) {
		r.bad = true
		if n >= 0 && n <= 64 {
			return make([]byte, n)
		}
		return nil
	}
	s := r.b[r.p : r.p+n]
	r.p += n
	return s
}
func (r *reader) u8() int     { return int(r.take(1)[0]) }
func (r *reader) u16() int    { return int(binary.BigEndian.Uint16(r.take(2))) }
func (r *reader) u32() int    { return int(binary.BigEndian.Uint32(r.take(4))) }
func (r *reader) u64() uint64 { return binary.BigEndian.Uint64(r.take(8)) }
func (r *reader) vec32() []byte {
	return r.take(r.u32())
}
func (r *reader) ok() bool { return !r.bad && r.p == len(r.b) }

// ---- certificates and bundles (§4) ----

type cert struct {
	raw, acc, dsk, ik, sig []byte
	ver, suite, kind       int
}

func readCert(r *reader) cert {
	start := r.p
	c := cert{ver: r.u8(), suite: r.u16(), acc: r.take(16), dsk: r.take(32), kind: r.u8()}
	r.u64()
	c.ik, c.sig = r.take(32), r.take(64)
	if !r.bad {
		c.raw = r.b[start:r.p]
	}
	return c
}

func (c cert) deviceID() []byte { return H("device-id", c.dsk)[:16] }

func certOK(c cert) bool {
	return c.raw != nil && c.ver == 0 && c.suite == 1 && c.kind >= 1 && c.kind <= 4 &&
		bytes.Equal(c.acc, H("account-id", c.ik)[:16]) && verify(c.ik, "device-cert", c.raw[:60], c.sig)
}

type bundle struct {
	raw, acc, dev, dek, sig []byte
	ver, suite              int
	nb, na                  uint64
}

func readBundle(r *reader) bundle {
	start := r.p
	b := bundle{ver: r.u8(), suite: r.u16(), acc: r.take(16), dev: r.take(16), dek: r.take(32), nb: r.u64(), na: r.u64()}
	b.sig = r.take(64)
	if !r.bad {
		b.raw = r.b[start:r.p]
	}
	return b
}

func (b bundle) keyID() []byte { return H("key-id", b.dek)[:8] }

func bundleOK(b bundle, dsk, acc []byte) bool {
	return b.raw != nil && b.ver == 0 && b.suite == 1 && bytes.Equal(b.dev, H("device-id", dsk)[:16]) &&
		bytes.Equal(b.acc, acc) && b.nb < b.na && b.na <= b.nb+35*86_400_000 && verify(dsk, "key-bundle", b.raw[:83], b.sig)
}

// ---- public circle state (§6.1) ----

type device struct {
	id, acc, dsk []byte
	kind         int
	b            bundle
}

type member struct {
	acc, ik []byte
	admin   bool
	devs    map[string]*device
}

type state struct {
	cid, head []byte
	seq       int64
	epoch     int
	pending   bool // rekey_pending (§6.4)
	members   map[string]*member
	hashes    map[string]bool
}

func newState() *state {
	return &state{head: make([]byte, 32), seq: -1, members: map[string]*member{}, hashes: map[string]bool{}}
}

func (s *state) clone() *state {
	c := &state{cid: s.cid, head: s.head, seq: s.seq, epoch: s.epoch, pending: s.pending, members: map[string]*member{}, hashes: map[string]bool{}}
	for k, v := range s.hashes {
		c.hashes[k] = v
	}
	for k, m := range s.members {
		nm := &member{acc: m.acc, ik: m.ik, admin: m.admin, devs: map[string]*device{}}
		for dk, d := range m.devs {
			nd := *d
			nm.devs[dk] = &nd
		}
		c.members[k] = nm
	}
	return c
}

func (s *state) device(id []byte) *device {
	for _, m := range s.members {
		if d, ok := m.devs[string(id)]; ok {
			return d
		}
	}
	return nil
}

func (s *state) devices(skip func(*device) bool) []*device {
	var out []*device
	for _, m := range s.members {
		for _, d := range m.devs {
			if skip == nil || !skip(d) {
				out = append(out, d)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].id, out[j].id) < 0 })
	return out
}

func (s *state) admins() int {
	n := 0
	for _, m := range s.members {
		if m.admin {
			n++
		}
	}
	return n
}

// ---- log entries in public mode (§5, §6.3 steps 1–8, §6.4) ----

type body struct {
	c                                     cert
	bu                                    bundle
	commit, details, invite, consent, tgt []byte
	admin                                 bool
	wraps                                 [][]byte
}

func parseBody(t int, raw []byte) (body, bool) {
	r := &reader{b: raw}
	var b body
	flag := func() bool {
		v := r.u8()
		if v > 1 {
			r.bad = true
		}
		return v == 1
	}
	wraps := func() {
		w := r.vec32()
		if len(w)%104 != 0 {
			r.bad = true
			return
		}
		for i := 0; i < len(w); i += 104 {
			b.wraps = append(b.wraps, w[i:i+104])
		}
	}
	if t == 1 || t == 2 || t == 4 {
		b.c, b.bu = readCert(r), readBundle(r)
	}
	switch t {
	case 1:
		b.commit, b.details = r.take(32), r.vec32()
	case 2:
		b.invite, b.consent = r.take(16), r.take(64)
		b.admin = flag()
		b.details = r.vec32()
	case 3, 5:
		b.tgt, b.commit = r.take(16), r.take(32)
		wraps()
	case 6:
		b.bu = readBundle(r)
	case 7:
		b.details = r.vec32()
	case 8:
		b.commit = r.take(32)
		wraps()
	case 9:
		b.tgt = r.take(16)
		b.admin = flag()
	}
	if !r.ok() || ((t == 1 || t == 2 || t == 7) && len(b.details) < 28) {
		return b, false
	}
	return b, true
}

func wrapsCover(ws [][]byte, devs []*device) bool {
	if len(ws) != len(devs) {
		return false
	}
	want := map[string][]byte{}
	for _, d := range devs {
		want[string(d.id)] = d.b.keyID()
	}
	for i, w := range ws {
		if i > 0 && bytes.Compare(ws[i-1][:16], w[:16]) >= 0 {
			return false
		}
		if k, ok := want[string(w[:16])]; !ok || !bytes.Equal(k, w[16:24]) {
			return false
		}
	}
	return true
}

// epochBody checks a removal's new-epoch fields: a removal by an admin who stays starts a new
// epoch for the remaining devices; any other removal carries no secret at all (§6.4).
func epochBody(b body, fresh bool, remaining []*device) bool {
	if fresh {
		return wrapsCover(b.wraps, remaining)
	}
	return bytes.Equal(b.commit, make([]byte, 32)) && len(b.wraps) == 0
}

func (s *state) advance(fresh bool) {
	if fresh {
		s.epoch++
		s.pending = false
	} else {
		s.pending = true
	}
}

// apply returns the new state, or the fatal reason code.
func apply(s0 *state, raw []byte) (*state, string) {
	r := &reader{b: raw}
	ver, suite, t := r.u8(), r.u16(), r.u8()
	cid, seq, prev := r.take(16), r.u64(), r.take(32)
	r.u64()
	author, epoch := r.take(16), r.u32()
	bodyBytes, sig := r.vec32(), r.take(64)
	if !r.ok() {
		return nil, "malformed"
	}
	if ver != 0 || suite != 1 {
		return nil, "bad_version"
	}
	if t < 1 || t > 9 {
		return nil, "unknown_entry_type"
	}
	b, ok := parseBody(t, bodyBytes)
	if !ok {
		return nil, "malformed"
	}
	zero16, zero32 := make([]byte, 16), make([]byte, 32)
	if s0.cid == nil {
		switch {
		case t != 1 || seq != 0:
			return nil, "bad_seq"
		case !bytes.Equal(prev, zero32):
			return nil, "bad_prev_hash"
		case !bytes.Equal(cid, zero16):
			return nil, "bad_circle_id"
		case epoch != 0:
			return nil, "bad_epoch"
		}
	} else {
		switch {
		case t == 1:
			return nil, "unexpected_genesis"
		case int64(seq) != s0.seq+1:
			return nil, "bad_seq"
		case !bytes.Equal(prev, s0.head):
			return nil, "bad_prev_hash"
		case !bytes.Equal(cid, s0.cid):
			return nil, "bad_circle_id"
		case epoch != s0.epoch:
			return nil, "bad_epoch"
		}
	}
	var authorKey, authorAcc []byte
	if t == 1 {
		if !bytes.Equal(author, b.c.deviceID()) {
			return nil, "bad_author"
		}
		authorKey, authorAcc = b.c.dsk, b.c.acc
	} else {
		d := s0.device(author)
		if d == nil {
			return nil, "author_not_active"
		}
		authorKey, authorAcc = d.dsk, d.acc
	}
	if !verify(authorKey, "log-entry", raw[:len(raw)-64], sig) {
		return nil, "bad_signature"
	}

	s := s0.clone()
	s.seq, s.head = int64(seq), H("log-hash", raw)
	s.hashes[string(s.head)] = true
	am := s.members[string(authorAcc)]
	newDevice := func() *device {
		return &device{id: b.c.deviceID(), acc: b.c.acc, dsk: b.c.dsk, kind: b.c.kind, b: b.bu}
	}

	switch t {
	case 1: // GENESIS
		if !certOK(b.c) {
			return nil, "bad_cert"
		}
		if !bundleOK(b.bu, b.c.dsk, b.c.acc) {
			return nil, "bad_bundle"
		}
		s.cid = H("circle-id", raw)[:16]
		s.members[string(b.c.acc)] = &member{acc: b.c.acc, ik: b.c.ik, admin: true,
			devs: map[string]*device{string(b.c.deviceID()): newDevice()}}
	case 2: // ADD_MEMBER
		switch {
		case !am.admin:
			return nil, "not_admin"
		case s.pending:
			return nil, "rekey_pending"
		case !certOK(b.c):
			return nil, "bad_cert"
		case !bundleOK(b.bu, b.c.dsk, b.c.acc):
			return nil, "bad_bundle"
		case s.members[string(b.c.acc)] != nil:
			return nil, "already_member"
		case s.device(b.c.deviceID()) != nil:
			return nil, "device_active"
		case !verify(b.c.ik, "join-consent", bytes.Join([][]byte{s.cid, b.invite, b.c.raw, b.bu.raw}, nil), b.consent):
			return nil, "bad_consent"
		}
		s.members[string(b.c.acc)] = &member{acc: b.c.acc, ik: b.c.ik, admin: b.admin,
			devs: map[string]*device{string(b.c.deviceID()): newDevice()}}
	case 3: // REMOVE_MEMBER
		tm := s.members[string(b.tgt)]
		switch {
		case tm == nil:
			return nil, "not_member"
		case !am.admin && !bytes.Equal(authorAcc, b.tgt):
			return nil, "not_admin"
		case tm.admin && s.admins() == 1 && len(s.members) > 1:
			return nil, "last_admin"
		}
		fresh := am.admin && !bytes.Equal(authorAcc, b.tgt)
		if !epochBody(b, fresh, s.devices(func(d *device) bool { return bytes.Equal(d.acc, b.tgt) })) {
			return nil, "bad_wraps"
		}
		delete(s.members, string(b.tgt))
		s.advance(fresh)
	case 4: // ADD_DEVICE
		switch {
		case !certOK(b.c):
			return nil, "bad_cert"
		case !bytes.Equal(b.c.acc, authorAcc) || !bytes.Equal(b.c.ik, am.ik):
			return nil, "wrong_account"
		case !bundleOK(b.bu, b.c.dsk, b.c.acc):
			return nil, "bad_bundle"
		case s.device(b.c.deviceID()) != nil:
			return nil, "device_active"
		}
		am.devs[string(b.c.deviceID())] = newDevice()
	case 5: // REMOVE_DEVICE
		td := s.device(b.tgt)
		switch {
		case td == nil:
			return nil, "unknown_device"
		case !bytes.Equal(td.acc, authorAcc) && !am.admin:
			return nil, "not_admin"
		case len(s.members[string(td.acc)].devs) == 1:
			return nil, "last_device"
		}
		fresh := am.admin && !bytes.Equal(author, b.tgt)
		if !epochBody(b, fresh, s.devices(func(d *device) bool { return bytes.Equal(d.id, b.tgt) })) {
			return nil, "bad_wraps"
		}
		delete(s.members[string(td.acc)].devs, string(b.tgt))
		s.advance(fresh)
	case 6: // UPDATE_KEY
		d := s.device(author)
		if !bundleOK(b.bu, d.dsk, d.acc) || bytes.Equal(b.bu.keyID(), d.b.keyID()) {
			return nil, "bad_bundle"
		}
		d.b = b.bu
	case 7: // POLICY: its content is opaque to servers
		if s.pending {
			return nil, "rekey_pending"
		}
	case 8: // REKEY
		if !am.admin {
			return nil, "not_admin"
		}
		if !wrapsCover(b.wraps, s.devices(nil)) {
			return nil, "bad_wraps"
		}
		s.advance(true)
	case 9: // SET_ADMIN
		tm := s.members[string(b.tgt)]
		switch {
		case !am.admin:
			return nil, "not_admin"
		case tm == nil:
			return nil, "not_member"
		case !b.admin && tm.admin && s.admins() == 1:
			return nil, "last_admin"
		}
		tm.admin = b.admin
	}
	return s, ""
}

func (s *state) publicJSON() any {
	var accs []string
	for k := range s.members {
		accs = append(accs, k)
	}
	sort.Strings(accs)
	members := []any{}
	for _, k := range accs {
		m := s.members[k]
		devs := []any{}
		for _, d := range s.devices(func(d *device) bool { return !bytes.Equal(d.acc, m.acc) }) {
			devs = append(devs, map[string]any{"device_id": hex.EncodeToString(d.id), "kind": d.kind,
				"key_id": hex.EncodeToString(d.b.keyID())})
		}
		members = append(members, map[string]any{"account_id": hex.EncodeToString(m.acc), "admin": m.admin, "devices": devs})
	}
	out := map[string]any{"seq": s.seq, "head": hex.EncodeToString(s.head), "epoch": s.epoch, "rekey_pending": s.pending, "members": members,
		"circle_id": nil}
	if s.cid != nil {
		out["circle_id"] = hex.EncodeToString(s.cid)
	}
	return normalize(out)
}

// ---- envelopes: the checks a server makes before storing one (§7.5) ----

const maxAgeMS = 31 * 86_400_000

func envelopeCheck(s *state, raw []byte, seen map[string]bool, now uint64) string {
	r := &reader{b: raw}
	ver, suite, kind := r.u8(), r.u16(), r.u8()
	cid, sender, seq := r.take(16), r.take(16), r.u64()
	sentAt := r.u64()
	ttl := r.u32()
	head := r.take(32)
	wraps := r.vec32()
	r.vec32()
	sig := r.take(64)
	switch {
	case !r.ok() || len(wraps)%104 != 0:
		return "malformed"
	case ver != 0 || suite != 1:
		return "bad_version"
	case kind != 1 && kind != 2:
		return "bad_kind"
	case !bytes.Equal(cid, s.cid):
		return "wrong_circle"
	case !s.hashes[string(head)]:
		return "unknown_log_head"
	}
	d := s.device(sender)
	if d == nil {
		return "sender_not_active"
	}
	if !verify(d.dsk, "envelope", raw[:len(raw)-64], sig) {
		return "bad_signature"
	}
	if sentAt+maxAgeMS < now {
		return "expired"
	}
	if sentAt > now+86_400_000 {
		return "bad_time"
	}
	key := fmt.Sprintf("%x/%d", sender, seq)
	if seen[key] {
		return "replay"
	}
	if len(wraps) == 0 {
		return "bad_wraps"
	}
	for i := 0; i < len(wraps); i += 104 {
		if (i > 0 && bytes.Compare(wraps[i-104:i-88], wraps[i:i+16]) >= 0) || s.device(wraps[i:i+16]) == nil {
			return "bad_wraps"
		}
	}
	if ttl < 60 || ttl > 2_592_000 {
		return "bad_ttl"
	}
	seen[key] = true
	return ""
}

// ---- vector runner ----

var counts = map[string]int{}
var failures []string

func check(group, name string, ok bool) {
	counts[group]++
	if !ok {
		failures = append(failures, group+": "+name)
	}
}

func normalize(v any) any {
	b, _ := json.Marshal(v)
	var out any
	json.Unmarshal(b, &out)
	return out
}

func obj(v any) map[string]any { return v.(map[string]any) }
func arr(v any) []any          { return v.([]any) }
func str(v any) string         { return v.(string) }
func hx(v any) []byte {
	b, err := hex.DecodeString(v.(string))
	if err != nil {
		panic(err)
	}
	return b
}

func publicOnly(st any) any {
	m := normalize(st).(map[string]any)
	delete(m, "name")
	delete(m, "flags")
	delete(m, "private_unknown_from")
	for _, mem := range arr(m["members"]) {
		for _, k := range []string{"role", "teen_until", "guardians", "rules", "pauses"} {
			delete(obj(mem), k)
		}
	}
	return m
}

func runEntry(s *state, e map[string]any, tag string) *state {
	raw := hx(e["raw"])
	ns, why := apply(s, raw)
	res := "accepted"
	if why != "" {
		res = "fatal"
	}
	wantWhy, _ := e["public_reason"].(string)
	check("log", tag+" public result", res == str(e["public_result"]) && why == wantWhy)
	check("log", tag+" hash", hex.EncodeToString(H("log-hash", raw)) == str(e["hash"]))
	if ns == nil {
		return s
	}
	if st, ok := e["state_after"]; ok {
		check("log", tag+" public state", reflect.DeepEqual(ns.publicJSON(), publicOnly(st)))
	}
	return ns
}

func main() {
	path := "../../spec/vectors/kinfold-v0.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		panic(err)
	}

	p := obj(v["primitives"])
	for _, t := range arr(p["H"]) {
		tt := obj(t)
		h := sha256.Sum256(append(vec16([]byte(str(tt["label"]))), hx(tt["data"])...))
		check("primitives", "H", hex.EncodeToString(h[:]) == str(tt["out"]))
	}
	for _, t := range arr(p["kdf"]) {
		tt := obj(t)
		out := kdfLabel(hx(tt["ikm"]), vec16([]byte(str(tt["label"]))), int(tt["length"].(float64)))
		check("primitives", "kdf", hex.EncodeToString(out) == str(tt["out"]))
	}
	for _, t := range arr(p["sign"]) {
		tt := obj(t)
		sk := ed25519.NewKeyFromSeed(hx(tt["seed"]))
		sig := ed25519.Sign(sk, append(vec16([]byte(str(tt["label"]))), hx(tt["data"])...))
		check("primitives", "sign", hex.EncodeToString(sig) == str(tt["sig"]))
	}
	b64 := base64.RawURLEncoding.Strict()
	for _, t := range arr(p["b64u"]) {
		tt := obj(t)
		dec, err := b64.DecodeString(str(tt["text"]))
		check("primitives", "b64u", err == nil && bytes.Equal(dec, hx(tt["bytes"])) && b64.EncodeToString(dec) == str(tt["text"]))
	}

	devices := map[string]map[string]any{}
	for name, pv := range obj(v["identities"]) {
		pp := obj(pv)
		ik := ed25519.NewKeyFromSeed(hx(pp["ik_seed"])).Public().(ed25519.PublicKey)
		check("identities", name, hex.EncodeToString(ik) == str(pp["ik_pub"]) &&
			hex.EncodeToString(H("account-id", ik)[:16]) == str(pp["account_id"]))
		for _, dv := range obj(pp["devices"]) {
			d := obj(dv)
			dsk := []byte(ed25519.NewKeyFromSeed(hx(d["dsk_seed"])).Public().(ed25519.PublicKey))
			c := readCert(&reader{b: hx(d["cert"])})
			check("identities", str(d["label"]), bytes.Equal(dsk, hx(d["dsk_pub"])) && certOK(c) && bytes.Equal(c.dsk, dsk) &&
				hex.EncodeToString(c.deviceID()) == str(d["device_id"]))
			for _, bv := range arr(d["bundles"]) {
				bu := readBundle(&reader{b: hx(bv)})
				check("identities", str(d["label"])+" bundle", bundleOK(bu, dsk, hx(pp["account_id"])))
			}
			devices[str(d["label"])] = d
		}
	}

	lg := obj(v["log"])
	entries := arr(lg["entries"])
	s := newState()
	states := []*state{}
	for _, e := range entries {
		ee := obj(e)
		s = runEntry(s, ee, fmt.Sprintf("seq %v", ee["seq"]))
		states = append(states, s)
	}
	check("log", "circle_id", hex.EncodeToString(s.cid) == str(lg["circle_id"]))
	for _, c := range arr(lg["cases"]) {
		cc := obj(c)
		cs := newState()
		if base := int(cc["base_seq"].(float64)); base >= 0 {
			cs = states[base]
		}
		for _, e := range arr(cc["entries"]) {
			cs = runEntry(cs, obj(e), str(cc["name"]))
		}
	}

	serverReasons := map[string]bool{"malformed": true, "bad_version": true, "bad_kind": true, "wrong_circle": true,
		"unknown_log_head": true, "sender_not_active": true, "bad_signature": true, "expired": true, "replay": true,
		"bad_wraps": true, "bad_ttl": true, "bad_time": true}
	now := uint64(obj(v["envelopes"])["receiver_now"].(float64))
	env := obj(v["envelopes"])
	for _, t := range arr(env["valid"]) {
		tt := obj(t)
		got := envelopeCheck(states[int(tt["log_seq"].(float64))], hx(tt["raw"]), map[string]bool{}, now)
		check("envelopes", str(tt["name"]), got == "")
	}
	for _, t := range arr(env["invalid"]) {
		tt := obj(t)
		want := str(tt["error"])
		if !serverReasons[want] {
			want = "" // only the recipient can detect it
		}
		got := envelopeCheck(states[int(tt["log_seq"].(float64))], hx(tt["raw"]), map[string]bool{}, now)
		check("envelopes", str(tt["name"]), got == want)
	}
	rp := obj(env["replay"])
	seen := map[string]bool{}
	var got []string
	for _, raw := range arr(rp["sequence"]) {
		r := envelopeCheck(states[int(rp["log_seq"].(float64))], hx(raw), seen, now)
		if r == "" {
			r = "ok"
		}
		got = append(got, r)
	}
	check("envelopes", "replay", fmt.Sprint(got) == fmt.Sprint(arr(rp["results"])))
	for _, t := range arr(env["server_rejects"]) {
		tt := obj(t)
		r := envelopeCheck(states[int(tt["log_seq"].(float64))], hx(tt["raw"]), map[string]bool{}, now)
		check("envelopes", str(tt["name"]), r == str(tt["server_error"]))
	}

	au := obj(v["auth"])
	info := hx(au["server_info"])
	r := &reader{b: info}
	r.u8()
	url := r.take(r.u16())
	key := r.take(32)
	r.u64()
	r.u64()
	tbs := r.p
	isig := r.take(64)
	check("auth", "server info", r.ok() && string(url) == str(au["server_url"]) && bytes.Equal(key, hx(au["server_key"])) &&
		verify(key, "server-info", info[:tbs], isig))
	ch, did := hx(au["challenge"]), hx(au["device_id"])
	exp := make([]byte, 8)
	binary.BigEndian.PutUint64(exp, uint64(au["expires_at"].(float64)))
	check("auth", "challenge", verify(key, "auth-challenge", bytes.Join([][]byte{ch, did, exp}, nil), hx(au["challenge_sig"])))
	check("auth", "device", verify(hx(devices[str(au["device"])]["dsk_pub"]), "auth", bytes.Join([][]byte{key, ch, did}, nil),
		hx(au["device_sig"])))

	groups := []string{}
	for g := range counts {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	total := 0
	for _, g := range groups {
		fmt.Printf("%-12s %4d checks\n", g, counts[g])
		total += counts[g]
	}
	if len(failures) > 0 {
		fmt.Println("FAILED:")
		for _, f := range failures {
			fmt.Println("  " + f)
		}
		os.Exit(1)
	}
	fmt.Printf("all %d public-mode checks passed\n", total)
}
