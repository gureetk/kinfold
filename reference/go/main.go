// SPDX-License-Identifier: Apache-2.0

// Command kinfold-vectors checks the parts of the Kinfold v0 test vectors that
// a server must enforce ("public mode", PROTOCOL.md §6.2 and §17), using only
// the Go standard library: primitives and strict Ed25519 verification,
// the RFC 9180 case, identities and identity chains, every member-log entry
// and case with its public outcome and public state, the envelope checks a
// server makes, watch grants, the pushes a server signs and seals, and server
// identity, moves and login. It is the seed of the server's protocol package.
//
// Usage: go run . ../../spec/vectors/kinfold-v0.json
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
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
	"strings"
)

// ---- primitives (§3) ----

const prefix = "kinfold/v0/"

func vec16(b []byte) []byte {
	out := make([]byte, 2, 2+len(b))
	binary.BigEndian.PutUint16(out, uint16(len(b)))
	return append(out, b...)
}

func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

func label(purpose string) []byte { return vec16([]byte(prefix + purpose)) }

func H(purpose string, data ...[]byte) []byte {
	h := sha256.New()
	h.Write(label(purpose))
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Little-endian constants of §3.3 and §3.5.
var (
	edL        = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010") // group order
	fieldP     = unhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f") // 2^255 - 19
	smallOrder = [][]byte{                                                                 // y of the eight small-order Ed25519 points
		unhex("0000000000000000000000000000000000000000000000000000000000000000"),
		unhex("0100000000000000000000000000000000000000000000000000000000000000"),
		unhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
		unhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
		unhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	}
	lowOrderX = [][]byte{ // X25519 public keys whose shared secret is always zero
		unhex("0000000000000000000000000000000000000000000000000000000000000000"),
		unhex("0100000000000000000000000000000000000000000000000000000000000000"),
		unhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
		unhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
		unhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	}
)

// leLess reports whether a < b, both read as 32-byte little-endian integers.
func leLess(a, b []byte) bool {
	for i := 31; i >= 0; i-- {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func oneOf(v []byte, set [][]byte) bool {
	for _, s := range set {
		if bytes.Equal(v, s) {
			return true
		}
	}
	return false
}

// edPointRejected is checks 2 and 3 of §3.3 on a public key or on R.
func edPointRejected(enc []byte) bool {
	if len(enc) != 32 {
		return true
	}
	y := append([]byte(nil), enc...)
	y[31] &= 0x7f
	return !leLess(y, fieldP) || oneOf(y, smallOrder)
}

// xKeyInvalid is the X25519 key check of §3.5.
func xKeyInvalid(pub []byte) bool {
	return len(pub) != 32 || pub[31]&0x80 != 0 || !leLess(pub, fieldP) || oneOf(pub, lowOrderX)
}

// verifyRaw is strict Ed25519 verification (§3.3): the byte checks first, then the
// standard library's single-signature, cofactorless check.
func verifyRaw(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	if !leLess(sig[32:], edL) || edPointRejected(pub) || edPointRejected(sig[:32]) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

func verify(pub []byte, purpose string, data, sig []byte) bool {
	return verifyRaw(pub, append(label(purpose), data...), sig)
}

func hmac256(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

func hkdfExpand(prk, info []byte, n int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < n; i++ {
		t = hmac256(prk, t, info, []byte{i})
		out = append(out, t...)
	}
	return out[:n]
}

func kdfLabel(ikm, info []byte, n int) []byte { // HKDF-SHA256 with a zero salt
	return hkdfExpand(hmac256(make([]byte, 32), ikm), info, n)
}

// padTo is PadTo of §7.4.
func padTo(p []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, p)
	out[len(p)] = 0x80
	return out
}

// ---- HPKE base-mode seal (RFC 9180), which a server needs to seal pushes (§14.2) ----

var (
	kemSuite  = []byte("KEM\x00\x20")
	hpkeSuite = []byte("HPKE\x00\x20\x00\x01\x00\x02")
)

func labeledExtract(salt, suite []byte, lbl string, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, 32)
	}
	return hmac256(salt, []byte("HPKE-v1"), suite, []byte(lbl), ikm)
}

func labeledExpand(prk, suite []byte, lbl string, info []byte, n int) []byte {
	full := bytes.Join([][]byte{{byte(n >> 8), byte(n)}, []byte("HPKE-v1"), suite, []byte(lbl), info}, nil)
	return hkdfExpand(prk, full, n)
}

// hpkeSetup returns enc, the AEAD key and the base nonce of a base-mode sender context.
// ikmE must be 32 fresh random bytes in production.
func hpkeSetup(pkR, info, ikmE []byte) (enc, key, nonce []byte, err error) {
	skE, err := ecdh.X25519().NewPrivateKey(labeledExpand(labeledExtract(nil, kemSuite, "dkp_prk", ikmE), kemSuite, "sk", nil, 32))
	if err != nil {
		return nil, nil, nil, err
	}
	peer, err := ecdh.X25519().NewPublicKey(pkR)
	if err != nil {
		return nil, nil, nil, err
	}
	dh, err := skE.ECDH(peer)
	if err != nil {
		return nil, nil, nil, err
	}
	enc = skE.PublicKey().Bytes()
	shared := labeledExpand(labeledExtract(nil, kemSuite, "eae_prk", dh), kemSuite, "shared_secret", append(append([]byte(nil), enc...), pkR...), 32)
	ctx := bytes.Join([][]byte{{0}, labeledExtract(nil, hpkeSuite, "psk_id_hash", nil), labeledExtract(nil, hpkeSuite, "info_hash", info)}, nil)
	secret := labeledExtract(shared, hpkeSuite, "secret", nil)
	return enc, labeledExpand(secret, hpkeSuite, "key", ctx, 32), labeledExpand(secret, hpkeSuite, "base_nonce", ctx, 12), nil
}

func gcmSeal(key, nonce, pt, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, pt, aad), nil
}

// hpkeSeal is the single-shot seal of §3.5: empty aad, the first message of the context.
func hpkeSeal(pkR, info, pt, ikmE []byte) (enc, ct []byte, err error) {
	enc, key, nonce, err := hpkeSetup(pkR, info, ikmE)
	if err != nil {
		return nil, nil, err
	}
	ct, err = gcmSeal(key, nonce, pt, nil)
	return enc, ct, err
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
func (r *reader) u8() int       { return int(r.take(1)[0]) }
func (r *reader) u16() int      { return int(binary.BigEndian.Uint16(r.take(2))) }
func (r *reader) u32() int      { return int(binary.BigEndian.Uint32(r.take(4))) }
func (r *reader) u64() uint64   { return binary.BigEndian.Uint64(r.take(8)) }
func (r *reader) vec16() []byte { return r.take(r.u16()) }
func (r *reader) vec32() []byte { return r.take(r.u32()) }
func (r *reader) ok() bool      { return !r.bad && r.p == len(r.b) }

// ---- certificates, identity chains and bundles (§4) ----

const (
	kindPhone, kindTablet, kindWeb, kindHomeAssistant, kindRecovery = 1, 2, 3, 4, 5
	linkLen, maxLinks                                               = 192, 8
)

func receiving(kind int) bool { return kind >= kindPhone && kind <= kindHomeAssistant }

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

// certWellFormed is §4.3. It says nothing about whether the account belongs to the key: see chainProves.
func certWellFormed(c cert) bool {
	return c.raw != nil && c.ver == 0 && c.suite == 1 && c.kind >= kindPhone && c.kind <= kindRecovery &&
		!edPointRejected(c.ik) && !edPointRejected(c.dsk) && verify(c.ik, "device-cert", c.raw[:60], c.sig)
}

func parseChain(b []byte) ([][]byte, bool) {
	if len(b)%linkLen != 0 || len(b) > linkLen*maxLinks {
		return nil, false
	}
	var links [][]byte
	for i := 0; i < len(b); i += linkLen {
		links = append(links, b[i:i+linkLen])
	}
	return links, true
}

// linkOK: both keys usable and both signatures verify for this account.
func linkOK(acc, link []byte) bool {
	oldK, newK := link[:32], link[32:64]
	tbs := bytes.Join([][]byte{acc, oldK, newK}, nil)
	return !edPointRejected(oldK) && !edPointRejected(newK) &&
		verify(oldK, "identity-rotate", tbs, link[64:128]) && verify(newK, "identity-rotate", tbs, link[128:192])
}

// chainProves reports whether the chain proves that c.ik is the current identity key of c.acc.
func chainProves(c cert, links [][]byte) bool {
	if len(links) == 0 {
		return bytes.Equal(c.acc, H("account-id", c.ik)[:16])
	}
	var key []byte
	for i, l := range links {
		if i == 0 {
			if !bytes.Equal(H("account-id", l[:32])[:16], c.acc) {
				return false
			}
		} else if !bytes.Equal(l[:32], key) {
			return false
		}
		if !linkOK(c.acc, l) {
			return false
		}
		key = l[32:64]
	}
	return bytes.Equal(key, c.ik)
}

type bundle struct {
	raw, acc, dev, dek, sig []byte
	ver, suite              int
	nb, na                  uint64
}

func readBundle(r *reader) bundle {
	start := r.p
	b := bundle{ver: r.u8(), suite: r.u16(), acc: r.take(16), dev: r.take(16), dek: r.take(32), nb: r.u64(), na: r.u64()}
	r.u8()  // proto_max: never affects validity
	r.u32() // features
	b.sig = r.take(64)
	if !r.bad {
		b.raw = r.b[start:r.p]
	}
	return b
}

func (b bundle) keyID() []byte { return H("key-id", b.dek)[:8] }

func bundleOK(b bundle, dsk, acc []byte) bool {
	return b.raw != nil && b.ver == 0 && b.suite == 1 && bytes.Equal(b.dev, H("device-id", dsk)[:16]) &&
		bytes.Equal(b.acc, acc) && !xKeyInvalid(b.dek) && b.nb < b.na && b.na-b.nb <= 35*86_400_000 &&
		verify(dsk, "key-bundle", b.raw[:88], b.sig)
}

// bundleCurrent: what a bundle must be at the created_at of the entry that carries it (§4.4).
// Its author chooses t, so the limits are differences, never sums that could wrap around
// (Appendix C); the same goes for every time below.
func bundleCurrent(b bundle, t uint64) bool { return (b.nb <= t || b.nb-t <= 600_000) && t < b.na }

// ---- public circle state (§6.1) ----

type device struct {
	id, acc, dsk []byte
	kind         int
	b            bundle // no bundle (raw == nil) for a recovery device
}

type member struct {
	acc, ik []byte // ik: the current identity key
	admin   bool
	devs    map[string]*device
}

type state struct {
	cid, head   []byte
	seq         int64
	epoch       int
	pending     bool // rekey_pending (§6.4)
	options     int
	members     map[string]*member
	hashes      map[string]int64 // entry hash -> seq
	usedInvites map[string]bool
	recvChanged int64 // last entry that changed the set of receiving devices (§7.5)
}

func newState() *state {
	return &state{head: make([]byte, 32), seq: -1, recvChanged: -1, members: map[string]*member{},
		hashes: map[string]int64{}, usedInvites: map[string]bool{}}
}

func (s *state) clone() *state {
	c := *s
	c.members, c.hashes, c.usedInvites = map[string]*member{}, map[string]int64{}, map[string]bool{}
	for k, v := range s.hashes {
		c.hashes[k] = v
	}
	for k := range s.usedInvites {
		c.usedInvites[k] = true
	}
	for k, m := range s.members {
		nm := &member{acc: m.acc, ik: m.ik, admin: m.admin, devs: map[string]*device{}}
		for dk, d := range m.devs {
			nd := *d
			nm.devs[dk] = &nd
		}
		c.members[k] = nm
	}
	return &c
}

func (s *state) device(id []byte) *device {
	for _, m := range s.members {
		if d, ok := m.devs[string(id)]; ok {
			return d
		}
	}
	return nil
}

// receivingDevices lists active devices of kind 1-4, in order, leaving out those skip selects.
func (s *state) receivingDevices(skip func(*device) bool) []*device {
	var out []*device
	for _, m := range s.members {
		for _, d := range m.devs {
			if receiving(d.kind) && (skip == nil || !skip(d)) {
				out = append(out, d)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].id, out[j].id) < 0 })
	return out
}

func (s *state) receivingSet() string {
	var ids []string
	for _, d := range s.receivingDevices(nil) {
		ids = append(ids, string(d.id))
	}
	return strings.Join(ids, "")
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

// ---- log entries in public mode (§5, §6.3 steps 1-9, §6.4) ----

const (
	maxEntry, detailsLen   = 65536, 540
	maxMembers, maxDevices = 32, 8
	optionsDefined         = 3 // bit 0: web devices; bit 1: Home Assistant devices
)

type body struct {
	c                                                  cert
	bu                                                 bundle
	chain                                              [][]byte
	commit, invite, terms, consent, tgt, link, details []byte
	admin                                              bool
	options                                            int
	wraps                                              [][]byte
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
	certChainBundle := func() {
		b.c = readCert(r)
		chain, ok := parseChain(r.vec16())
		if !ok {
			r.bad = true
		}
		b.chain, b.bu = chain, readBundle(r)
	}
	switch t {
	case 1:
		certChainBundle()
		b.commit, b.details = r.take(32), r.take(detailsLen)
	case 2:
		certChainBundle()
		b.invite, b.terms, b.consent = r.take(16), r.take(32), r.take(64)
		b.admin = flag()
		b.details = r.take(detailsLen)
	case 3, 5:
		b.tgt, b.commit = r.take(16), r.take(32)
		wraps()
	case 4:
		b.c, b.bu = readCert(r), readBundle(r)
	case 6:
		b.bu = readBundle(r)
	case 7:
		b.details = r.take(detailsLen)
	case 8:
		b.commit = r.take(32)
		wraps()
	case 9:
		b.tgt = r.take(16)
		b.admin = flag()
	case 10:
		b.c = readCert(r)
	case 11:
		b.options = r.u32()
	case 12:
		b.link = r.take(linkLen)
	}
	return b, r.ok()
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

func noEpoch(b body) bool { return bytes.Equal(b.commit, make([]byte, 32)) && len(b.wraps) == 0 }

// epochBody checks a removal's new-epoch fields: a removal by an admin who stays starts a new
// epoch for the remaining receiving devices; any other removal carries no secret at all (§6.4).
func epochBody(b body, fresh bool, remaining []*device) bool {
	if fresh {
		return wrapsCover(b.wraps, remaining)
	}
	return noEpoch(b)
}

func (s *state) advance(fresh bool) {
	if fresh {
		s.epoch++
		s.pending = false
	} else {
		s.pending = true
	}
}

// kindMayAuthor is the table in §6.3: what a device may write depends on its kind.
func kindMayAuthor(s *state, t int, b body, author []byte, kind int, authorAcc []byte) bool {
	switch kind {
	case kindPhone, kindTablet:
		return true
	case kindWeb, kindHomeAssistant:
		return t == 6 || (t == 5 && bytes.Equal(b.tgt, author))
	case kindRecovery:
		if t == 4 {
			return true
		}
		if t == 5 {
			d := s.device(b.tgt)
			return d != nil && bytes.Equal(d.acc, authorAcc)
		}
	}
	return false
}

// apply returns the new state, or the fatal reason code.
func apply(s0 *state, raw []byte) (*state, string) {
	if len(raw) > maxEntry {
		return nil, "too_large"
	}
	r := &reader{b: raw}
	ver, suite, t := r.u8(), r.u16(), r.u8()
	cid, seq, prev := r.take(16), r.u64(), r.take(32)
	createdAt := r.u64()
	author, epoch := r.take(16), r.u32()
	bodyBytes, sig := r.vec32(), r.take(64)
	if !r.ok() {
		return nil, "malformed"
	}
	if ver != 0 || suite != 1 {
		return nil, "bad_version"
	}
	if t < 1 || t > 12 {
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
	var authorKind int
	if t == 1 {
		if !bytes.Equal(author, b.c.deviceID()) {
			return nil, "bad_author"
		}
		authorKey, authorAcc, authorKind = b.c.dsk, b.c.acc, b.c.kind
	} else {
		d := s0.device(author)
		if d == nil {
			return nil, "author_not_active"
		}
		authorKey, authorAcc, authorKind = d.dsk, d.acc, d.kind
	}
	if !verify(authorKey, "log-entry", raw[:len(raw)-64], sig) {
		return nil, "bad_signature"
	}
	if !kindMayAuthor(s0, t, b, author, authorKind, authorAcc) {
		return nil, "kind_not_allowed"
	}

	s := s0.clone()
	s.seq, s.head = int64(seq), H("log-hash", raw)
	s.hashes[string(s.head)] = s.seq
	am := s.members[string(authorAcc)]
	newDevice := func() *device {
		return &device{id: b.c.deviceID(), acc: b.c.acc, dsk: b.c.dsk, kind: b.c.kind, b: b.bu}
	}
	ownCert := func() string { // the first two checks of ADD_DEVICE and ADD_RECOVERY
		switch {
		case !certWellFormed(b.c):
			return "bad_cert"
		case !bytes.Equal(b.c.acc, authorAcc) || !bytes.Equal(b.c.ik, am.ik):
			return "wrong_account"
		}
		return ""
	}

	switch t {
	case 1: // GENESIS
		if !certWellFormed(b.c) || !chainProves(b.c, b.chain) {
			return nil, "bad_cert"
		}
		if !bundleOK(b.bu, b.c.dsk, b.c.acc) || !bundleCurrent(b.bu, createdAt) {
			return nil, "bad_bundle"
		}
		s.cid = H("circle-id", raw)[:16]
		s.members[string(b.c.acc)] = &member{acc: b.c.acc, ik: b.c.ik, admin: true,
			devs: map[string]*device{string(b.c.deviceID()): newDevice()}}
	case 2: // ADD_MEMBER
		keyTaken := false
		for _, m := range s.members {
			keyTaken = keyTaken || bytes.Equal(m.ik, b.c.ik)
		}
		switch {
		case !am.admin:
			return nil, "not_admin"
		case s.pending:
			return nil, "rekey_pending"
		case len(s.members) >= maxMembers:
			return nil, "too_many_members"
		case !certWellFormed(b.c) || !chainProves(b.c, b.chain):
			return nil, "bad_cert"
		case b.c.kind != kindPhone && b.c.kind != kindTablet:
			return nil, "kind_not_allowed"
		case !bundleOK(b.bu, b.c.dsk, b.c.acc) || !bundleCurrent(b.bu, createdAt):
			return nil, "bad_bundle"
		case s.members[string(b.c.acc)] != nil || keyTaken:
			return nil, "already_member"
		case s.device(b.c.deviceID()) != nil:
			return nil, "device_active"
		case s.usedInvites[string(b.invite)]:
			return nil, "invite_reused"
		case !verify(b.c.ik, "join-consent", bytes.Join([][]byte{s.cid, b.invite, b.c.raw, b.bu.raw, b.terms}, nil), b.consent):
			return nil, "bad_consent"
		}
		s.members[string(b.c.acc)] = &member{acc: b.c.acc, ik: b.c.ik, admin: b.admin,
			devs: map[string]*device{string(b.c.deviceID()): newDevice()}}
		s.usedInvites[string(b.invite)] = true
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
		if !epochBody(b, fresh, s.receivingDevices(func(d *device) bool { return bytes.Equal(d.acc, b.tgt) })) {
			return nil, "bad_wraps"
		}
		delete(s.members, string(b.tgt))
		s.advance(fresh)
	case 4: // ADD_DEVICE
		if why := ownCert(); why != "" {
			return nil, why
		}
		switch {
		case !receiving(b.c.kind) || (b.c.kind == kindWeb && s.options&1 == 0) || (b.c.kind == kindHomeAssistant && s.options&2 == 0):
			return nil, "kind_not_allowed"
		case len(am.devs) >= maxDevices:
			return nil, "too_many_devices"
		case !bundleOK(b.bu, b.c.dsk, b.c.acc) || !bundleCurrent(b.bu, createdAt):
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
		if td.kind == kindRecovery { // it never held an epoch secret, so nothing else changes
			if !noEpoch(b) {
				return nil, "bad_wraps"
			}
			delete(s.members[string(td.acc)].devs, string(b.tgt))
			break
		}
		fresh := am.admin && !bytes.Equal(author, b.tgt)
		if !epochBody(b, fresh, s.receivingDevices(func(d *device) bool { return bytes.Equal(d.id, b.tgt) })) {
			return nil, "bad_wraps"
		}
		delete(s.members[string(td.acc)].devs, string(b.tgt))
		s.advance(fresh)
	case 6: // UPDATE_KEY
		d := s.device(author)
		if !bundleOK(b.bu, d.dsk, d.acc) || !bundleCurrent(b.bu, createdAt) || bytes.Equal(b.bu.keyID(), d.b.keyID()) {
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
		if !wrapsCover(b.wraps, s.receivingDevices(nil)) {
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
	case 10: // ADD_RECOVERY
		if why := ownCert(); why != "" {
			return nil, why
		}
		hasRecovery := false
		for _, d := range am.devs {
			hasRecovery = hasRecovery || d.kind == kindRecovery
		}
		switch {
		case b.c.kind != kindRecovery:
			return nil, "kind_not_allowed"
		case hasRecovery || len(am.devs) >= maxDevices:
			return nil, "too_many_devices"
		case s.device(b.c.deviceID()) != nil:
			return nil, "device_active"
		}
		am.devs[string(b.c.deviceID())] = &device{id: b.c.deviceID(), acc: b.c.acc, dsk: b.c.dsk, kind: b.c.kind}
	case 11: // SET_OPTIONS
		switch {
		case !am.admin:
			return nil, "not_admin"
		case b.options&^optionsDefined != 0:
			return nil, "bad_options"
		}
		s.options = b.options
	case 12: // ROTATE_IDENTITY
		oldK, newK := b.link[:32], b.link[32:64]
		taken := false
		for _, m := range s.members {
			taken = taken || bytes.Equal(m.ik, newK)
		}
		if !bytes.Equal(oldK, am.ik) || edPointRejected(newK) || taken || !linkOK(authorAcc, b.link) {
			return nil, "bad_rotation"
		}
		am.ik = append([]byte(nil), newK...)
	}
	if t == 1 || s.receivingSet() != s0.receivingSet() {
		s.recvChanged = s.seq
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
		var ds []*device
		for _, d := range m.devs {
			ds = append(ds, d)
		}
		sort.Slice(ds, func(i, j int) bool { return bytes.Compare(ds[i].id, ds[j].id) < 0 })
		devs := []any{}
		for _, d := range ds {
			var kid any
			if d.b.raw != nil {
				kid = hex.EncodeToString(d.b.keyID())
			}
			devs = append(devs, map[string]any{"device_id": hex.EncodeToString(d.id), "kind": d.kind, "key_id": kid})
		}
		members = append(members, map[string]any{"account_id": hex.EncodeToString(m.acc), "ik_pub": hex.EncodeToString(m.ik),
			"admin": m.admin, "devices": devs})
	}
	used := []string{}
	for k := range s.usedInvites {
		used = append(used, hex.EncodeToString([]byte(k)))
	}
	sort.Strings(used)
	out := map[string]any{"seq": s.seq, "head": hex.EncodeToString(s.head), "epoch": s.epoch, "rekey_pending": s.pending,
		"options": s.options, "used_invites": used, "members": members, "circle_id": nil}
	if s.cid != nil {
		out["circle_id"] = hex.EncodeToString(s.cid)
	}
	return normalize(out)
}

// ---- envelopes: the checks a server makes before storing one (§7.5) ----

const maxAgeMS = 31 * 86_400_000

// envelopeCheck returns "stored", "duplicate" (the same bytes again: posting is idempotent)
// or a reason code. seen maps sender/seq to the SHA-256 of the envelope stored under it.
func envelopeCheck(s *state, raw []byte, seen map[string][32]byte, now uint64) string {
	r := &reader{b: raw}
	ver, suite, kind := r.u8(), r.u16(), r.u8()
	cid, sender, seq := r.take(16), r.take(16), r.u64()
	sentAt := r.u64()
	ttl := r.u32()
	head := r.take(32)
	wraps := r.vec32()
	r.vec32()
	sig := r.take(64)
	switch { // §7.6 steps 1 to 4
	case !r.ok() || len(wraps)%104 != 0:
		return "malformed"
	case ver != 0 || suite != 1:
		return "bad_version"
	case kind != 1 && kind != 2:
		return "bad_kind"
	case !bytes.Equal(cid, s.cid):
		return "wrong_circle"
	}
	d := s.device(sender) // step 5
	if d == nil || !receiving(d.kind) {
		return "sender_not_active"
	}
	if !verify(d.dsk, "envelope", raw[:len(raw)-64], sig) { // step 6
		return "bad_signature"
	}
	headSeq, known := s.hashes[string(head)] // step 7
	if !known {
		return "unknown_log_head"
	}
	if now > sentAt && now-sentAt > maxAgeMS { // step 8
		return "expired"
	}
	if sentAt > now && sentAt-now > 86_400_000 {
		return "bad_time"
	}
	key, digest := fmt.Sprintf("%x/%d", sender, seq), sha256.Sum256(raw)
	if prev, ok := seen[key]; ok { // step 9
		if prev == digest {
			return "duplicate"
		}
		return "replay"
	}
	n := len(wraps) / 104 // step 10
	if n < 1 || n > 255 {
		return "bad_wraps"
	}
	named := map[string]bool{}
	for i := 0; i < len(wraps); i += 104 {
		if i > 0 && bytes.Compare(wraps[i-104:i-88], wraps[i:i+16]) >= 0 {
			return "bad_wraps"
		}
		named[string(wraps[i:i+16])] = true
	}
	// what only a server checks (§7.5)
	for id := range named {
		if rd := s.device([]byte(id)); rd == nil || !receiving(rd.kind) {
			return "bad_wraps"
		}
	}
	if ttl < 60 || ttl > 2_592_000 {
		return "bad_ttl"
	}
	if kind == 1 {
		if headSeq < s.recvChanged {
			return "stale_head"
		}
		others := s.receivingDevices(func(x *device) bool { return bytes.Equal(x.id, sender) })
		if len(others) != len(named) {
			return "bad_wraps" // a circle envelope names every receiving device but the sender
		}
		for _, o := range others {
			if !named[string(o.id)] {
				return "bad_wraps"
			}
		}
	}
	seen[key] = digest
	return "stored"
}

// ---- watch grants, pushes and the relay signature (§14) ----

// watchGrantOK reports whether a server may register the watch at time now.
func watchGrantOK(s *state, raw []byte, now uint64) bool {
	r := &reader{b: raw}
	ver, cid, watched, watcher := r.u8(), r.take(16), r.take(16), r.take(16)
	afterMin, notAfter, sig := r.u16(), r.u64(), r.take(64)
	if !r.ok() {
		return false
	}
	d := s.device(watched)
	return ver == 0 && bytes.Equal(cid, s.cid) && d != nil && (d.kind == kindPhone || d.kind == kindTablet) &&
		s.members[string(watcher)] != nil && afterMin >= 15 && afterMin <= 1440 &&
		now < notAfter && notAfter-now <= 35*86_400_000 && verify(d.dsk, "watch-grant", raw[:59], sig)
}

// makePush builds the Push structure of §14.2; seed is the server's signing key.
func makePush(seed, deviceID []byte, ptype int, sentAt uint64, bodyBytes []byte) []byte {
	tbs := bytes.Join([][]byte{{0, byte(ptype)}, u64(sentAt), vec16(bodyBytes)}, nil)
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), bytes.Join([][]byte{label("push-sig"), deviceID, tbs}, nil))
	return append(tbs, sig...)
}

// sealPush returns the 2,616 bytes a server hands to a push service.
func sealPush(push, deviceID, dekPub, ikmE []byte) ([]byte, error) {
	kid := H("key-id", dekPub)[:8]
	enc, ct, err := hpkeSeal(dekPub, H("push", deviceID, kid), padTo(push, 2560), ikmE)
	if err != nil {
		return nil, err
	}
	return bytes.Join([][]byte{kid, enc, ct}, nil), nil
}

func relayTBS(capability, sealed []byte, sentAt uint64, delivery int) []byte {
	return bytes.Join([][]byte{capability, sealed, u64(sentAt), {byte(delivery)}}, nil)
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
func num(v any) uint64         { return uint64(v.(float64)) }
func hx(v any) []byte          { return unhex(v.(string)) }

func publicOnly(st any) any {
	m := normalize(st).(map[string]any)
	for _, k := range []string{"name", "flags", "private_unknown_from", "state_hash"} {
		delete(m, k)
	}
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

func pubOf(seed []byte) []byte {
	return []byte(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
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

	hp := obj(v["hpke_rfc9180"])
	hpEnc, hpKey, hpNonce, err := hpkeSetup(hx(hp["pkRm"]), hx(hp["info"]), hx(hp["ikmE"]))
	check("hpke", "RFC 9180 sender context", err == nil && bytes.Equal(hpEnc, hx(hp["enc"])) &&
		bytes.Equal(hpKey, hx(hp["key"])) && bytes.Equal(hpNonce, hx(hp["base_nonce"])))
	if err == nil {
		e0 := obj(arr(hp["encryptions"])[0])
		ct, err := gcmSeal(hpKey, hpNonce, hx(e0["pt"]), hx(e0["aad"]))
		check("hpke", "RFC 9180 first encryption", err == nil && bytes.Equal(ct, hx(e0["ct"])))
	}

	p := obj(v["primitives"])
	for _, t := range arr(p["H"]) {
		tt := obj(t)
		h := sha256.Sum256(append(vec16([]byte(str(tt["label"]))), hx(tt["data"])...))
		check("primitives", "H", hex.EncodeToString(h[:]) == str(tt["out"]))
	}
	for _, t := range arr(p["kdf"]) {
		tt := obj(t)
		out := kdfLabel(hx(tt["ikm"]), vec16([]byte(str(tt["label"]))), int(num(tt["length"])))
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
	code := func(prefix, text string) []byte { // the bytes inside a scanned code (§2)
		dec, err := b64.DecodeString(strings.TrimPrefix(text, prefix))
		if err != nil || !strings.HasPrefix(text, prefix) {
			return nil
		}
		return dec
	}

	// strict Ed25519 and the X25519 key check (§3.3, §3.5)
	ed := obj(v["ed25519"])
	for _, t := range arr(ed["signatures"]) {
		tt := obj(t)
		check("ed25519", str(tt["name"]), verifyRaw(hx(tt["pub"]), hx(tt["msg"]), hx(tt["sig"])) == tt["valid"].(bool))
	}
	for _, t := range arr(ed["keys"]) {
		tt := obj(t)
		check("ed25519", "key "+str(tt["pub"])[:16], edPointRejected(hx(tt["pub"])) == tt["invalid"].(bool))
	}
	for _, t := range arr(obj(v["x25519"])["keys"]) {
		tt := obj(t)
		check("x25519", "key "+str(tt["pub"])[:16], xKeyInvalid(hx(tt["pub"])) == tt["invalid"].(bool))
	}

	devices := map[string]map[string]any{}
	dekPub := map[string][]byte{}
	for name, pv := range obj(v["identities"]) {
		pp := obj(pv)
		ik := pubOf(hx(pp["ik_seed"]))
		acc := H("account-id", pubOf(hx(arr(pp["ik_seeds"])[0])))[:16]
		chain, chainOK := parseChain(hx(pp["chain"]))
		check("identities", name, hex.EncodeToString(ik) == str(pp["ik_pub"]) && hex.EncodeToString(acc) == str(pp["account_id"]) &&
			chainOK && len(chain) == len(arr(pp["ik_seeds"]))-1)
		for _, dv := range obj(pp["devices"]) {
			d := obj(dv)
			dsk := pubOf(hx(d["dsk_seed"]))
			c := readCert(&reader{b: hx(d["cert"])})
			check("identities", str(d["label"]), bytes.Equal(dsk, hx(d["dsk_pub"])) && certWellFormed(c) && bytes.Equal(c.dsk, dsk) &&
				hex.EncodeToString(c.deviceID()) == str(d["device_id"]) && bytes.Equal(c.acc, acc) && chainProves(c, chain))
			for _, bv := range arr(d["bundles"]) {
				bu := readBundle(&reader{b: hx(bv)})
				check("identities", str(d["label"])+" bundle", bundleOK(bu, dsk, acc))
			}
			for _, kv := range arr(d["deks"]) {
				dekPub[str(obj(kv)["key_id"])] = hx(obj(kv)["pub"])
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

	env := obj(v["envelopes"])
	now := num(env["receiver_now"])
	at := func(t map[string]any) *state { return states[int(num(t["log_seq"]))] }
	server := func(t map[string]any, raw []byte) string {
		if got := envelopeCheck(at(t), raw, map[string][32]byte{}, now); got != "stored" {
			return got
		}
		return ""
	}
	for _, t := range arr(env["valid"]) {
		tt := obj(t)
		check("envelopes", str(tt["name"]), server(tt, hx(tt["raw"])) == "")
	}
	for _, name := range []string{"invalid", "server_rejects"} {
		for _, t := range arr(env[name]) {
			tt := obj(t)
			want, _ := tt["server_error"].(string) // null: only a recipient can detect the fault
			check("envelopes", str(tt["name"]), server(tt, hx(tt["raw"])) == want)
		}
	}
	rp := obj(env["server_repost"])
	seen := map[string][32]byte{}
	var got []string
	for _, raw := range arr(rp["sequence"]) {
		got = append(got, envelopeCheck(at(rp), hx(raw), seen, now))
	}
	check("envelopes", "repost", fmt.Sprint(got) == fmt.Sprint(arr(rp["results"])))

	for _, t := range arr(obj(v["padding"])["pad_to"]) {
		tt := obj(t)
		sum := sha256.Sum256(padTo(bytes.Repeat(hx(tt["payload_byte"]), int(num(tt["payload_length"]))), int(num(tt["to"]))))
		check("padding", fmt.Sprintf("pad_to %v/%v", tt["payload_length"], tt["to"]), hex.EncodeToString(sum[:]) == str(tt["padded_sha256"]))
	}

	// server identity, setup codes, login and moves (§13)
	au := obj(v["auth"])
	info := hx(au["server_info"])
	r := &reader{b: info}
	r.u8()
	url := r.vec16()
	key := r.take(32)
	r.u64()
	r.u64()
	tbs := r.p
	isig := r.take(64)
	check("auth", "server info", r.ok() && string(url) == str(au["server_url"]) && bytes.Equal(key, hx(au["server_key"])) &&
		verify(key, "server-info", info[:tbs], isig))
	ch, did := hx(au["challenge"]), hx(au["device_id"])
	check("auth", "challenge", verify(key, "auth-challenge", bytes.Join([][]byte{ch, did, u64(num(au["expires_at"]))}, nil), hx(au["challenge_sig"])))
	check("auth", "device", verify(hx(devices[str(au["device"])]["dsk_pub"]), "auth", bytes.Join([][]byte{key, ch, did}, nil),
		hx(au["device_sig"])))
	su := obj(v["setup"])
	r = &reader{b: code("KFS0", str(su["code"]))}
	sver, surl, skey, stok, sexp := r.u8(), r.vec16(), r.take(32), r.vec16(), r.u64()
	check("setup", "code", r.ok() && sver == 0 && string(surl) == str(su["server_url"]) && bytes.Equal(skey, hx(su["server_key"])) &&
		bytes.Equal(stok, hx(su["reg_token"])) && sexp == num(su["expires_at"]))
	for _, t := range arr(v["server_moves"]) {
		tt := obj(t)
		raw := hx(tt["move"])
		r := &reader{b: raw}
		mver, oldURL, oldKey, newURL, newKey := r.u8(), r.vec16(), r.take(32), r.vec16(), r.take(32)
		r.u64()
		mtbs := r.p
		msig := r.take(64)
		ok := r.ok() && mver == 0 && verify(oldKey, "server-move", raw[:mtbs], msig)
		check("moves", str(tt["name"]), ok == tt["valid"].(bool) && string(oldURL) == str(tt["old_url"]) && bytes.Equal(oldKey, hx(tt["old_key"])) &&
			string(newURL) == str(tt["new_url"]) && bytes.Equal(newKey, hx(tt["new_key"])))
	}

	// watch grants, pushes and the relay signature (§14)
	wg := obj(v["watch_grants"])
	for _, t := range arr(wg["grants"]) {
		tt := obj(t)
		check("watch", str(tt["name"]), watchGrantOK(at(wg), hx(tt["grant"]), num(wg["now"])) == tt["valid"].(bool))
	}
	pu := obj(v["push"])
	seed := hx(au["server_seed"])
	for _, t := range arr(pu["valid"]) {
		tt := obj(t)
		push := makePush(seed, hx(tt["device_id"]), int(num(tt["type"])), num(tt["sent_at"]), hx(tt["body"]))
		sealed, err := sealPush(push, hx(tt["device_id"]), dekPub[str(tt["sealed"])[:16]], hx(tt["ikm"]))
		check("push", str(tt["name"]), err == nil && bytes.Equal(push, hx(tt["push"])) && bytes.Equal(sealed, hx(tt["sealed"])) &&
			len(sealed) == 2616)
	}
	rl := obj(pu["relay"])
	for delivery := 1; delivery <= 3; delivery++ {
		ok := verify(key, "relay-push", relayTBS(hx(rl["capability"]), hx(rl["sealed"]), num(rl["sent_at"]), delivery), hx(rl["sig"]))
		check("push", fmt.Sprintf("relay signature, delivery %d", delivery), ok == (delivery == int(num(rl["delivery"]))))
	}

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
