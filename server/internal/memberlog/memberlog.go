// SPDX-License-Identifier: AGPL-3.0-or-later

// Package memberlog runs the public rules of a circle's member log (PROTOCOL.md §5, §6):
// steps 1 to 9 of §6.3 with the public effects of step 11, which is "public mode", and the
// server's clock check of §6.7. A server can't read the encrypted details, so it never
// rejects or flags an entry: an entry is accepted or it is fatal.
package memberlog

import (
	"bytes"
	"encoding/hex"
	"sort"

	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/kcrypto"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// Entry types (§16.1).
const (
	Genesis        = 0x01
	AddMember      = 0x02
	RemoveMember   = 0x03
	AddDevice      = 0x04
	RemoveDevice   = 0x05
	UpdateKey      = 0x06
	Policy         = 0x07
	Rekey          = 0x08
	SetAdmin       = 0x09
	AddRecovery    = 0x0A
	SetOptions     = 0x0B
	RotateIdentity = 0x0C
)

// Limits (§16.6) and sizes (§5).
const (
	MaxEntry       = 65_536
	HeaderLen      = 88
	DetailsLen     = 540
	WrapLen        = 104
	MaxMembers     = 32
	MaxDevices     = 8
	OptionsDefined = 0x3 // bit 0: web devices; bit 1: Home Assistant devices (§16.7)

	// ClockSkewMS is how far created_at may be from the server's clock (§6.7).
	ClockSkewMS = 600_000
)

// Fatal is an entry that breaks the log (§6.2). A server refuses to append it.
type Fatal struct {
	Reason string // a reason code of §16.5
}

func (f *Fatal) Error() string { return "fatal log entry: " + f.Reason }

func fatal(reason string) error { return &Fatal{Reason: reason} }

// Entry is a log entry whose framing parsed (§5.2).
type Entry struct {
	Raw       []byte
	Version   uint8
	Suite     uint16
	Type      uint8
	CircleID  []byte
	Seq       uint64
	PrevHash  []byte
	CreatedAt uint64
	Author    []byte
	Epoch     uint32
	Body      []byte
	Sig       []byte
}

// Hash is the entry hash, H("log-hash", the entire entry).
func Hash(raw []byte) []byte { return kcrypto.H("log-hash", raw) }

// ParseEntry is step 1 of §6.3: the size limit, then the framing.
func ParseEntry(raw []byte) (*Entry, error) {
	if len(raw) > MaxEntry {
		return nil, fatal("too_large")
	}
	r := wire.NewReader(raw)
	e := &Entry{Raw: raw, Version: r.U8(), Suite: r.U16(), Type: r.U8(), CircleID: r.Take(16), Seq: r.U64(),
		PrevHash: r.Take(32), CreatedAt: r.U64(), Author: r.Take(16), Epoch: r.U32()}
	e.Body, e.Sig = r.Vec32(), r.Take(64)
	if !r.Done() {
		return nil, fatal("malformed")
	}
	return e, nil
}

// body is the parsed body of any entry type (§5.3).
type body struct {
	cert    identity.Cert
	bundle  identity.Bundle
	chain   [][]byte
	commit  []byte // epoch_commit, or terms_commit in ADD_MEMBER
	invite  []byte
	consent []byte
	target  []byte // account_id or device_id
	link    []byte
	admin   bool
	options uint32
	wraps   [][]byte
	terms   []byte
	details []byte
}

func parseBody(t uint8, raw []byte) (body, bool) {
	r := wire.NewReader(raw)
	var b body
	readWraps := func() {
		w := r.Vec32()
		if len(w)%WrapLen != 0 {
			r.Fail()
			return
		}
		for i := 0; i < len(w); i += WrapLen {
			b.wraps = append(b.wraps, w[i:i+WrapLen])
		}
	}
	certChainBundle := func() {
		b.cert = identity.ReadCert(r)
		chain, ok := identity.ParseChain(r.Vec16())
		if !ok {
			r.Fail()
		}
		b.chain, b.bundle = chain, identity.ReadBundle(r)
	}
	switch t {
	case Genesis:
		certChainBundle()
		b.commit, b.details = r.Take(32), r.Take(DetailsLen)
	case AddMember:
		certChainBundle()
		b.invite, b.terms, b.consent = r.Take(16), r.Take(32), r.Take(64)
		b.admin = r.Flag()
		b.details = r.Take(DetailsLen)
	case RemoveMember, RemoveDevice:
		b.target, b.commit = r.Take(16), r.Take(32)
		readWraps()
	case AddDevice:
		b.cert, b.bundle = identity.ReadCert(r), identity.ReadBundle(r)
	case UpdateKey:
		b.bundle = identity.ReadBundle(r)
	case Policy:
		b.details = r.Take(DetailsLen)
	case Rekey:
		b.commit = r.Take(32)
		readWraps()
	case SetAdmin:
		b.target = r.Take(16)
		b.admin = r.Flag()
	case AddRecovery:
		b.cert = identity.ReadCert(r)
	case SetOptions:
		b.options = r.U32()
	case RotateIdentity:
		b.link = r.Take(identity.LinkLen)
	default:
		return b, false
	}
	return b, r.Done()
}

// ---- public state (§6.1) ----

// Device is an active device of a member.
type Device struct {
	ID      []byte
	Account []byte
	DSK     []byte
	Kind    uint8
	Bundle  identity.Bundle // the current key bundle; Raw is nil for a recovery device
}

// Member is a current member: account, current identity key, admin flag and devices.
type Member struct {
	Account []byte
	IK      []byte
	Admin   bool
	Devices map[string]*Device // by device ID
}

// State is a circle's public state, which is everything a server keeps (§6.1).
type State struct {
	CircleID     []byte // nil before GENESIS
	Seq          int64  // -1 before GENESIS
	Head         []byte // hash of the last entry
	Epoch        uint32
	RekeyPending bool
	Options      uint32
	Members      map[string]*Member // by account ID
	UsedInvites  map[string]bool    // invite IDs already spent
	// RecvChanged is the seq of the last entry that changed the set of receiving devices,
	// which is what a circle envelope's log_head must not be older than (§7.5).
	RecvChanged int64
}

// New returns the state of an empty log.
func New() *State {
	return &State{Seq: -1, Head: make([]byte, 32), RecvChanged: -1,
		Members: map[string]*Member{}, UsedInvites: map[string]bool{}}
}

// Clone returns a deep copy.
func (s *State) Clone() *State {
	c := *s
	c.Members = make(map[string]*Member, len(s.Members))
	for k, m := range s.Members {
		nm := *m
		nm.Devices = make(map[string]*Device, len(m.Devices))
		for dk, d := range m.Devices {
			nd := *d
			nm.Devices[dk] = &nd
		}
		c.Members[k] = &nm
	}
	c.UsedInvites = make(map[string]bool, len(s.UsedInvites))
	for k := range s.UsedInvites {
		c.UsedInvites[k] = true
	}
	return &c
}

// Device returns the active device with this ID, or nil.
func (s *State) Device(id []byte) *Device {
	for _, m := range s.Members {
		if d, ok := m.Devices[string(id)]; ok {
			return d
		}
	}
	return nil
}

// Member returns the current member with this account ID, or nil.
func (s *State) Member(account []byte) *Member { return s.Members[string(account)] }

// ReceivingDevices lists the active devices of kind 1 to 4 in ascending order of ID,
// leaving out those skip selects.
func (s *State) ReceivingDevices(skip func(*Device) bool) []*Device {
	var out []*Device
	for _, m := range s.Members {
		for _, d := range m.Devices {
			if identity.Receiving(d.Kind) && (skip == nil || !skip(d)) {
				out = append(out, d)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].ID, out[j].ID) < 0 })
	return out
}

func (s *State) receivingSet() string {
	var b []byte
	for _, d := range s.ReceivingDevices(nil) {
		b = append(b, d.ID...)
	}
	return string(b)
}

// Admins counts the current admins.
func (s *State) Admins() int {
	n := 0
	for _, m := range s.Members {
		if m.Admin {
			n++
		}
	}
	return n
}

// ---- validation (§6.3, §6.4) ----

func wrapsCover(ws [][]byte, devs []*Device) bool {
	if len(ws) != len(devs) {
		return false
	}
	want := make(map[string][]byte, len(devs))
	for _, d := range devs {
		want[string(d.ID)] = d.Bundle.KeyID()
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

// epochBody checks a removal's epoch fields: a removal by an admin who stays starts an
// epoch for the remaining receiving devices; any other removal carries no secret (§6.4).
func epochBody(b body, fresh bool, remaining []*Device) bool {
	if fresh {
		return wrapsCover(b.wraps, remaining)
	}
	return noEpoch(b)
}

func (s *State) advance(fresh bool) {
	if fresh {
		s.Epoch++
		s.RekeyPending = false
	} else {
		s.RekeyPending = true
	}
}

// kindMayAuthor is the table of §6.3: what a device may write depends on its kind.
func kindMayAuthor(s *State, t uint8, b body, author []byte, kind uint8, authorAcc []byte) bool {
	switch kind {
	case identity.Phone, identity.Tablet:
		return true
	case identity.Web, identity.HomeAssistant:
		return t == UpdateKey || (t == RemoveDevice && bytes.Equal(b.target, author))
	case identity.Recovery:
		if t == AddDevice {
			return true
		}
		if t == RemoveDevice {
			d := s.Device(b.target)
			return d != nil && bytes.Equal(d.Account, authorAcc)
		}
	}
	return false
}

// Apply runs §6.3 steps 1 to 9 for raw against s and returns the entry and the state after
// it, with the public effects of step 11 applied. It never changes s. A failure is a
// *Fatal. Apply does not check created_at against a clock: see CheckTime.
func Apply(s0 *State, raw []byte) (*State, *Entry, error) {
	e, err := ParseEntry(raw) // step 1
	if err != nil {
		return nil, nil, err
	}
	if e.Version != identity.Version || e.Suite != identity.Suite { // step 2
		return nil, nil, fatal("bad_version")
	}
	if e.Type < Genesis || e.Type > RotateIdentity { // step 3
		return nil, nil, fatal("unknown_entry_type")
	}
	b, ok := parseBody(e.Type, e.Body) // step 4
	if !ok {
		return nil, nil, fatal("malformed")
	}
	zero16, zero32 := make([]byte, 16), make([]byte, 32)
	if s0.CircleID == nil { // step 5
		switch {
		case e.Type != Genesis || e.Seq != 0:
			return nil, nil, fatal("bad_seq")
		case !bytes.Equal(e.PrevHash, zero32):
			return nil, nil, fatal("bad_prev_hash")
		case !bytes.Equal(e.CircleID, zero16):
			return nil, nil, fatal("bad_circle_id")
		case e.Epoch != 0:
			return nil, nil, fatal("bad_epoch")
		}
	} else {
		switch {
		case e.Type == Genesis:
			return nil, nil, fatal("unexpected_genesis")
		case s0.Seq < 0 || e.Seq != uint64(s0.Seq)+1:
			return nil, nil, fatal("bad_seq")
		case !bytes.Equal(e.PrevHash, s0.Head):
			return nil, nil, fatal("bad_prev_hash")
		case !bytes.Equal(e.CircleID, s0.CircleID):
			return nil, nil, fatal("bad_circle_id")
		case e.Epoch != s0.Epoch:
			return nil, nil, fatal("bad_epoch")
		}
	}
	var authorKey, authorAcc []byte // step 6
	var authorKind uint8
	if e.Type == Genesis {
		if !bytes.Equal(e.Author, b.cert.DeviceID()) {
			return nil, nil, fatal("bad_author")
		}
		authorKey, authorAcc, authorKind = b.cert.DSK, b.cert.AccountID, b.cert.Kind
	} else {
		d := s0.Device(e.Author)
		if d == nil {
			return nil, nil, fatal("author_not_active")
		}
		authorKey, authorAcc, authorKind = d.DSK, d.Account, d.Kind
	}
	if !kcrypto.Verify(authorKey, "log-entry", raw[:len(raw)-64], e.Sig) { // step 7
		return nil, nil, fatal("bad_signature")
	}
	if !kindMayAuthor(s0, e.Type, b, e.Author, authorKind, authorAcc) { // step 8
		return nil, nil, fatal("kind_not_allowed")
	}

	s := s0.Clone() // step 9, and the effects of step 11
	s.Seq, s.Head = int64(e.Seq), Hash(raw)
	am := s.Members[string(authorAcc)] // nil only in GENESIS
	newDevice := func() *Device {
		return &Device{ID: b.cert.DeviceID(), Account: b.cert.AccountID, DSK: b.cert.DSK, Kind: b.cert.Kind, Bundle: b.bundle}
	}
	ownCert := func() string { // the first two checks of ADD_DEVICE and ADD_RECOVERY
		switch {
		case !b.cert.WellFormed():
			return "bad_cert"
		case !bytes.Equal(b.cert.AccountID, authorAcc) || !bytes.Equal(b.cert.IK, am.IK):
			return "wrong_account"
		}
		return ""
	}

	switch e.Type {
	case Genesis:
		if !b.cert.WellFormed() || !identity.ChainProves(b.cert, b.chain) {
			return nil, nil, fatal("bad_cert")
		}
		if !b.bundle.ValidFor(b.cert.DSK, b.cert.AccountID) || !b.bundle.CurrentAt(e.CreatedAt) {
			return nil, nil, fatal("bad_bundle")
		}
		s.CircleID = kcrypto.H("circle-id", raw)[:16]
		s.Members[string(b.cert.AccountID)] = &Member{Account: b.cert.AccountID, IK: b.cert.IK, Admin: true,
			Devices: map[string]*Device{string(b.cert.DeviceID()): newDevice()}}

	case AddMember:
		keyTaken := false
		for _, m := range s.Members {
			keyTaken = keyTaken || bytes.Equal(m.IK, b.cert.IK)
		}
		switch {
		case !am.Admin:
			return nil, nil, fatal("not_admin")
		case s.RekeyPending:
			return nil, nil, fatal("rekey_pending")
		case len(s.Members) >= MaxMembers:
			return nil, nil, fatal("too_many_members")
		case !b.cert.WellFormed() || !identity.ChainProves(b.cert, b.chain):
			return nil, nil, fatal("bad_cert")
		case !identity.PhoneOrTablet(b.cert.Kind):
			return nil, nil, fatal("kind_not_allowed")
		case !b.bundle.ValidFor(b.cert.DSK, b.cert.AccountID) || !b.bundle.CurrentAt(e.CreatedAt):
			return nil, nil, fatal("bad_bundle")
		case s.Members[string(b.cert.AccountID)] != nil || keyTaken:
			return nil, nil, fatal("already_member")
		case s.Device(b.cert.DeviceID()) != nil:
			return nil, nil, fatal("device_active")
		case s.UsedInvites[string(b.invite)]:
			return nil, nil, fatal("invite_reused")
		case !kcrypto.Verify(b.cert.IK, "join-consent",
			wire.Concat(s.CircleID, b.invite, b.cert.Raw, b.bundle.Raw, b.terms), b.consent):
			return nil, nil, fatal("bad_consent")
		}
		s.Members[string(b.cert.AccountID)] = &Member{Account: b.cert.AccountID, IK: b.cert.IK, Admin: b.admin,
			Devices: map[string]*Device{string(b.cert.DeviceID()): newDevice()}}
		s.UsedInvites[string(b.invite)] = true

	case RemoveMember:
		tm := s.Members[string(b.target)]
		switch {
		case tm == nil:
			return nil, nil, fatal("not_member")
		case !am.Admin && !bytes.Equal(authorAcc, b.target):
			return nil, nil, fatal("not_admin")
		case tm.Admin && s.Admins() == 1 && len(s.Members) > 1:
			return nil, nil, fatal("last_admin")
		}
		fresh := am.Admin && !bytes.Equal(authorAcc, b.target)
		remaining := s.ReceivingDevices(func(d *Device) bool { return bytes.Equal(d.Account, b.target) })
		if !epochBody(b, fresh, remaining) {
			return nil, nil, fatal("bad_wraps")
		}
		delete(s.Members, string(b.target))
		s.advance(fresh)

	case AddDevice:
		if why := ownCert(); why != "" {
			return nil, nil, fatal(why)
		}
		k := b.cert.Kind
		switch {
		case !identity.Receiving(k) || (k == identity.Web && s.Options&1 == 0) || (k == identity.HomeAssistant && s.Options&2 == 0):
			return nil, nil, fatal("kind_not_allowed")
		case len(am.Devices) >= MaxDevices:
			return nil, nil, fatal("too_many_devices")
		case !b.bundle.ValidFor(b.cert.DSK, b.cert.AccountID) || !b.bundle.CurrentAt(e.CreatedAt):
			return nil, nil, fatal("bad_bundle")
		case s.Device(b.cert.DeviceID()) != nil:
			return nil, nil, fatal("device_active")
		}
		am.Devices[string(b.cert.DeviceID())] = newDevice()

	case RemoveDevice:
		td := s.Device(b.target)
		switch {
		case td == nil:
			return nil, nil, fatal("unknown_device")
		case !bytes.Equal(td.Account, authorAcc) && !am.Admin:
			return nil, nil, fatal("not_admin")
		case len(s.Members[string(td.Account)].Devices) == 1:
			return nil, nil, fatal("last_device")
		}
		if td.Kind == identity.Recovery { // it never held an epoch secret, so nothing else changes
			if !noEpoch(b) {
				return nil, nil, fatal("bad_wraps")
			}
			delete(s.Members[string(td.Account)].Devices, string(b.target))
			break
		}
		fresh := am.Admin && !bytes.Equal(e.Author, b.target)
		remaining := s.ReceivingDevices(func(d *Device) bool { return bytes.Equal(d.ID, b.target) })
		if !epochBody(b, fresh, remaining) {
			return nil, nil, fatal("bad_wraps")
		}
		delete(s.Members[string(td.Account)].Devices, string(b.target))
		s.advance(fresh)

	case UpdateKey:
		d := s.Device(e.Author)
		if !b.bundle.ValidFor(d.DSK, d.Account) || !b.bundle.CurrentAt(e.CreatedAt) ||
			bytes.Equal(b.bundle.KeyID(), d.Bundle.KeyID()) {
			return nil, nil, fatal("bad_bundle")
		}
		d.Bundle = b.bundle

	case Policy: // its content is encrypted, so a server checks only this
		if s.RekeyPending {
			return nil, nil, fatal("rekey_pending")
		}

	case Rekey:
		if !am.Admin {
			return nil, nil, fatal("not_admin")
		}
		if !wrapsCover(b.wraps, s.ReceivingDevices(nil)) {
			return nil, nil, fatal("bad_wraps")
		}
		s.advance(true)

	case SetAdmin:
		tm := s.Members[string(b.target)]
		switch {
		case !am.Admin:
			return nil, nil, fatal("not_admin")
		case tm == nil:
			return nil, nil, fatal("not_member")
		case !b.admin && tm.Admin && s.Admins() == 1:
			return nil, nil, fatal("last_admin")
		}
		tm.Admin = b.admin

	case AddRecovery:
		if why := ownCert(); why != "" {
			return nil, nil, fatal(why)
		}
		hasRecovery := false
		for _, d := range am.Devices {
			hasRecovery = hasRecovery || d.Kind == identity.Recovery
		}
		switch {
		case b.cert.Kind != identity.Recovery:
			return nil, nil, fatal("kind_not_allowed")
		case hasRecovery || len(am.Devices) >= MaxDevices:
			return nil, nil, fatal("too_many_devices")
		case s.Device(b.cert.DeviceID()) != nil:
			return nil, nil, fatal("device_active")
		}
		am.Devices[string(b.cert.DeviceID())] = &Device{ID: b.cert.DeviceID(), Account: b.cert.AccountID,
			DSK: b.cert.DSK, Kind: b.cert.Kind}

	case SetOptions:
		switch {
		case !am.Admin:
			return nil, nil, fatal("not_admin")
		case b.options&^OptionsDefined != 0:
			return nil, nil, fatal("bad_options")
		}
		s.Options = b.options

	case RotateIdentity:
		oldK, newK := b.link[:32], b.link[32:64]
		taken := false
		for _, m := range s.Members {
			taken = taken || bytes.Equal(m.IK, newK)
		}
		if !bytes.Equal(oldK, am.IK) || kcrypto.EdKeyInvalid(newK) || taken || !identity.LinkOK(authorAcc, b.link) {
			return nil, nil, fatal("bad_rotation")
		}
		am.IK = append([]byte(nil), newK...)
	}
	if e.Type == Genesis || s.receivingSet() != s0.receivingSet() {
		s.RecvChanged = s.Seq
	}
	return s, e, nil
}

// Append is everything a server checks before it appends an entry (§6.7): steps 1 to 9
// of §6.3, then created_at against its clock, now (ms). In repair mode an entry may be
// older than the clock by any amount.
func Append(s *State, raw []byte, now uint64, repair bool) (*State, *Entry, error) {
	ns, e, err := Apply(s, raw)
	if err != nil {
		return nil, nil, err
	}
	if err := CheckTime(e.CreatedAt, now, repair); err != nil {
		return nil, nil, err
	}
	return ns, e, nil
}

// CheckTime is the server's clock check of §6.7: created_at within 10 minutes of now,
// or, in repair mode, any age but no more than 10 minutes ahead. A failure is bad_time.
func CheckTime(createdAt, now uint64, repair bool) error {
	if createdAt > now && createdAt-now > ClockSkewMS {
		return fatal("bad_time")
	}
	if !repair && now > createdAt && now-createdAt > ClockSkewMS {
		return fatal("bad_time")
	}
	return nil
}

// ---- the public state as the test vectors write it (vectors/README.md) ----

// PublicJSON is the public state in the form of the vectors' state_after, without the
// private fields, ready for encoding/json.
func (s *State) PublicJSON() map[string]any {
	accs := make([]string, 0, len(s.Members))
	for k := range s.Members {
		accs = append(accs, k)
	}
	sort.Strings(accs)
	members := []any{}
	for _, k := range accs {
		m := s.Members[k]
		ds := make([]*Device, 0, len(m.Devices))
		for _, d := range m.Devices {
			ds = append(ds, d)
		}
		sort.Slice(ds, func(i, j int) bool { return bytes.Compare(ds[i].ID, ds[j].ID) < 0 })
		devs := []any{}
		for _, d := range ds {
			var kid any
			if d.Bundle.Raw != nil {
				kid = hex.EncodeToString(d.Bundle.KeyID())
			}
			devs = append(devs, map[string]any{"device_id": hex.EncodeToString(d.ID), "kind": int(d.Kind), "key_id": kid})
		}
		members = append(members, map[string]any{"account_id": hex.EncodeToString(m.Account),
			"ik_pub": hex.EncodeToString(m.IK), "admin": m.Admin, "devices": devs})
	}
	used := []string{}
	for k := range s.UsedInvites {
		used = append(used, hex.EncodeToString([]byte(k)))
	}
	sort.Strings(used)
	var cid any
	if s.CircleID != nil {
		cid = hex.EncodeToString(s.CircleID)
	}
	return map[string]any{"circle_id": cid, "seq": s.Seq, "head": hex.EncodeToString(s.Head), "epoch": s.Epoch,
		"rekey_pending": s.RekeyPending, "options": s.Options, "used_invites": used, "members": members}
}
