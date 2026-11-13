// SPDX-License-Identifier: AGPL-3.0-or-later

// Package store is what the server keeps (API.md §15), behind an interface with two
// implementations: SQLite (sqlstore) for the server, and memory (memstore) for tests. All
// access goes through transactions, so that a check and the write it guards are atomic.
// The storetest package holds the tests both must pass.
package store

import (
	"errors"

	"github.com/gureetk/kinfold/server/internal/memberlog"
)

// ErrNotFound is returned by lookups that find nothing.
var ErrNotFound = errors.New("not found")

// Store opens transactions.
type Store interface {
	// Update runs fn in a read-write transaction. If fn returns an error, nothing it
	// wrote is kept. Transactions don't overlap.
	Update(fn func(Tx) error) error
	// View runs fn in a read-only transaction.
	View(fn func(Tx) error) error
}

// Settings are what the operator switches on and off (API.md §16).
type Settings struct {
	MemberTokens bool   // admins may mint registration tokens with invites (§9)
	WebDevices   bool   // web and Home Assistant devices may be registered (§5)
	RepairUntil  uint64 // repair mode lasts until this time (ms); 0 when off (§6)
	LastBackupAt uint64 // when the last backup was written (ms); 0 if never (§16)
	// WebTileRanges lets web devices read map regions in parts (§13).
	WebTileRanges bool
	// Limits are the rate limits the operator has set, as JSON; the rest keep their
	// defaults (§3). Empty means none.
	Limits string
}

// Token is a registration token. Only its hash is kept.
type Token struct {
	Hash      []byte // SHA-256 of the token
	CreatedAt uint64
	ExpiresAt uint64
	Spent     bool
	Invite    []byte // the invite it came with (member tokens), if any
}

// Account is a registered account.
type Account struct {
	ID        []byte
	IK        []byte // the current identity key
	Chain     []byte // the identity chain that leads to it
	Operator  bool
	CreatedAt uint64
	Nickname  string // a label only the operator sees (API.md §16)
}

// Device is a registered device.
type Device struct {
	ID         []byte
	Account    []byte
	Kind       uint8
	DSK        []byte
	Cert       []byte
	Bundle     []byte // nil for a recovery device
	CreatedAt  uint64
	LastSeenAt uint64
	Nickname   string // a label only the operator sees (API.md §16)
}

// Challenge is a login challenge (§13.2), used once.
type Challenge struct {
	Challenge []byte
	Device    []byte
	ExpiresAt uint64
}

// Session is a logged-in device. Only the token's hash is kept.
type Session struct {
	Hash      []byte
	Device    []byte
	ExpiresAt uint64
}

// Circle is a circle's public state. State is never changed in place: appending an entry
// stores a new one.
type Circle struct {
	ID        []byte
	State     *memberlog.State
	CreatedAt uint64
}

// Removal lets a removed device read the log up to the entry that removed it (API.md §6).
type Removal struct {
	Circle []byte
	Device []byte
	Seq    int64  // the entry that removed it
	At     uint64 // when it was appended
}

// Envelope is a stored envelope with its delivery details.
type Envelope struct {
	Seq        uint64 // store-wide order of arrival; set by PutEnvelope
	Circle     []byte
	Sender     []byte
	Recipients [][]byte
	ReceivedAt uint64
	ExpiresAt  uint64 // received_at + ttl_s
	Raw        []byte
}

// SeenRecord is what the replay record keeps for an envelope it stored.
type SeenRecord struct {
	Digest     [32]byte // SHA-256 of the envelope
	ReceivedAt uint64
	KeepUntil  uint64 // 32 days after sent_at (API.md §15)
}

// Invite is an invite's mailbox (API.md §9). A sweep deletes it once it can no longer
// matter: after expires_at, and after the retention of its result if one was written.
type Invite struct {
	ID        []byte
	Circle    []byte
	Account   []byte // the inviter's account
	ExpiresAt uint64
	Requests  [][]byte // join requests waiting
	Askers    [][]byte // devices that posted a request; they may read the result
	Used      bool     // its ADD_MEMBER is in the log: no more requests
	Result    []byte
	ResultAt  uint64
	Ended     bool // deleted or expired: kept only to answer 410
}

// Watch is a silence watch (API.md §8): one per circle, watched device and watcher account.
type Watch struct {
	Circle   []byte
	Device   []byte // the watched phone or tablet
	Watcher  []byte // the watcher's account
	Grant    []byte // the WatchGrant that allows it
	AfterMin uint16
	NotAfter uint64
	Since    uint64 // when the current silence began
	WokeAt   uint64 // when the device was woken in this silence; 0 before that
	Alerted  bool   // the watcher has been told of this silence
	// Revoked: the watched account deleted it. It stays until NotAfter, inactive, so that
	// its grant can't be registered again.
	Revoked bool
}

// Share is a share link (API.md §11): the latest update of a live location, sealed under a
// key that only the link's fragment holds.
type Share struct {
	ID        []byte
	Account   []byte
	Device    []byte // the creating device, the only one that may post updates
	ExpiresAt uint64
	Update    []byte // the latest ShareUpdate; nil before the first and once deleted
	Seq       uint64 // its seq
	Views     int
	LastView  uint64
	Ended     bool // deleted: kept, empty, until ExpiresAt, to answer 410
}

// PushReg is a device's push registration (API.md §12): one per device.
type PushReg struct {
	Device []byte
	Kind   string // "relay" or "webpush"; "dropped" once the push host has said it is dead
	// relay: the capabilities for alert and background pushes, and for location pushes
	// (nil without the entitlement).
	Notify, Locate []byte
	// webpush: the endpoint and the subscription's keys (RFC 8291).
	Endpoint     string
	P256dh, Auth []byte
}

// Tx is a transaction.
type Tx interface {
	Settings() (Settings, error)
	PutSettings(Settings) error

	PutToken(Token) error
	Token(hash []byte) (Token, error)
	Tokens() ([]Token, error)
	DeleteToken(hash []byte) error

	PutAccount(Account) error
	Account(id []byte) (Account, error)
	// Accounts lists every account, by ID.
	Accounts() ([]Account, error)
	DeleteAccount(id []byte) error

	PutDevice(Device) error
	Device(id []byte) (Device, error)
	DevicesOf(account []byte) ([]Device, error)
	DeleteDevice(id []byte) error

	PutChallenge(Challenge) error
	// TakeChallenge returns the challenge and removes it, so it works once.
	TakeChallenge(challenge []byte) (Challenge, error)

	PutSession(Session) error
	Session(hash []byte) (Session, error)
	DeleteSession(hash []byte) error
	DeleteSessionsOf(device []byte) error

	// CreateCircle stores a circle and its GENESIS entry.
	CreateCircle(c Circle, genesis []byte) error
	Circle(id []byte) (Circle, error)
	// AppendEntry stores raw as entry s.Seq, appended at the server's time at, and s as the
	// circle's state. A circle whose state has no members is closed from then on.
	AppendEntry(circle, raw []byte, s *memberlog.State, at uint64) error
	// Entries returns entries after seq `after`, in order, at most limit of them and no
	// more than maxBytes in all (but at least one).
	Entries(circle []byte, after int64, limit, maxBytes int) ([][]byte, error)
	// SeqOf finds an entry hash in a circle's log.
	SeqOf(circle, hash []byte) (int64, bool, error)
	// CirclesOf lists the circles in which the account is a member.
	CirclesOf(account []byte) ([]Circle, error)
	// Circles lists every circle, closed ones too, by ID.
	Circles() ([]Circle, error)
	PutRemoval(Removal) error
	Removal(circle, device []byte) (Removal, error)

	// PutEnvelope stores an envelope and returns its Seq.
	PutEnvelope(Envelope) (uint64, error)
	// Inbox returns, in order of arrival, envelopes after Seq `after` addressed to device
	// in one of the circles, unexpired at now: at most limit, no more than maxBytes (but at
	// least one), and whether more wait. Their Recipients may be left out.
	Inbox(device []byte, circles [][]byte, after uint64, limit, maxBytes int, now uint64) ([]Envelope, bool, error)
	// Seen is the replay record of a circle (§7.5).
	Seen(circle, sender []byte, seq uint64) (SeenRecord, bool, error)
	PutSeen(circle, sender []byte, seq uint64, r SeenRecord) error

	PutInvite(Invite) error
	Invite(id []byte) (Invite, error)
	InvitesOf(circle []byte) ([]Invite, error)

	PutWatch(Watch) error
	Watch(circle, device, watcher []byte) (Watch, error)
	// WatchesIn lists a circle's watches, Watches every watch; both by device, then watcher.
	WatchesIn(circle []byte) ([]Watch, error)
	Watches() ([]Watch, error)
	DeleteWatch(circle, device, watcher []byte) error
	// Heard records that the device stored a circle envelope at `at`; the silence of every
	// watch on it starts again from then.
	Heard(circle, device []byte, at uint64) error
	// LastHeard is when the device last stored a circle envelope, if the store knows.
	LastHeard(circle, device []byte) (uint64, bool, error)

	PutShare(Share) error
	Share(id []byte) (Share, error)
	// SharesOf lists the share links a device made, by ID.
	SharesOf(device []byte) ([]Share, error)

	PutPush(PushReg) error
	Push(device []byte) (PushReg, error)
	DeletePush(device []byte) error

	// Sweep deletes what has run out by now (API.md §15) and counts what it deleted.
	Sweep(now uint64, r Retention) (Swept, error)
}

// Retention is how long the server keeps what has ended, in milliseconds. Everything else
// goes when it expires: challenges, sessions, tokens, envelopes, replay records, share
// links and revoked watches. (Watches that are still active end in the silence check, which tells the watcher.)
type Retention struct {
	Removals      uint64 // a removed device may read the log for this long (API.md §6)
	Results       uint64 // a join result, after it is written (§9)
	ClosedCircles uint64 // a closed circle, after its last member leaves (§6)
}

// Swept counts what a sweep deleted.
type Swept struct {
	Challenges, Sessions, Tokens, Envelopes, Seen, Removals, Invites, Watches, Shares, Circles int
}
