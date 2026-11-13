// SPDX-License-Identifier: AGPL-3.0-or-later

// Package identity holds the structures of PROTOCOL.md §4 that a server checks
// (device certificates, identity chains and key bundles) and the server's own identity
// of §13: its signed identity document, setup codes, move notices and login.
package identity

import (
	"bytes"
	"crypto/ed25519"

	"github.com/gureetk/kinfold/server/internal/kcrypto"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// Device kinds (§16.3).
const (
	Phone         = 1
	Tablet        = 2
	Web           = 3
	HomeAssistant = 4
	Recovery      = 5
)

// Receiving reports whether a device of this kind receives envelopes and epoch wraps.
func Receiving(kind uint8) bool { return kind >= Phone && kind <= HomeAssistant }

// PhoneOrTablet reports whether a device of this kind holds the identity key.
func PhoneOrTablet(kind uint8) bool { return kind == Phone || kind == Tablet }

const (
	Version = 0
	Suite   = 0x0001

	CertLen   = 156
	BundleLen = 152
	LinkLen   = 192
	MaxLinks  = 8

	DayMS = 86_400_000
)

// AccountID is H("account-id", ik_pub)[0:16] of the account's first identity key.
func AccountID(firstIK []byte) []byte { return kcrypto.H("account-id", firstIK)[:16] }

// DeviceID is H("device-id", dsk_pub)[0:16].
func DeviceID(dsk []byte) []byte { return kcrypto.H("device-id", dsk)[:16] }

// KeyID is H("key-id", dek_pub)[0:8].
func KeyID(dek []byte) []byte { return kcrypto.H("key-id", dek)[:8] }

// ---- device certificates (§4.3) ----

// Cert is a DeviceCert. Raw is nil when it didn't parse.
type Cert struct {
	Raw       []byte
	Version   uint8
	Suite     uint16
	AccountID []byte
	DSK       []byte
	Kind      uint8
	IssuedAt  uint64
	IK        []byte
	Sig       []byte
}

// ReadCert reads a DeviceCert from r.
func ReadCert(r *wire.Reader) Cert {
	start := r.Pos()
	c := Cert{Version: r.U8(), Suite: r.U16(), AccountID: r.Take(16), DSK: r.Take(32), Kind: r.U8(),
		IssuedAt: r.U64(), IK: r.Take(32), Sig: r.Take(64)}
	if !r.Failed() {
		c.Raw = r.Bytes()[start:r.Pos()]
	}
	return c
}

// ParseCert parses a DeviceCert that fills b exactly.
func ParseCert(b []byte) (Cert, bool) {
	r := wire.NewReader(b)
	c := ReadCert(r)
	return c, r.Done()
}

// DeviceID is the device ID of the certified signing key.
func (c Cert) DeviceID() []byte { return DeviceID(c.DSK) }

// WellFormed is §4.3: version and suite, a kind in the registry, keys that are not invalid,
// and a signature under ik_pub. It says nothing about whether the account belongs to the
// key; see ChainProves.
func (c Cert) WellFormed() bool {
	return c.Raw != nil && c.Version == Version && c.Suite == Suite && c.Kind >= Phone && c.Kind <= Recovery &&
		!kcrypto.EdKeyInvalid(c.IK) && !kcrypto.EdKeyInvalid(c.DSK) &&
		kcrypto.Verify(c.IK, "device-cert", c.Raw[:60], c.Sig)
}

// ---- identity chains (§4.3) ----

// ParseChain splits a chain into its links: a multiple of 192 bytes, at most 8 links.
func ParseChain(b []byte) ([][]byte, bool) {
	if len(b)%LinkLen != 0 || len(b) > LinkLen*MaxLinks {
		return nil, false
	}
	var links [][]byte
	for i := 0; i < len(b); i += LinkLen {
		links = append(links, b[i:i+LinkLen])
	}
	return links, true
}

// LinkOK reports whether both keys of an IdentityLink are usable and both signatures
// verify for the account.
func LinkOK(account, link []byte) bool {
	if len(link) != LinkLen {
		return false
	}
	oldK, newK := link[:32], link[32:64]
	tbs := wire.Concat(account, oldK, newK)
	return !kcrypto.EdKeyInvalid(oldK) && !kcrypto.EdKeyInvalid(newK) &&
		kcrypto.Verify(oldK, "identity-rotate", tbs, link[64:128]) &&
		kcrypto.Verify(newK, "identity-rotate", tbs, link[128:192])
}

// ChainProves reports whether the chain proves that c.IK is the current identity key of
// c.AccountID.
func ChainProves(c Cert, links [][]byte) bool {
	if len(links) == 0 {
		return bytes.Equal(c.AccountID, AccountID(c.IK))
	}
	var key []byte
	for i, l := range links {
		if i == 0 {
			if !bytes.Equal(AccountID(l[:32]), c.AccountID) {
				return false
			}
		} else if !bytes.Equal(l[:32], key) {
			return false
		}
		if !LinkOK(c.AccountID, l) {
			return false
		}
		key = l[32:64]
	}
	return bytes.Equal(key, c.IK)
}

// ---- key bundles (§4.4) ----

// Bundle is a KeyBundle. Raw is nil when it didn't parse.
type Bundle struct {
	Raw       []byte
	Version   uint8
	Suite     uint16
	AccountID []byte
	DeviceID  []byte
	DEK       []byte
	NotBefore uint64
	NotAfter  uint64
	ProtoMax  uint8
	Features  uint32
	Sig       []byte
}

// ReadBundle reads a KeyBundle from r.
func ReadBundle(r *wire.Reader) Bundle {
	start := r.Pos()
	b := Bundle{Version: r.U8(), Suite: r.U16(), AccountID: r.Take(16), DeviceID: r.Take(16), DEK: r.Take(32),
		NotBefore: r.U64(), NotAfter: r.U64(), ProtoMax: r.U8(), Features: r.U32(), Sig: r.Take(64)}
	if !r.Failed() {
		b.Raw = r.Bytes()[start:r.Pos()]
	}
	return b
}

// ParseBundle parses a KeyBundle that fills b exactly.
func ParseBundle(b []byte) (Bundle, bool) {
	r := wire.NewReader(b)
	bu := ReadBundle(r)
	return bu, r.Done()
}

// KeyID is the key ID of the bundle's encryption key.
func (b Bundle) KeyID() []byte { return KeyID(b.DEK) }

// ValidFor is §4.4: the bundle belongs to the device with signing key dsk in the account,
// its encryption key passes the check of §3.5, its validity is at most 35 days, and the
// device signed it. proto_max and features never affect validity.
func (b Bundle) ValidFor(dsk, account []byte) bool {
	return b.Raw != nil && b.Version == Version && b.Suite == Suite &&
		bytes.Equal(b.DeviceID, DeviceID(dsk)) && bytes.Equal(b.AccountID, account) &&
		!kcrypto.XKeyInvalid(b.DEK) && b.NotBefore < b.NotAfter && b.NotAfter-b.NotBefore <= 35*DayMS &&
		kcrypto.Verify(dsk, "key-bundle", b.Raw[:88], b.Sig)
}

// CurrentAt is §4.4: not_before ≤ t + 10 minutes and t < not_after. t is an entry's
// created_at, which its author chooses, so the sum is never formed.
func (b Bundle) CurrentAt(t uint64) bool {
	return (b.NotBefore <= t || b.NotBefore-t <= 600_000) && t < b.NotAfter
}

// ---- the server's identity (§13) ----

// ServerInfo is the signed identity document of §13.1.
type ServerInfo struct {
	Raw       []byte
	URL       string
	Key       []byte
	IssuedAt  uint64
	ExpiresAt uint64
}

// MakeServerInfo builds and signs a ServerInfo.
func MakeServerInfo(priv ed25519.PrivateKey, url string, issuedAt, expiresAt uint64) []byte {
	tbs := wire.Concat([]byte{Version}, wire.Vec16([]byte(url)), priv.Public().(ed25519.PublicKey),
		wire.U64(issuedAt), wire.U64(expiresAt))
	return append(tbs, kcrypto.Sign(priv, "server-info", tbs)...)
}

// ParseServerInfo parses a ServerInfo and checks its signature under the key it carries.
// A client also checks that key against the one it trusts; a server only reads its own.
func ParseServerInfo(raw []byte) (ServerInfo, bool) {
	r := wire.NewReader(raw)
	ver, url, key, issued, expires := r.U8(), r.Vec16(), r.Take(32), r.U64(), r.U64()
	tbs := r.Pos()
	sig := r.Take(64)
	if !r.Done() || ver != Version || !kcrypto.Verify(key, "server-info", raw[:tbs], sig) {
		return ServerInfo{}, false
	}
	return ServerInfo{Raw: raw, URL: string(url), Key: key, IssuedAt: issued, ExpiresAt: expires}, true
}

// Setup is the structure behind a KFS0 setup code (§13.1).
type Setup struct {
	URL       string
	Key       []byte
	RegToken  []byte
	ExpiresAt uint64
}

// MakeSetup builds the Setup bytes.
func MakeSetup(url string, key, regToken []byte, expiresAt uint64) []byte {
	return wire.Concat([]byte{Version}, wire.Vec16([]byte(url)), key, wire.Vec16(regToken), wire.U64(expiresAt))
}

// SetupCode is "KFS0" ‖ b64u(Setup).
func SetupCode(setup []byte) string { return "KFS0" + wire.EncodeB64u(setup) }

// ParseSetup parses Setup bytes.
func ParseSetup(raw []byte) (Setup, bool) {
	r := wire.NewReader(raw)
	ver, url, key, tok, exp := r.U8(), r.Vec16(), r.Take(32), r.Vec16(), r.U64()
	if !r.Done() || ver != Version {
		return Setup{}, false
	}
	return Setup{URL: string(url), Key: key, RegToken: tok, ExpiresAt: exp}, true
}

// ParseCode returns the bytes inside a scanned code with the given prefix.
func ParseCode(prefix, text string) ([]byte, bool) {
	if len(text) < len(prefix) || text[:len(prefix)] != prefix {
		return nil, false
	}
	b, err := wire.DecodeB64u(text[len(prefix):])
	return b, err == nil
}

// ServerMove is the notice of §13.3.
type ServerMove struct {
	OldURL   string
	OldKey   []byte
	NewURL   string
	NewKey   []byte
	IssuedAt uint64
}

// MakeServerMove builds a ServerMove signed with the old key.
func MakeServerMove(oldPriv ed25519.PrivateKey, oldURL, newURL string, newKey []byte, issuedAt uint64) []byte {
	tbs := wire.Concat([]byte{Version}, wire.Vec16([]byte(oldURL)), oldPriv.Public().(ed25519.PublicKey),
		wire.Vec16([]byte(newURL)), newKey, wire.U64(issuedAt))
	return append(tbs, kcrypto.Sign(oldPriv, "server-move", tbs)...)
}

// ParseServerMove parses a ServerMove and checks its signature under old_key.
func ParseServerMove(raw []byte) (ServerMove, bool) {
	r := wire.NewReader(raw)
	ver, oldURL, oldKey, newURL, newKey, issued := r.U8(), r.Vec16(), r.Take(32), r.Vec16(), r.Take(32), r.U64()
	tbs := r.Pos()
	sig := r.Take(64)
	if !r.Done() || ver != Version || !kcrypto.Verify(oldKey, "server-move", raw[:tbs], sig) {
		return ServerMove{}, false
	}
	return ServerMove{OldURL: string(oldURL), OldKey: oldKey, NewURL: string(newURL), NewKey: newKey, IssuedAt: issued}, true
}

// ---- login (§13.2) ----

// ChallengeSig is Sign(server key, "auth-challenge", challenge ‖ device_id ‖ u64(expires_at)).
func ChallengeSig(priv ed25519.PrivateKey, challenge, deviceID []byte, expiresAt uint64) []byte {
	return kcrypto.Sign(priv, "auth-challenge", challenge, deviceID, wire.U64(expiresAt))
}

// AuthOK checks a device's login signature: Sign(DSK, "auth", server_key ‖ challenge ‖ device_id).
func AuthOK(dsk, serverKey, challenge, deviceID, sig []byte) bool {
	return kcrypto.Verify(dsk, "auth", wire.Concat(serverKey, challenge, deviceID), sig)
}
