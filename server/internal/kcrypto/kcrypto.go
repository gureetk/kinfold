// SPDX-License-Identifier: AGPL-3.0-or-later

// Package kcrypto is cipher suite 0x0001 of PROTOCOL.md §3, built only on Go's standard
// library: labelled hashes, the KDF, strict Ed25519 verification (§3.3), the X25519 key
// check (§3.5), and HPKE base mode with empty aad.
package kcrypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/gureetk/kinfold/server/internal/wire"
)

// LabelPrefix starts every domain-separation label (§3.2).
const LabelPrefix = "kinfold/v0/"

// Label is vec16 of the full label kinfold/v0/<purpose>.
func Label(purpose string) []byte { return wire.Vec16([]byte(LabelPrefix + purpose)) }

// H is SHA-256(vec16(label) ‖ data).
func H(purpose string, data ...[]byte) []byte {
	h := sha256.New()
	h.Write(Label(purpose))
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// KDF is HKDF-SHA-256 with a salt of 32 zero bytes and info vec16(label).
func KDF(ikm []byte, purpose string, n int) []byte {
	out, err := hkdf.Key(sha256.New, ikm, make([]byte, 32), string(Label(purpose)), n)
	if err != nil {
		panic("kcrypto: KDF length out of range") // only n > 255*32 can fail
	}
	return out
}

// Sign is Ed25519 over vec16(label) ‖ the parts.
func Sign(priv ed25519.PrivateKey, purpose string, parts ...[]byte) []byte {
	return ed25519.Sign(priv, append(Label(purpose), wire.Concat(parts...)...))
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Little-endian constants of §3.3 and §3.5.
var (
	groupOrder = mustHex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010") // L
	fieldPrime = mustHex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f") // p = 2^255 - 19
	// y of the eight small-order Ed25519 points, with the sign bit cleared.
	edSmall = [][]byte{
		mustHex("0000000000000000000000000000000000000000000000000000000000000000"),
		mustHex("0100000000000000000000000000000000000000000000000000000000000000"),
		mustHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
		mustHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
		mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	}
	// X25519 public keys whose shared secret is always zero.
	xLowOrder = [][]byte{
		mustHex("0000000000000000000000000000000000000000000000000000000000000000"),
		mustHex("0100000000000000000000000000000000000000000000000000000000000000"),
		mustHex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
		mustHex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
		mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	}
)

// lessLE reports a < b for 32-byte little-endian integers.
func lessLE(a, b []byte) bool {
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

// EdKeyInvalid is checks 2 and 3 of §3.3 on a public key or on R: y not below p, or one of
// the small-order values. A key that fails them is an invalid key.
func EdKeyInvalid(enc []byte) bool {
	if len(enc) != 32 {
		return true
	}
	var y [32]byte
	copy(y[:], enc)
	y[31] &= 0x7f
	return !lessLE(y[:], fieldPrime) || oneOf(y[:], edSmall)
}

// VerifyRaw is strict Ed25519 verification (§3.3): the three byte checks, then the
// standard library's single-signature, cofactorless equation.
func VerifyRaw(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	if !lessLE(sig[32:], groupOrder) || EdKeyInvalid(pub) || EdKeyInvalid(sig[:32]) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// Verify checks sig over vec16(label) ‖ data.
func Verify(pub []byte, purpose string, data, sig []byte) bool {
	return VerifyRaw(pub, append(Label(purpose), data...), sig)
}

// XKeyInvalid is the X25519 key check of §3.5.
func XKeyInvalid(pub []byte) bool {
	return len(pub) != 32 || pub[31]&0x80 != 0 || !lessLE(pub, fieldPrime) || oneOf(pub, xLowOrder)
}

// ---- HPKE (§3.5): KEM 0x0020, KDF 0x0001, AEAD 0x0002, base mode, empty aad ----

var (
	hpkeKEM  = hpke.DHKEM(ecdh.X25519())
	hpkeKDF  = hpke.HKDFSHA256()
	hpkeAEAD = hpke.AES256GCM()
)

// ErrBadKey is returned when sealing to a key that fails the key check of §3.5.
var ErrBadKey = errors.New("invalid X25519 key")

// Seal encrypts pt to pkR in a single-shot context with a fresh ephemeral key. It returns
// enc (32 bytes) and the ciphertext (len(pt)+16 bytes).
func Seal(pkR, info, pt []byte) (enc, ct []byte, err error) {
	if XKeyInvalid(pkR) {
		return nil, nil, ErrBadKey
	}
	pk, err := hpkeKEM.NewPublicKey(pkR)
	if err != nil {
		return nil, nil, err
	}
	out, err := hpke.Seal(pk, hpkeKDF, hpkeAEAD, info, pt)
	if err != nil {
		return nil, nil, err
	}
	return out[:32], out[32:], nil
}

// Open decrypts a single-shot ciphertext. Servers never open anything; tests use it to
// check what Seal produced.
func Open(enc, skR, info, ct []byte) ([]byte, error) {
	sk, err := hpkeKEM.NewPrivateKey(skR)
	if err != nil {
		return nil, err
	}
	return hpke.Open(sk, hpkeKDF, hpkeAEAD, info, wire.Concat(enc, ct))
}

// HPKE returns the suite's KEM, KDF and AEAD, for tests that need the multi-message API.
func HPKE() (hpke.KEM, hpke.KDF, hpke.AEAD) { return hpkeKEM, hpkeKDF, hpkeAEAD }
