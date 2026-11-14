// SPDX-License-Identifier: AGPL-3.0-or-later

package kcrypto_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/gureetk/kinfold/server/internal/kcrypto"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
	"github.com/gureetk/kinfold/server/internal/wire"
)

func TestPrimitives(t *testing.T) {
	p := tv.Obj(tv.Load(t)["primitives"])
	if tv.Str(p["label_prefix"]) != kcrypto.LabelPrefix {
		t.Fatal("label prefix")
	}
	strip := func(label string) string { return label[len(kcrypto.LabelPrefix):] }
	for _, c := range tv.Arr(p["H"]) {
		cc := tv.Obj(c)
		if got := kcrypto.H(strip(tv.Str(cc["label"])), tv.Hex(cc["data"])); hex.EncodeToString(got) != tv.Str(cc["out"]) {
			t.Errorf("H(%s)", tv.Str(cc["label"]))
		}
	}
	for _, c := range tv.Arr(p["kdf"]) {
		cc := tv.Obj(c)
		got := kcrypto.KDF(tv.Hex(cc["ikm"]), strip(tv.Str(cc["label"])), int(tv.Num(cc["length"])))
		if hex.EncodeToString(got) != tv.Str(cc["out"]) {
			t.Errorf("KDF(%s)", tv.Str(cc["label"]))
		}
	}
	for _, c := range tv.Arr(p["sign"]) {
		cc := tv.Obj(c)
		priv := ed25519.NewKeyFromSeed(tv.Hex(cc["seed"]))
		sig := kcrypto.Sign(priv, strip(tv.Str(cc["label"])), tv.Hex(cc["data"]))
		if hex.EncodeToString(sig) != tv.Str(cc["sig"]) {
			t.Errorf("Sign(%s)", tv.Str(cc["label"]))
		}
		if !kcrypto.Verify(priv.Public().(ed25519.PublicKey), strip(tv.Str(cc["label"])), tv.Hex(cc["data"]), sig) {
			t.Errorf("Verify(%s)", tv.Str(cc["label"]))
		}
	}
}

// The RFC 9180 case, through the standard library. Go can't fix the sender's ephemeral key,
// so the vector's sender context is checked through DeriveKeyPair and opening (§3.5).
func TestHPKE(t *testing.T) {
	h := tv.Obj(tv.Load(t)["hpke_rfc9180"])
	if tv.Num(h["mode"]) != 0 || tv.Num(h["kem_id"]) != 0x20 || tv.Num(h["kdf_id"]) != 1 || tv.Num(h["aead_id"]) != 2 {
		t.Fatal("unexpected suite")
	}
	kem, kdf, aead := kcrypto.HPKE()
	eph, err := kem.DeriveKeyPair(tv.Hex(h["ikmE"]))
	if err != nil || !bytes.Equal(eph.PublicKey().Bytes(), tv.Hex(h["enc"])) {
		t.Fatalf("DeriveKeyPair(ikmE) doesn't give enc: %v", err)
	}
	rk, err := kem.DeriveKeyPair(tv.Hex(h["ikmR"]))
	if err != nil || !bytes.Equal(rk.PublicKey().Bytes(), tv.Hex(h["pkRm"])) {
		t.Fatalf("DeriveKeyPair(ikmR) doesn't give pkRm: %v", err)
	}
	sk, err := kem.NewPrivateKey(tv.Hex(h["skRm"]))
	if err != nil {
		t.Fatal(err)
	}
	rcp, err := hpke.NewRecipient(tv.Hex(h["enc"]), sk, kdf, aead, tv.Hex(h["info"]))
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range tv.Arr(h["encryptions"]) {
		ee := tv.Obj(e)
		pt, err := rcp.Open(tv.Hex(ee["aad"]), tv.Hex(ee["ct"]))
		if err != nil || !bytes.Equal(pt, tv.Hex(ee["pt"])) {
			t.Fatalf("encryption %d: %v", i, err)
		}
	}
	// The protocol's single-shot form, empty aad, round trip.
	pk := rk.PublicKey().Bytes()
	enc, ct, err := kcrypto.Seal(pk, []byte("info"), []byte("secret"))
	if err != nil || len(enc) != 32 || len(ct) != 6+16 {
		t.Fatalf("Seal: %v", err)
	}
	if pt, err := kcrypto.Open(enc, tv.Hex(h["skRm"]), []byte("info"), ct); err != nil || string(pt) != "secret" {
		t.Fatalf("Open: %v", err)
	}
}

func TestEd25519EdgeCases(t *testing.T) {
	ed := tv.Obj(tv.Load(t)["ed25519"])
	for _, c := range tv.Arr(ed["signatures"]) {
		cc := tv.Obj(c)
		if got := kcrypto.VerifyRaw(tv.Hex(cc["pub"]), tv.Hex(cc["msg"]), tv.Hex(cc["sig"])); got != tv.Bool(cc["valid"]) {
			t.Errorf("%s: got %v", tv.Str(cc["name"]), got)
		}
	}
	for _, c := range tv.Arr(ed["keys"]) {
		cc := tv.Obj(c)
		if kcrypto.EdKeyInvalid(tv.Hex(cc["pub"])) != tv.Bool(cc["invalid"]) {
			t.Errorf("Ed25519 key %s", tv.Str(cc["pub"]))
		}
	}
	for _, c := range tv.Arr(tv.Obj(tv.Load(t)["x25519"])["keys"]) {
		cc := tv.Obj(c)
		if kcrypto.XKeyInvalid(tv.Hex(cc["pub"])) != tv.Bool(cc["invalid"]) {
			t.Errorf("X25519 key %s", tv.Str(cc["pub"]))
		}
	}
}

func TestSealRefusesInvalidKeys(t *testing.T) {
	for _, c := range tv.Arr(tv.Obj(tv.Load(t)["x25519"])["keys"]) {
		cc := tv.Obj(c)
		if !tv.Bool(cc["invalid"]) {
			continue
		}
		if _, _, err := kcrypto.Seal(tv.Hex(cc["pub"]), nil, []byte("x")); err == nil {
			t.Errorf("sealed to invalid key %s", tv.Str(cc["pub"]))
		}
	}
}

func TestVerifyIsBoundToLabel(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	sig := kcrypto.Sign(priv, "envelope", []byte("data"))
	if kcrypto.Verify(pub, "log-entry", []byte("data"), sig) || !kcrypto.Verify(pub, "envelope", []byte("data"), sig) {
		t.Fatal("a signature verified under the wrong label")
	}
	if got := sha256.Sum256(kcrypto.Label("x")); bytes.Equal(got[:], kcrypto.H("x")) != true {
		t.Fatal("H of no data is not SHA-256 of the label")
	}
	if !bytes.Equal(kcrypto.Label("log-hash")[:2], wire.U16(19)) {
		t.Fatal("label length")
	}
}
