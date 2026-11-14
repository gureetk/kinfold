// SPDX-License-Identifier: AGPL-3.0-or-later

package identity_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/gureetk/kinfold/server/internal/identity"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
	"github.com/gureetk/kinfold/server/internal/wire"
)

func pubOf(seed []byte) []byte { return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey) }

func TestIdentities(t *testing.T) {
	for name, p := range tv.Obj(tv.Load(t)["identities"]) {
		pp := tv.Obj(p)
		seeds := tv.Arr(pp["ik_seeds"])
		ik := pubOf(tv.Hex(pp["ik_seed"]))
		acc := identity.AccountID(pubOf(tv.Hex(seeds[0])))
		chain, ok := identity.ParseChain(tv.Hex(pp["chain"]))
		if !ok || len(chain) != len(seeds)-1 || hex.EncodeToString(ik) != tv.Str(pp["ik_pub"]) ||
			hex.EncodeToString(acc) != tv.Str(pp["account_id"]) {
			t.Errorf("%s: identity", name)
		}
		for _, dv := range tv.Obj(pp["devices"]) {
			d := tv.Obj(dv)
			dsk := pubOf(tv.Hex(d["dsk_seed"]))
			c, ok := identity.ParseCert(tv.Hex(d["cert"]))
			if !ok || !c.WellFormed() || !bytes.Equal(c.DSK, dsk) || !bytes.Equal(c.AccountID, acc) ||
				hex.EncodeToString(c.DeviceID()) != tv.Str(d["device_id"]) || !identity.ChainProves(c, chain) {
				t.Errorf("%s: certificate", tv.Str(d["label"]))
			}
			for i, bv := range tv.Arr(d["bundles"]) {
				b, ok := identity.ParseBundle(tv.Hex(bv))
				dek := tv.Obj(tv.Arr(d["deks"])[i])
				if !ok || !b.ValidFor(dsk, acc) || hex.EncodeToString(b.KeyID()) != tv.Str(dek["key_id"]) {
					t.Errorf("%s: bundle %d", tv.Str(d["label"]), i)
				}
				if b.ValidFor(dsk, make([]byte, 16)) || b.ValidFor(pubOf(make([]byte, 32)), acc) {
					t.Errorf("%s: bundle %d is valid for the wrong device or account", tv.Str(d["label"]), i)
				}
			}
		}
		// A chain that proves one account proves no other, and a truncated one proves nothing.
		if len(chain) > 0 {
			c, _ := identity.ParseCert(tv.Hex(tv.Obj(firstDevice(pp))["cert"]))
			if identity.ChainProves(c, chain[:len(chain)-1]) {
				t.Errorf("%s: a truncated chain proves the account", name)
			}
		}
	}
}

func firstDevice(p tv.V) any {
	for _, d := range tv.Obj(p["devices"]) {
		if tv.Num(tv.Obj(d)["kind"]) != identity.Recovery {
			return d
		}
	}
	return nil
}

func TestBundleCurrentAt(t *testing.T) {
	b := identity.Bundle{NotBefore: 1_000_000, NotAfter: 2_000_000}
	for _, c := range []struct {
		t    uint64
		want bool
	}{{399_999, false}, {400_000, true}, {1_999_999, true}, {2_000_000, false}, {^uint64(0), false}} {
		if b.CurrentAt(c.t) != c.want {
			t.Errorf("CurrentAt(%d) != %v", c.t, c.want)
		}
	}
	far := identity.Bundle{NotBefore: ^uint64(0) - 10, NotAfter: ^uint64(0)}
	if !far.CurrentAt(^uint64(0) - 5) {
		t.Error("CurrentAt near the end of the u64 range")
	}
}

func TestServerIdentity(t *testing.T) {
	v := tv.Load(t)
	au := tv.Obj(v["auth"])
	priv := ed25519.NewKeyFromSeed(tv.Hex(au["server_seed"]))
	info := tv.Hex(au["server_info"])
	si, ok := identity.ParseServerInfo(info)
	if !ok || si.URL != tv.Str(au["server_url"]) || !bytes.Equal(si.Key, tv.Hex(au["server_key"])) {
		t.Fatal("server_info doesn't parse")
	}
	if again := identity.MakeServerInfo(priv, si.URL, si.IssuedAt, si.ExpiresAt); !bytes.Equal(again, info) {
		t.Error("MakeServerInfo doesn't rebuild server_info")
	}
	bad := append([]byte(nil), info...)
	bad[3] ^= 1
	if _, ok := identity.ParseServerInfo(bad); ok {
		t.Error("a changed server_info verified")
	}
	ch, did := tv.Hex(au["challenge"]), tv.Hex(au["device_id"])
	if sig := identity.ChallengeSig(priv, ch, did, tv.Num(au["expires_at"])); !bytes.Equal(sig, tv.Hex(au["challenge_sig"])) {
		t.Error("ChallengeSig doesn't rebuild challenge_sig")
	}
	var dsk []byte
	for _, p := range tv.Obj(v["identities"]) {
		for _, d := range tv.Obj(tv.Obj(p)["devices"]) {
			if tv.Str(tv.Obj(d)["label"]) == tv.Str(au["device"]) {
				dsk = tv.Hex(tv.Obj(d)["dsk_pub"])
			}
		}
	}
	if !identity.AuthOK(dsk, si.Key, ch, did, tv.Hex(au["device_sig"])) {
		t.Error("device_sig doesn't verify")
	}
	if identity.AuthOK(dsk, make([]byte, 32), ch, did, tv.Hex(au["device_sig"])) {
		t.Error("device_sig verified for another server key")
	}

	su := tv.Obj(v["setup"])
	raw, ok := identity.ParseCode("KFS0", tv.Str(su["code"]))
	if !ok || !bytes.Equal(raw, tv.Hex(su["setup"])) {
		t.Fatal("setup code")
	}
	s, ok := identity.ParseSetup(raw)
	if !ok || s.URL != tv.Str(su["server_url"]) || !bytes.Equal(s.Key, tv.Hex(su["server_key"])) ||
		!bytes.Equal(s.RegToken, tv.Hex(su["reg_token"])) || s.ExpiresAt != tv.Num(su["expires_at"]) {
		t.Error("setup fields")
	}
	if again := identity.MakeSetup(s.URL, s.Key, s.RegToken, s.ExpiresAt); identity.SetupCode(again) != tv.Str(su["code"]) {
		t.Error("MakeSetup doesn't rebuild the code")
	}

	for _, m := range tv.Arr(v["server_moves"]) {
		mm := tv.Obj(m)
		mv, ok := identity.ParseServerMove(tv.Hex(mm["move"]))
		if ok != tv.Bool(mm["valid"]) {
			t.Errorf("move %s: valid %v", tv.Str(mm["name"]), ok)
			continue
		}
		if ok && (mv.OldURL != tv.Str(mm["old_url"]) || !bytes.Equal(mv.OldKey, tv.Hex(mm["old_key"])) ||
			mv.NewURL != tv.Str(mm["new_url"]) || !bytes.Equal(mv.NewKey, tv.Hex(mm["new_key"])) || mv.IssuedAt != tv.Num(mm["issued_at"])) {
			t.Errorf("move %s: fields", tv.Str(mm["name"]))
		}
	}
	mv := identity.MakeServerMove(priv, "https://a.example", "https://b.example", si.Key, 5)
	if got, ok := identity.ParseServerMove(mv); !ok || got.NewURL != "https://b.example" {
		t.Error("MakeServerMove round trip")
	}
}

func FuzzParseCert(f *testing.F) {
	for _, s := range seeds(f, "cert") {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		c, ok := identity.ParseCert(b)
		if ok && (len(b) != identity.CertLen || !bytes.Equal(c.Raw, b)) {
			t.Fatal("a certificate parsed from the wrong number of bytes")
		}
		c.WellFormed()
		identity.ChainProves(c, nil)
	})
}

func FuzzParseBundle(f *testing.F) {
	for _, s := range seeds(f, "bundles") {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		bu, ok := identity.ParseBundle(b)
		if ok && len(b) != identity.BundleLen {
			t.Fatal("a bundle parsed from the wrong number of bytes")
		}
		bu.ValidFor(make([]byte, 32), make([]byte, 16))
		bu.CurrentAt(0)
	})
}

func FuzzChain(f *testing.F) {
	f.Add(make([]byte, 16), []byte{})
	f.Fuzz(func(t *testing.T, account, chain []byte) {
		links, ok := identity.ParseChain(chain)
		if !ok {
			return
		}
		if len(links)*identity.LinkLen != len(chain) || len(links) > identity.MaxLinks {
			t.Fatal("chain length")
		}
		for _, l := range links {
			identity.LinkOK(account, l)
		}
	})
}

func FuzzServerStructures(f *testing.F) {
	v := tv.Load(f)
	f.Add(tv.Hex(tv.Obj(v["auth"])["server_info"]))
	f.Add(tv.Hex(tv.Obj(v["setup"])["setup"]))
	for _, m := range tv.Arr(v["server_moves"]) {
		f.Add(tv.Hex(tv.Obj(m)["move"]))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if si, ok := identity.ParseServerInfo(b); ok && !bytes.Equal(si.Raw, b) {
			t.Fatal("server info")
		}
		if s, ok := identity.ParseSetup(b); ok && !bytes.Equal(identity.MakeSetup(s.URL, s.Key, s.RegToken, s.ExpiresAt), b) {
			t.Fatal("setup doesn't round-trip")
		}
		identity.ParseServerMove(b)
		identity.ParseCode("KFS0", "KFS0"+wire.EncodeB64u(b))
	})
}

// seeds collects certificates or bundles from the identities, as fuzzing seeds.
func seeds(f *testing.F, field string) [][]byte {
	var out [][]byte
	for _, p := range tv.Obj(tv.Load(f)["identities"]) {
		for _, d := range tv.Obj(tv.Obj(p)["devices"]) {
			switch x := tv.Obj(d)[field].(type) {
			case string:
				out = append(out, tv.Hex(x))
			case []any:
				for _, y := range x {
					out = append(out, tv.Hex(y))
				}
			}
		}
	}
	return out
}
