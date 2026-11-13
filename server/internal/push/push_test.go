// SPDX-License-Identifier: AGPL-3.0-or-later

package push_test

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/kcrypto"
	"github.com/gureetk/kinfold/server/internal/push"
	tv "github.com/gureetk/kinfold/server/internal/testvec"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// open is what a device does with a sealed push, up to the signature check.
func open(t *testing.T, sealed, deviceID []byte, keys tv.V) []byte {
	t.Helper()
	if len(sealed) != push.SealedLen {
		t.Fatalf("sealed push is %d bytes", len(sealed))
	}
	kid, enc, ct := sealed[:8], sealed[8:40], sealed[40:]
	sk, ok := keys[string(hexOf(kid))]
	if !ok {
		t.Fatalf("no key %x", kid)
	}
	padded, err := kcrypto.Open(enc, tv.Hex(sk), push.Info(deviceID, kid), ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	p, ok := wire.Unpad(padded, push.PlainLen)
	if !ok {
		t.Fatal("unpad")
	}
	return p
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, x := range b {
		out[2*i], out[2*i+1] = digits[x>>4], digits[x&15]
	}
	return string(out)
}

func TestPushVectors(t *testing.T) {
	v := tv.Load(t)
	pu := tv.Obj(v["push"])
	server := ed25519.NewKeyFromSeed(tv.Hex(tv.Obj(v["auth"])["server_seed"]))
	if !bytes.Equal(server.Public().(ed25519.PublicKey), tv.Hex(pu["server_key"])) {
		t.Fatal("server key")
	}
	for _, c := range tv.Arr(pu["valid"]) {
		cc := tv.Obj(c)
		did := tv.Hex(cc["device_id"])
		p, err := push.Build(server, did, uint8(tv.Num(cc["type"])), tv.Num(cc["sent_at"]), tv.Hex(cc["body"]))
		if err != nil || !bytes.Equal(p, tv.Hex(cc["push"])) {
			t.Errorf("%s: Build doesn't rebuild the push: %v", tv.Str(cc["name"]), err)
			continue
		}
		// The vector's sealed push opens with the standard library ...
		if got := open(t, tv.Hex(cc["sealed"]), did, tv.Obj(cc["keys"])); !bytes.Equal(got, p) {
			t.Errorf("%s: the vector's sealed push", tv.Str(cc["name"]))
		}
		// ... and a push sealed here opens to the same bytes. Go can't fix the ephemeral key,
		// so this replaces the byte-exact rebuild, which vectors/README.md makes optional.
		dek := deviceKey(t, v, tv.Str(cc["device"]), tv.Hex(cc["sealed"])[:8])
		sealed, err := push.Seal(p, did, dek)
		if err != nil || !bytes.Equal(sealed[:8], tv.Hex(cc["sealed"])[:8]) {
			t.Fatalf("%s: Seal: %v", tv.Str(cc["name"]), err)
		}
		if got := open(t, sealed, did, tv.Obj(cc["keys"])); !bytes.Equal(got, p) {
			t.Errorf("%s: a push sealed here", tv.Str(cc["name"]))
		}
	}
	rl := tv.Obj(pu["relay"])
	for d := uint8(push.Alert); d <= push.Location; d++ {
		sig := push.RelaySig(server, tv.Hex(rl["capability"]), tv.Hex(rl["sealed"]), tv.Num(rl["sent_at"]), d)
		if bytes.Equal(sig, tv.Hex(rl["sig"])) != (uint64(d) == tv.Num(rl["delivery"])) {
			t.Errorf("relay signature, delivery %d", d)
		}
	}
}

// deviceKey finds the encryption key with this key ID among a device's keys.
func deviceKey(t *testing.T, v tv.V, label string, kid []byte) []byte {
	for _, p := range tv.Obj(v["identities"]) {
		for _, d := range tv.Obj(tv.Obj(p)["devices"]) {
			if tv.Str(tv.Obj(d)["label"]) != label {
				continue
			}
			for _, k := range tv.Arr(tv.Obj(d)["deks"]) {
				if pub := tv.Hex(tv.Obj(k)["pub"]); bytes.Equal(identity.KeyID(pub), kid) {
					return pub
				}
			}
		}
	}
	t.Fatalf("no key %x for %s", kid, label)
	return nil
}

func TestBuildRefusesBodiesThatDontFit(t *testing.T) {
	server := ed25519.NewKeyFromSeed(make([]byte, 32))
	did := make([]byte, 16)
	for _, c := range []struct {
		ptype uint8
		body  []byte
	}{
		{push.Wake, []byte{1}},
		{push.Records, nil},
		{push.Silence, make([]byte, 39)},
		{4, nil},
		{push.Records, make([]byte, push.MaxBody+1)},
	} {
		if _, err := push.Build(server, did, c.ptype, 0, c.body); err == nil {
			t.Errorf("type %d with a %d-byte body was built", c.ptype, len(c.body))
		}
	}
	if _, err := push.Build(server, did, push.Records, 0, make([]byte, push.MaxBody)); err != nil {
		t.Error("the largest records body was refused")
	}
	body := push.RecordsBody([][]byte{push.Record(7, []byte("envelope"))})
	if !bytes.Equal(body, wire.Concat(wire.U32(16), wire.U64(7), []byte("envelope"))) {
		t.Error("records body layout")
	}
	if len(push.SilenceBody(make([]byte, 16), make([]byte, 16), 1)) != 40 {
		t.Error("silence body length")
	}
}
