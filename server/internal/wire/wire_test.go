// SPDX-License-Identifier: AGPL-3.0-or-later

package wire_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	tv "github.com/gureetk/kinfold/server/internal/testvec"
	"github.com/gureetk/kinfold/server/internal/wire"
)

func TestB64uVectors(t *testing.T) {
	for _, c := range tv.Arr(tv.Obj(tv.Load(t)["primitives"])["b64u"]) {
		want, text := tv.Hex(tv.Obj(c)["bytes"]), tv.Str(tv.Obj(c)["text"])
		got, err := wire.DecodeB64u(text)
		if err != nil || !bytes.Equal(got, want) || wire.EncodeB64u(want) != text {
			t.Errorf("b64u %q: got %x, %v", text, got, err)
		}
	}
}

func TestB64uRejects(t *testing.T) {
	for _, s := range []string{"AA==", "AA=", "A", "AB", "+/", "AA\n", "AAA\nA", " AA", "AA!"} {
		if _, err := wire.DecodeB64u(s); err == nil {
			t.Errorf("DecodeB64u(%q) accepted", s)
		}
	}
}

func TestPaddingVectors(t *testing.T) {
	p := tv.Obj(tv.Load(t)["padding"])
	for _, c := range tv.Arr(p["valid"]) {
		cc := tv.Obj(c)
		payload := bytes.Repeat(tv.Hex(cc["payload_byte"]), int(tv.Num(cc["payload_length"])))
		size := 0
		for _, b := range wire.Buckets {
			if b >= len(payload)+1 {
				size = b
				break
			}
		}
		padded := wire.PadTo(payload, size)
		sum := sha256.Sum256(padded)
		if size != int(tv.Num(cc["padded_length"])) || hex.EncodeToString(sum[:]) != tv.Str(cc["padded_sha256"]) {
			t.Errorf("pad %d bytes: bucket %d", len(payload), size)
		}
		if got, ok := wire.Unpad(padded, wire.Buckets...); !ok || !bytes.Equal(got, payload) {
			t.Errorf("unpad %d bytes", len(payload))
		}
	}
	for _, c := range tv.Arr(p["pad_to"]) {
		cc := tv.Obj(c)
		payload := bytes.Repeat(tv.Hex(cc["payload_byte"]), int(tv.Num(cc["payload_length"])))
		sum := sha256.Sum256(wire.PadTo(payload, int(tv.Num(cc["to"]))))
		if hex.EncodeToString(sum[:]) != tv.Str(cc["padded_sha256"]) {
			t.Errorf("pad_to %d/%d", len(payload), tv.Num(cc["to"]))
		}
	}
	for _, c := range tv.Arr(p["invalid"]) {
		if _, ok := wire.Unpad(tv.Hex(tv.Obj(c)["padded"]), wire.Buckets...); ok {
			t.Errorf("Unpad accepted: %s", tv.Str(tv.Obj(c)["description"]))
		}
	}
}

func TestReader(t *testing.T) {
	r := wire.NewReader([]byte{0, 1, 0, 0, 0, 2, 0xaa, 0xbb, 1})
	if r.U8() != 0 || r.U8() != 1 || !bytes.Equal(r.Vec32(), []byte{0xaa, 0xbb}) || !r.Flag() || !r.Done() {
		t.Fatal("reader misread its input")
	}
	r = wire.NewReader([]byte{2})
	if r.Flag(); r.Done() {
		t.Fatal("a flag of 2 was accepted")
	}
	r = wire.NewReader([]byte{0xff, 0xff, 0xff, 0xff})
	if v := r.Vec32(); v != nil || r.Done() {
		t.Fatal("a length past the end was accepted")
	}
	r = wire.NewReader([]byte{1, 2})
	if r.U8(); r.Done() {
		t.Fatal("leftover bytes were accepted")
	}
}

func TestFrames(t *testing.T) {
	var body []byte
	for _, f := range [][]byte{{1}, {}, bytes.Repeat([]byte{7}, 300)} {
		body = wire.AppendFrame(body, f)
	}
	fs, err := wire.Frames(body, 3, 300)
	if err != nil || len(fs) != 3 || len(fs[2]) != 300 {
		t.Fatalf("frames: %v %v", fs, err)
	}
	for _, bad := range []struct {
		body          []byte
		max, maxFrame int
	}{{body, 2, 300}, {body, 3, 299}, {body[:len(body)-1], 3, 300}, {[]byte{0, 0, 0}, 3, 300}} {
		if _, err := wire.Frames(bad.body, bad.max, bad.maxFrame); err == nil {
			t.Errorf("Frames accepted %x (max %d, %d)", bad.body, bad.max, bad.maxFrame)
		}
	}
}

func FuzzDecodeB64u(f *testing.F) {
	for _, s := range []string{"", "AA", "AAA", "AAAA", "_-_-", "AB", "A=="} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		b, err := wire.DecodeB64u(s)
		if err == nil && wire.EncodeB64u(b) != s {
			t.Fatalf("accepted a non-canonical encoding %q", s)
		}
	})
}

func FuzzFrames(f *testing.F) {
	f.Add(wire.AppendFrame(wire.AppendFrame(nil, []byte("ab")), nil))
	f.Add([]byte{0, 0, 0, 9, 1})
	f.Fuzz(func(t *testing.T, body []byte) {
		fs, err := wire.Frames(body, 64, 1024)
		if err != nil {
			return
		}
		var again []byte
		for _, fr := range fs {
			again = wire.AppendFrame(again, fr)
		}
		if !bytes.Equal(again, body) {
			t.Fatal("frames don't round-trip")
		}
	})
}

func FuzzUnpad(f *testing.F) {
	f.Add([]byte{1, 2, 0x80, 0, 0})
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, x []byte) {
		p, ok := wire.Unpad(x, len(x))
		if ok && !bytes.Equal(wire.PadTo(p, len(x)), x) {
			t.Fatal("Unpad accepted what PadTo wouldn't produce")
		}
	})
}
