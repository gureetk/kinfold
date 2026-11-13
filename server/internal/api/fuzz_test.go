// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"testing"

	"github.com/gureetk/kinfold/server/internal/store"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// joinMessage reads the clear part of join requests and results.
func FuzzJoinMessage(f *testing.F) {
	id := bytes.Repeat([]byte{7}, 16)
	f.Add(wire.Concat([]byte{0}, id, make([]byte, 12), wire.Vec32(make([]byte, 40))), id)
	f.Add([]byte{0, 1, 2}, id)
	f.Fuzz(func(t *testing.T, raw, invite []byte) {
		if !joinMessage(raw, invite) {
			return
		}
		r := wire.NewReader(raw)
		if r.U8() != 0 || !bytes.Equal(r.Take(16), invite) || len(raw) < 1+16+12+4+16 {
			t.Fatal("accepted a message for another invite, or too short")
		}
	})
}

// linkMessageOK reads the clear part of link messages and responses.
func FuzzLinkMessage(f *testing.F) {
	id := bytes.Repeat([]byte{7}, 16)
	f.Add(wire.Concat([]byte{0}, id, []byte{3}, make([]byte, 12), wire.Vec32(make([]byte, 40))), uint8(3))
	f.Add(wire.Concat([]byte{0}, id, make([]byte, 155), make([]byte, 32), wire.Vec32([]byte{1}), make([]byte, 64)), uint8(0))
	f.Add([]byte{0, 1, 2}, uint8(1))
	dev := store.Device{ID: id, Account: id, DSK: make([]byte, 32)}
	f.Fuzz(func(t *testing.T, raw []byte, msgType uint8) {
		q := &request{dev: dev}
		if !linkMessageOK(raw, id, msgType%5, q) {
			return
		}
		r := wire.NewReader(raw)
		if r.U8() != 0 || !bytes.Equal(r.Take(16), id) {
			t.Fatal("accepted a message for another mailbox")
		}
		if msgType%5 == 0 {
			t.Fatal("accepted a response no key signed") // the device's key here is all zeros
		}
		if r.U8() != msgType%5 {
			t.Fatal("accepted a message of another type")
		}
	})
}
