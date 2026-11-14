// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"testing"

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
