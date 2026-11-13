// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tilestest builds map archives for tests.
package tilestest

import (
	"crypto/rand"
	"encoding/binary"
	"math"
)

// Archive builds a PMTiles version 3 archive that the server's checks accept: a 127-byte
// header, a 16-byte root directory, "{}" as metadata, no leaf directories and random tile
// data, body bytes in all after the header.
func Archive(minZ, maxZ uint8, bounds [4]float64, body int) []byte {
	const headerLen = 127
	b := make([]byte, headerLen+body)
	rand.Read(b[headerLen:])
	copy(b, "PMTiles")
	b[7] = 3
	put := func(at int, v uint64) { binary.LittleEndian.PutUint64(b[at:], v) }
	root, rootLen := uint64(headerLen), uint64(16)
	put(0x08, root)
	put(0x10, rootLen)
	put(0x18, root+rootLen)
	put(0x20, 2)
	put(0x28, root+rootLen+2)
	put(0x38, root+rootLen+2)
	put(0x40, uint64(body)-rootLen-2)
	b[0x64], b[0x65] = minZ, maxZ
	for i, d := range bounds {
		binary.LittleEndian.PutUint32(b[0x66+4*i:], uint32(int32(math.Round(d*1e7))))
	}
	copy(b[root+rootLen:], "{}")
	return b
}
