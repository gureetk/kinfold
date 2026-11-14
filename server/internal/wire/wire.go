// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wire reads and writes the byte layouts of PROTOCOL.md §2: big-endian integers,
// length-prefixed vectors, strict base64url, the u32-length frames of API.md §1, and the
// padding of §7.4.
package wire

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
)

// ErrMalformed is the reason code `malformed`: input that ends early, a length that runs
// past the end, a flag other than 0 or 1, or bytes left over (§2).
var ErrMalformed = errors.New("malformed")

// Reader reads one structure. After the first failure every read returns zero values
// and Done reports false, so a parser can read every field and check once at the end.
type Reader struct {
	b   []byte
	p   int
	bad bool
}

// NewReader returns a Reader over b. Slices it returns alias b.
func NewReader(b []byte) *Reader { return &Reader{b: b} }

// Take returns the next n bytes. On failure it returns n zero bytes when n is at most 64,
// so that fixed-size fields can be indexed safely, and nil for anything longer; it never
// allocates a length read from the input.
func (r *Reader) Take(n int) []byte {
	if r.bad || n < 0 || n > len(r.b)-r.p {
		r.bad = true
		if n >= 0 && n <= 64 {
			return make([]byte, n)
		}
		return nil
	}
	s := r.b[r.p : r.p+n : r.p+n]
	r.p += n
	return s
}

func (r *Reader) U8() uint8   { return r.Take(1)[0] }
func (r *Reader) U16() uint16 { return binary.BigEndian.Uint16(r.Take(2)) }
func (r *Reader) U32() uint32 { return binary.BigEndian.Uint32(r.Take(4)) }
func (r *Reader) U64() uint64 { return binary.BigEndian.Uint64(r.Take(8)) }

// Vec16 reads a u16 length and that many bytes.
func (r *Reader) Vec16() []byte { return r.Take(int(r.U16())) }

// Vec32 reads a u32 length and that many bytes.
func (r *Reader) Vec32() []byte { return r.Take(int(r.U32())) }

// Flag reads a u8 that must be 0 or 1.
func (r *Reader) Flag() bool {
	v := r.U8()
	if v > 1 {
		r.bad = true
	}
	return v == 1
}

// Pos is the number of bytes read so far.
func (r *Reader) Pos() int { return r.p }

// Bytes is the whole input.
func (r *Reader) Bytes() []byte { return r.b }

// Fail marks the input as malformed.
func (r *Reader) Fail() { r.bad = true }

// Done reports whether every read succeeded and the input is used up.
func (r *Reader) Done() bool { return !r.bad && r.p == len(r.b) }

// Failed reports whether a read has failed.
func (r *Reader) Failed() bool { return r.bad }

// ---- writing ----

func U16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func U32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func U64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// Vec16 returns b with its u16 length in front. It panics if b is longer than 65,535 bytes,
// which only a programming error can cause.
func Vec16(b []byte) []byte {
	if len(b) > 0xffff {
		panic("wire: vec16 too long")
	}
	return append(U16(uint16(len(b))), b...)
}

// Vec32 returns b with its u32 length in front.
func Vec32(b []byte) []byte {
	if uint64(len(b)) > 0xffffffff {
		panic("wire: vec32 too long")
	}
	return append(U32(uint32(len(b))), b...)
}

// Concat joins byte strings.
func Concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ---- base64url (§2) ----

var b64 = base64.RawURLEncoding.Strict()

// EncodeB64u is unpadded base64url.
func EncodeB64u(b []byte) string { return b64.EncodeToString(b) }

// DecodeB64u decodes unpadded base64url and rejects padding, characters outside the
// alphabet, and any input whose re-encoding differs (§2). Go's decoder skips newlines,
// which the re-encoding check also catches.
func DecodeB64u(s string) ([]byte, error) {
	out, err := b64.DecodeString(s)
	if err != nil || b64.EncodeToString(out) != s {
		return nil, ErrMalformed
	}
	return out, nil
}

// ---- frames (API.md §1) ----

// AppendFrame appends a u32 length and the frame.
func AppendFrame(b, frame []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(frame)))
	return append(b, frame...)
}

// Frames splits a body into frames. It fails on a truncated frame, on more than max
// frames, and on a frame longer than maxFrame.
func Frames(body []byte, max, maxFrame int) ([][]byte, error) {
	var out [][]byte
	r := NewReader(body)
	for r.Pos() < len(body) {
		f := r.Vec32()
		if r.Failed() || len(f) > maxFrame || len(out) == max {
			return nil, ErrMalformed
		}
		out = append(out, f)
	}
	return out, nil
}

// ---- padding (§7.4) ----

// Buckets are the padded sizes of envelope payloads and share updates.
var Buckets = []int{256, 512, 1024, 2048, 4096, 8192, 16384, 65536}

// PadTo appends 0x80 and zero bytes to p, to exactly n bytes; p must be shorter than n.
func PadTo(p []byte, n int) []byte {
	if len(p) >= n {
		panic("wire: PadTo input too long")
	}
	out := make([]byte, n)
	copy(out, p)
	out[len(p)] = 0x80
	return out
}

// Unpad checks that x has one of the allowed sizes (§7.4: a bucket size for envelopes,
// 512 for log details, 2,560 for pushes), then strips trailing zero bytes and the 0x80
// before them.
func Unpad(x []byte, sizes ...int) ([]byte, bool) {
	sized := false
	for _, n := range sizes {
		sized = sized || len(x) == n
	}
	if !sized {
		return nil, false
	}
	i := len(x) - 1
	for i >= 0 && x[i] == 0 {
		i--
	}
	if i < 0 || x[i] != 0x80 {
		return nil, false
	}
	return x[:i], true
}
