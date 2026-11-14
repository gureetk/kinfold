// SPDX-License-Identifier: AGPL-3.0-or-later

package qr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type fixtures struct {
	Generator string
	All       []struct {
		Version, Length, Mask int
		Level, SHA256         string
	}
	Auto []struct {
		Version, Length, Mask int
		Level, SHA256         string
		Rows                  []string
		Scores                [8][4]int
	}
}

var levels = map[string]Level{"L": L, "M": M, "Q": Q, "H": H}

func load(t *testing.T) fixtures {
	b, err := os.ReadFile("testdata/segno.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixtures
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func rows(c *Code) []string {
	out := make([]string, c.Size)
	for y := range c.Size {
		var b strings.Builder
		for x := range c.Size {
			if c.Dark(x, y) {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
		out[y] = b.String()
	}
	return out
}

// Every version at every level, filled to capacity with a fixed mask, matches what segno
// drew module for module: the capacity tables, the blocks and their Reed–Solomon codewords,
// the function patterns, the version and format information, the placement and the masks.
func TestEveryVersionAndLevel(t *testing.T) {
	f := load(t)
	if len(f.All) != 160 {
		t.Fatalf("%d codes from %s", len(f.All), f.Generator)
	}
	for _, c := range f.All {
		lv := levels[c.Level]
		if n := Capacity(c.Version, lv); n != c.Length {
			t.Errorf("version %d-%s holds %d bytes, not %d", c.Version, c.Level, n, c.Length)
			continue
		}
		data := make([]byte, c.Length)
		for i := range data {
			data[i] = byte((31*i + 7*c.Version + int(lv)) % 256)
		}
		code, err := encode(data, lv, c.Version, c.Mask)
		if err != nil || code.Version != c.Version || code.Mask != c.Mask || code.Size != 17+4*c.Version {
			t.Errorf("version %d-%s: %v", c.Version, c.Level, err)
			continue
		}
		if sum := sha256.Sum256([]byte(strings.Join(rows(code), "\n"))); hex.EncodeToString(sum[:]) != c.SHA256 {
			t.Errorf("version %d-%s with mask %d differs from %s", c.Version, c.Level, c.Mask, f.Generator)
		}
	}
}

// Left to choose, Encode picks the smallest version that holds the data, and the mask that
// segno picked by the standard's penalty rules.
func TestChosenVersionAndMask(t *testing.T) {
	f := load(t)
	for _, c := range f.Auto {
		lv := levels[c.Level]
		data := make([]byte, c.Length)
		for i := range data {
			data[i] = byte((17*i + 3) % 256)
		}
		code, err := Encode(data, lv)
		if err != nil {
			t.Fatal(err)
		}
		// Each mask scores as segno scores it, rule by rule.
		u, err := unmasked(data, lv, 1)
		if err != nil {
			t.Fatal(err)
		}
		for m := range 8 {
			u.applyMask(m)
			if got := u.scores(); got != c.Scores[m] {
				t.Errorf("version %d-%s, mask %d: scores %v, want %v", c.Version, c.Level, m, got, c.Scores[m])
			}
			u.applyMask(m)
		}
		if code.Version != c.Version || code.Mask != c.Mask {
			t.Errorf("%d bytes at %s: version %d mask %d, want version %d mask %d", c.Length, c.Level, code.Version,
				code.Mask, c.Version, c.Mask)
			continue
		}
		got := rows(code)
		if sum := sha256.Sum256([]byte(strings.Join(got, "\n"))); hex.EncodeToString(sum[:]) != c.SHA256 {
			t.Errorf("version %d-%s differs from %s", c.Version, c.Level, f.Generator)
		}
		for y, row := range c.Rows {
			if got[y] != row {
				t.Errorf("version %d-%s, row %d:\n got %s\nwant %s", c.Version, c.Level, y, got[y], row)
				break
			}
		}
	}
}

// The segment of byte mode, worked by hand from ISO/IEC 18004:2015, 7.4: mode 0100, a count of
// 5 in 8 bits, "hello", the 4-bit terminator, which ends on a byte, then pad codewords from
// 0xEC on to the 16 that version 1-M holds.
func TestDataCodewords(t *testing.T) {
	got := hex.EncodeToString(dataCodewords([]byte("hello"), 1, M))
	if want := "40568656c6c6f0ec11ec11ec11ec11ec"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	// From version 10 the count takes 16 bits.
	if got := hex.EncodeToString(dataCodewords([]byte("hi"), 10, H)[:5]); got != "4000268690" {
		t.Errorf("version 10: got %s", got)
	}
}

// The finder-like rule, line by line, as segno applies it.
func TestFinderLike(t *testing.T) {
	for _, c := range []struct {
		line string
		want int
	}{
		{"1011101", 40}, // the edges count as light
		{"00001011101", 40},
		{"10111010000", 40},
		{"0001011101000", 40},       // three light modules, then the edge
		{"100010111010001", 0},      // three light modules each side, then dark
		{"11011101011", 0},          // dark on both sides
		{"0000101110111010000", 40}, // two that overlap score once
		{"00001011101000010111010000", 80},
		{"1011101" + "0000" + "1011101", 80},
		{"110111011" + "0000" + "11011101011", 0},
	} {
		l := make([]bool, len(c.line))
		for i, m := range c.line {
			l[i] = m == '1'
		}
		if got := finderLike(l); got != c.want {
			t.Errorf("%s: %d, want %d", c.line, got, c.want)
		}
	}
}

func TestTooLong(t *testing.T) {
	if _, err := Encode(make([]byte, Capacity(40, H)), H); err != nil {
		t.Errorf("the most a code holds at H: %v", err)
	}
	if _, err := Encode(make([]byte, Capacity(40, H)+1), H); !errors.Is(err, ErrTooLong) {
		t.Errorf("one byte more: %v", err)
	}
}

// The terminal drawing has the quiet zone, two rows to a line, and its own colours.
func TestTerminal(t *testing.T) {
	code, err := Encode([]byte("hello"), M)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(code.Terminal(), "\n"), "\n")
	if n := (code.Size + 8 + 1) / 2; len(lines) != n {
		t.Fatalf("%d lines, want %d", len(lines), n)
	}
	for i, l := range lines {
		if !strings.HasPrefix(l, "\x1b[30;47m") || !strings.HasSuffix(l, "\x1b[0m") {
			t.Fatalf("line %d doesn't set its colours: %q", i, l)
		}
		if cells := []rune(strings.TrimSuffix(strings.TrimPrefix(l, "\x1b[30;47m"), "\x1b[0m")); len(cells) != code.Size+8 {
			t.Fatalf("line %d is %d cells wide", i, len(cells))
		}
	}
	if lines[0] != "\x1b[30;47m"+strings.Repeat(" ", code.Size+8)+"\x1b[0m" {
		t.Error("the quiet zone above the code isn't light")
	}
	// Rows 4 and 5 of the drawing are the code's first two. Across the top-left finder, the
	// first is dark and the second dark only at its ends.
	if got := string([]rune(strings.TrimPrefix(lines[2], "\x1b[30;47m"))[4:11]); got != "█▀▀▀▀▀█" {
		t.Errorf("the top-left finder: %q", got)
	}
}
