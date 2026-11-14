// SPDX-License-Identifier: AGPL-3.0-or-later

// Package qr makes QR codes (ISO/IEC 18004) in byte mode, so that the command line can show
// a setup code (PROTOCOL.md §13.1) as one. It is written from the standard rather than taken
// as a dependency, and its tests hold it to matrices that another implementation drew for
// every version and level (testdata).
package qr

import (
	"errors"
	"math"
	"strings"
)

// Level is an error correction level: L restores about 7% of a code, M 15%, Q 25% and H 30%.
type Level int

const (
	L Level = iota
	M
	Q
	H
)

// formatLevel is what each level writes in the format information.
var formatLevel = [4]int{1, 0, 3, 2}

// eccPerBlock and blocks give, for each level and version, the error correction codewords
// in each block and the number of blocks (ISO/IEC 18004, table 9). Index 0 is unused.
var eccPerBlock = [4][41]int{
	{0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	{0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},
	{0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	{0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
}

var blocks = [4][41]int{
	{0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},
	{0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},
	{0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},
	{0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81},
}

// ErrTooLong is returned for data that no QR code holds at the level asked for.
var ErrTooLong = errors.New("qr: too much data for a QR code at this level")

// Code is a QR code, Size modules on a side.
type Code struct {
	Version int // 1 to 40
	Level   Level
	Mask    int // 0 to 7
	Size    int // 17 + 4 × Version
	dark    []bool
	fn      []bool // function patterns, which the data and the mask leave alone
}

// Dark reports whether the module in column x of row y is dark.
func (c *Code) Dark(x, y int) bool { return c.dark[y*c.Size+x] }

// Encode makes the smallest QR code that holds data in byte mode at the level, with the mask
// that the standard's penalty rules choose.
func Encode(data []byte, level Level) (*Code, error) { return encode(data, level, 1, -1) }

// encode is Encode starting from a version, and with a fixed mask unless mask is -1.
func encode(data []byte, level Level, version, mask int) (*Code, error) {
	c, err := unmasked(data, level, version)
	if err != nil {
		return nil, err
	}
	if mask < 0 {
		// Each mask is judged with the format and version information still light, as the
		// standard says (ISO/IEC 18004:2015, 7.8): the lowest score wins, the first on a tie.
		least := -1
		for m := range 8 {
			c.applyMask(m)
			if p := c.penalty(); least < 0 || p < least {
				least, mask = p, m
			}
			c.applyMask(m) // a mask undoes itself
		}
	}
	c.Mask = mask
	c.applyMask(mask)
	c.drawFormat(mask, false)
	c.drawVersion(false)
	return c, nil
}

// unmasked lays out the smallest code from the version up that holds the data: the function
// patterns, with the format and version information reserved and light, and the codewords.
func unmasked(data []byte, level Level, version int) (*Code, error) {
	for ; version <= 40 && len(data) > Capacity(version, level); version++ {
	}
	if version > 40 {
		return nil, ErrTooLong
	}
	c := &Code{Version: version, Level: level, Size: 17 + 4*version}
	c.dark, c.fn = make([]bool, c.Size*c.Size), make([]bool, c.Size*c.Size)
	c.drawFunctionPatterns()
	c.placeData(interleave(dataCodewords(data, version, level), version, level))
	return c, nil
}

// rawDataModules is how many modules of a version hold codewords, remainder bits included.
func rawDataModules(version int) int {
	n := (16*version+128)*version + 64
	if version >= 2 {
		align := version/7 + 2
		n -= (25*align-10)*align - 55
		if version >= 7 {
			n -= 36
		}
	}
	return n
}

func dataLen(version int, level Level) int {
	return rawDataModules(version)/8 - eccPerBlock[level][version]*blocks[level][version]
}

func countBits(version int) int {
	if version <= 9 {
		return 8
	}
	return 16
}

// Capacity is how many bytes a version holds at a level in byte mode.
func Capacity(version int, level Level) int {
	return (dataLen(version, level)*8 - 4 - countBits(version)) / 8
}

// dataCodewords is the byte-mode segment: mode 0100, the count, the bytes, up to four zero
// bits as a terminator, zeros to the byte, then the pad bytes 0xEC and 0x11 in turn.
func dataCodewords(data []byte, version int, level Level) []byte {
	var bits []bool
	put := func(v, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, v>>i&1 == 1)
		}
	}
	put(0b0100, 4)
	put(len(data), countBits(version))
	for _, b := range data {
		put(int(b), 8)
	}
	room := dataLen(version, level) * 8
	put(0, min(4, room-len(bits)))
	put(0, (8-len(bits)%8)%8)
	out := make([]byte, 0, room/8)
	for i := 0; i < len(bits); i += 8 {
		var b byte
		for _, bit := range bits[i : i+8] {
			b <<= 1
			if bit {
				b |= 1
			}
		}
		out = append(out, b)
	}
	for pad := byte(0xEC); len(out) < room/8; pad ^= 0xEC ^ 0x11 {
		out = append(out, pad)
	}
	return out
}

// interleave splits the data into blocks, adds each block's Reed–Solomon codewords, and
// reads the blocks out a codeword at a time: the data first, then the error correction.
func interleave(data []byte, version int, level Level) []byte {
	n, eccLen := blocks[level][version], eccPerBlock[level][version]
	raw := rawDataModules(version) / 8
	short, shortLen := n-raw%n, raw/n // short blocks hold one data codeword fewer
	divisor := rsDivisor(eccLen)
	var dataBlocks, eccBlocks [][]byte
	for i, k := 0, 0; i < n; i++ {
		l := shortLen - eccLen
		if i >= short {
			l++
		}
		dataBlocks = append(dataBlocks, data[k:k+l])
		eccBlocks = append(eccBlocks, rsRemainder(data[k:k+l], divisor))
		k += l
	}
	out := make([]byte, 0, raw)
	for i := 0; i <= shortLen-eccLen; i++ {
		for _, b := range dataBlocks {
			if i < len(b) {
				out = append(out, b[i])
			}
		}
	}
	for i := range eccLen {
		for _, b := range eccBlocks {
			out = append(out, b[i])
		}
	}
	return out
}

// gfMul multiplies in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1.
func gfMul(x, y byte) byte {
	z := 0
	for i := 7; i >= 0; i-- {
		z = z<<1 ^ (z>>7)*0x11D
		z ^= int(y>>i&1) * int(x)
	}
	return byte(z)
}

// rsDivisor is the generator polynomial of degree n, highest power first and its leading 1
// left out: the product of (x − 2^i) for i from 0 to n − 1.
func rsDivisor(n int) []byte {
	d := make([]byte, n)
	d[n-1] = 1
	root := byte(1)
	for range n {
		for j := range d {
			d[j] = gfMul(d[j], root)
			if j+1 < n {
				d[j] ^= d[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return d
}

// rsRemainder is the remainder of data, times x^len(divisor), divided by the generator.
func rsRemainder(data, divisor []byte) []byte {
	r := make([]byte, len(divisor))
	for _, b := range data {
		f := b ^ r[0]
		copy(r, r[1:])
		r[len(r)-1] = 0
		for i := range r {
			r[i] ^= gfMul(divisor[i], f)
		}
	}
	return r
}

func (c *Code) setFn(x, y int, dark bool) {
	c.dark[y*c.Size+x], c.fn[y*c.Size+x] = dark, true
}

// drawFunctionPatterns draws the timing patterns, the three finders with their separators
// and the alignment patterns, and reserves the format and version information, light.
func (c *Code) drawFunctionPatterns() {
	for i := range c.Size {
		c.setFn(6, i, i%2 == 0)
		c.setFn(i, 6, i%2 == 0)
	}
	for _, at := range [][2]int{{3, 3}, {c.Size - 4, 3}, {3, c.Size - 4}} {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := at[0]+dx, at[1]+dy
				if d := max(abs(dx), abs(dy)); x >= 0 && y >= 0 && x < c.Size && y < c.Size {
					c.setFn(x, y, d != 2 && d != 4)
				}
			}
		}
	}
	pos := alignmentPositions(c.Version)
	last := len(pos) - 1
	for i, y := range pos {
		for j, x := range pos {
			if (i == 0 && j == 0) || (i == 0 && j == last) || (i == last && j == 0) {
				continue // the finders are there
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					c.setFn(x+dx, y+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	c.drawFormat(0, true)
	c.drawVersion(true)
}

// alignmentPositions are the rows, and the columns, that alignment patterns centre on.
func alignmentPositions(version int) []int {
	if version == 1 {
		return nil
	}
	n := version/7 + 2
	step := (version*8 + n*3 + 5) / (n*4 - 4) * 2
	pos := make([]int, n)
	pos[0] = 6
	for i, p := n-1, 17+4*version-7; i >= 1; i, p = i-1, p-step {
		pos[i] = p
	}
	return pos
}

// drawFormat writes the level and the mask, with their BCH code, in both places, and the
// module that is always dark; or, to reserve them, leaves them all light.
func (c *Code) drawFormat(mask int, reserve bool) {
	data := formatLevel[c.Level]<<3 | mask
	r := data
	for range 10 {
		r = r<<1 ^ (r>>9)*0x537
	}
	bits := (data<<10 | r) ^ 0x5412
	bit := func(i int) bool { return !reserve && bits>>i&1 == 1 }
	for i := 0; i <= 5; i++ {
		c.setFn(8, i, bit(i))
	}
	c.setFn(8, 7, bit(6))
	c.setFn(8, 8, bit(7))
	c.setFn(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		c.setFn(14-i, 8, bit(i))
	}
	for i := range 8 {
		c.setFn(c.Size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		c.setFn(8, c.Size-15+i, bit(i))
	}
	c.setFn(8, c.Size-8, !reserve)
}

// drawVersion writes the version with its Golay code in both corners, from version 7; or, to
// reserve them, leaves them light.
func (c *Code) drawVersion(reserve bool) {
	if c.Version < 7 {
		return
	}
	r := c.Version
	for range 12 {
		r = r<<1 ^ (r>>11)*0x1F25
	}
	bits := c.Version<<12 | r
	for i := range 18 {
		dark := !reserve && bits>>i&1 == 1
		a, b := c.Size-11+i%3, i/3
		c.setFn(a, b, dark)
		c.setFn(b, a, dark)
	}
}

// placeData lays the codewords out in two-module columns from the bottom right, up and down
// in turn, skipping the function patterns and the vertical timing pattern.
func (c *Code) placeData(codewords []byte) {
	i := 0
	for right := c.Size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := range c.Size {
			for j := range 2 {
				x, y := right-j, vert
				if (right+1)&2 == 0 {
					y = c.Size - 1 - vert
				}
				if !c.fn[y*c.Size+x] && i < len(codewords)*8 {
					c.dark[y*c.Size+x] = codewords[i>>3]>>(7-i&7)&1 == 1
					i++
				}
			}
		}
	}
}

// applyMask flips the data modules where the mask's condition holds.
func (c *Code) applyMask(mask int) {
	for y := range c.Size {
		for x := range c.Size {
			var flip bool
			switch mask {
			case 0:
				flip = (x+y)%2 == 0
			case 1:
				flip = y%2 == 0
			case 2:
				flip = x%3 == 0
			case 3:
				flip = (x+y)%3 == 0
			case 4:
				flip = (x/3+y/2)%2 == 0
			case 5:
				flip = x*y%2+x*y%3 == 0
			case 6:
				flip = (x*y%2+x*y%3)%2 == 0
			case 7:
				flip = ((x+y)%2+x*y%3)%2 == 0
			}
			if flip && !c.fn[y*c.Size+x] {
				c.dark[y*c.Size+x] = !c.dark[y*c.Size+x]
			}
		}
	}
}

// penalty scores a masked code by the four rules of ISO/IEC 18004:2015, 7.8.3, read as segno
// reads them, so that both choose the same mask: 3 for a run of five modules alike and 1 more
// for each module past five, in rows and columns; 3 for each 2×2 block alike; 40 for each
// dark-light-dark-dark-dark-light-dark pattern with four light modules, or the edge, on one
// side; and 10 for each 5% the dark modules are from half.
func (c *Code) penalty() int {
	s := c.scores()
	return s[0] + s[1] + s[2] + s[3]
}

// scores are the four rules' scores, apart.
func (c *Code) scores() (s [4]int) {
	line := make([]bool, c.Size)
	for i := range c.Size {
		for _, across := range []bool{true, false} {
			for j := range c.Size {
				if across {
					line[j] = c.Dark(j, i)
				} else {
					line[j] = c.Dark(i, j)
				}
			}
			s[0] += runs(line)
			s[2] += finderLike(line)
		}
	}
	dark := 0
	for y := range c.Size {
		for x := range c.Size {
			d := c.Dark(x, y)
			if d {
				dark++
			}
			if x > 0 && y > 0 && d == c.Dark(x-1, y) && d == c.Dark(x, y-1) && d == c.Dark(x-1, y-1) {
				s[1] += 3
			}
		}
	}
	share := float64(dark) / float64(c.Size*c.Size)
	s[3] = 10 * int(math.Abs(share*100-50)/5)
	return s
}

// runs scores the runs of five or more modules alike in a line.
func runs(line []bool) int {
	score, run := 0, 1
	for j := 1; j <= len(line); j++ {
		if j < len(line) && line[j] == line[j-1] {
			run++
			continue
		}
		if run >= 5 {
			score += run - 2
		}
		run = 1
	}
	return score
}

var finder = []bool{true, false, true, true, true, false, true}

// finderLike scores the patterns in a line that look like the middle of a finder, with four
// light modules before or after them; the edge of the code counts as light. A pattern that
// scores is skipped whole, so two that overlap score once.
func finderLike(line []bool) int {
	light := func(part []bool) bool {
		for _, d := range part {
			if d {
				return false
			}
		}
		return true
	}
	score, n := 0, len(line)
	for i := 0; i+7 <= n; i++ {
		match := true
		for k, d := range finder {
			match = match && line[i+k] == d
		}
		if match && (light(line[max(i-4, 0):i]) || light(line[i+7:min(i+11, n)])) {
			score += 40
			i += 6
		}
	}
	return score
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Terminal draws the code for a terminal, two rows of modules to a line, inside the quiet
// zone of four light modules that scanners need. It sets black on white itself, so the code
// reads the same way on dark and light terminals.
func (c *Code) Terminal() string {
	const quiet = 4
	n := c.Size + 2*quiet
	dark := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		return x >= 0 && y >= 0 && x < c.Size && y < c.Size && c.Dark(x, y)
	}
	var b strings.Builder
	for y := 0; y < n; y += 2 {
		b.WriteString("\x1b[30;47m")
		for x := range n {
			switch top, bottom := dark(x, y), dark(x, y+1); {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\x1b[0m\n")
	}
	return b.String()
}
