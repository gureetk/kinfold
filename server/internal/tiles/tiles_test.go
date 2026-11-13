// SPDX-License-Identifier: AGPL-3.0-or-later

package tiles

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gureetk/kinfold/server/internal/tiles/tilestest"
)

var Archive = tilestest.Archive

var bc = [4]float64{-139.1, 48.2, -114.0, 60.0}

func TestParseHeader(t *testing.T) {
	a := Archive(0, 15, bc, 4096)
	h, err := ParseHeader(a, int64(len(a)))
	if err != nil || h.MinZoom != 0 || h.MaxZoom != 15 || h.Bounds != bc {
		t.Fatalf("%+v %v", h, err)
	}
	bad := map[string]func(b []byte) int64{
		"magic":         func(b []byte) int64 { b[0] = 'p'; return int64(len(b)) },
		"version 2":     func(b []byte) int64 { b[7] = 2; return int64(len(b)) },
		"short file":    func(b []byte) int64 { return 100 },
		"truncated":     func(b []byte) int64 { return int64(len(b)) - 1 },
		"no root":       func(b []byte) int64 { binary.LittleEndian.PutUint64(b[0x10:], 0); return int64(len(b)) },
		"root in data":  func(b []byte) int64 { binary.LittleEndian.PutUint64(b[0x08:], 16384); return 20000 },
		"in the header": func(b []byte) int64 { binary.LittleEndian.PutUint64(b[0x18:], 100); return int64(len(b)) },
		"huge length":   func(b []byte) int64 { binary.LittleEndian.PutUint64(b[0x40:], math.MaxUint64); return int64(len(b)) },
		"zooms":         func(b []byte) int64 { b[0x64] = 16; return int64(len(b)) },
		"zoom 31":       func(b []byte) int64 { b[0x65] = 31; return int64(len(b)) },
		"west of east":  func(b []byte) int64 { copy(b[0x66:0x6A], b[0x6E:0x72]); return int64(len(b)) },
		"north pole": func(b []byte) int64 {
			binary.LittleEndian.PutUint32(b[0x72:], uint32(int32(910_000_000)))
			return int64(len(b))
		},
	}
	for name, f := range bad {
		b := slices.Clone(a)
		if _, err := ParseHeader(b, f(b)); !errors.Is(err, ErrNotPMTiles) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseHeader(a[:HeaderLen-1], int64(len(a))); !errors.Is(err, ErrNotPMTiles) {
		t.Error("a short header")
	}
}

func FuzzParseHeader(f *testing.F) {
	a := Archive(0, 15, bc, 64)
	f.Add(a[:HeaderLen], int64(len(a)))
	f.Fuzz(func(t *testing.T, b []byte, size int64) {
		h, err := ParseHeader(b, size)
		if err != nil {
			return
		}
		if h.MinZoom > h.MaxZoom || h.Bounds[0] >= h.Bounds[2] || h.Bounds[1] >= h.Bounds[3] || size < HeaderLen {
			t.Fatalf("accepted %+v", h)
		}
	})
}

func writeFile(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "region.pmtiles")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// stored lists the files in the library's directory.
func stored(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func sumOf(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestLibrary(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tiles")
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Regions()) != 0 {
		t.Fatal("a new library has regions")
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A region is copied in under its hash; the operator's file can go.
	a := Archive(0, 15, bc, 8192)
	src := writeFile(t, a)
	r, err := l.Add("bc", "British Columbia", src, 1000)
	if err != nil {
		t.Fatal(err)
	}
	want := Region{ID: "bc", Name: "British Columbia", Bounds: bc, MaxZoom: 15, Size: int64(len(a)), SHA256: sumOf(a), UpdatedAt: 1000}
	if r != want {
		t.Fatalf("%+v", r)
	}
	os.Remove(src)
	if got, ok := l.Region("bc"); !ok || got != want {
		t.Fatalf("Region: %+v", got)
	}
	f, err := l.Open(r)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := f.Stat()
	f.Close()
	if st.Size() != int64(len(a)) || st.Mode().Perm() != 0o600 {
		t.Fatalf("the stored file: %d bytes, mode %v", st.Size(), st.Mode())
	}
	if _, err := l.Add("on", "", writeFile(t, Archive(2, 12, [4]float64{-95.2, 41.6, -74.3, 56.9}, 512)), 2000); err != nil {
		t.Fatal(err)
	}
	if ids := []string{l.Regions()[0].ID, l.Regions()[1].ID}; ids[0] != "bc" || ids[1] != "on" {
		t.Fatalf("not in order: %v", ids)
	}
	if on, _ := l.Region("on"); on.Name != "on" {
		t.Fatalf("a region without a name is named after its ID: %q", on.Name)
	}

	// A newer file replaces the old one, which is deleted; a download under way keeps it.
	open, _ := l.Open(r)
	defer open.Close()
	b := Archive(0, 14, bc, 4096)
	r2, err := l.Add("bc", "British Columbia", writeFile(t, b), 3000)
	if err != nil || r2.SHA256 != sumOf(b) || r2.UpdatedAt != 3000 {
		t.Fatalf("%+v %v", r2, err)
	}
	if _, err := os.Stat(filepath.Join(dir, sumOf(a)+".pmtiles")); !os.IsNotExist(err) {
		t.Error("the old file is still there")
	}
	if got, err := open.ReadAt(make([]byte, 16), 0); err != nil || got != 16 {
		t.Error("a download under way lost its file")
	}

	// What is refused leaves nothing behind.
	for _, id := range []string{"", "BC", "coarse", "-bc", "b/c", "abcdefghijklmnopqrstuvwxyz0123456"} {
		if _, err := l.Add(id, "", writeFile(t, b), 0); !errors.Is(err, ErrBadID) {
			t.Errorf("ID %q: %v", id, err)
		}
	}
	if _, err := l.Add("x", "bad\nname", writeFile(t, b), 0); !errors.Is(err, ErrBadName) {
		t.Errorf("a name with a newline: %v", err)
	}
	if _, err := l.Add("x", "", writeFile(t, []byte("not a map")), 0); !errors.Is(err, ErrNotPMTiles) {
		t.Errorf("not a map: %v", err)
	}
	if _, err := l.Add("x", "", dir, 0); err == nil {
		t.Error("a directory")
	}
	if _, err := l.SetCoarse(writeFile(t, Archive(0, 14, bc, 512)), 0); !errors.Is(err, ErrTooFine) {
		t.Errorf("a coarse archive to zoom 14: %v", err)
	}
	if _, ok := l.Region("x"); ok {
		t.Error("a refused region is offered")
	}

	c := Archive(0, 13, bc, 1024)
	if cr, err := l.SetCoarse(writeFile(t, c), 4000); err != nil || cr.SHA256 != sumOf(c) || cr.MaxZoom != 13 {
		t.Fatalf("coarse: %+v %v", cr, err)
	}
	if got := stored(t, dir); !slices.Equal(got, sortedNames(sumOf(b)+".pmtiles", sumOf(c)+".pmtiles",
		l.mustRegion(t, "on").SHA256+".pmtiles", "index.json", "notes.txt")) {
		t.Fatalf("the directory holds %v", got)
	}

	// Reopened, the library offers the same; a file gone behind its back isn't offered.
	l2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(l2.Regions(), l.Regions()) {
		t.Fatalf("reopened: %+v", l2.Regions())
	}
	if c2, ok := l2.Coarse(); !ok || c2.SHA256 != sumOf(c) {
		t.Fatal("reopened: the coarse archive")
	}
	os.Remove(filepath.Join(dir, l.mustRegion(t, "on").SHA256+".pmtiles"))
	if l3, err := Open(dir); err != nil || len(l3.Regions()) != 1 {
		t.Fatalf("a missing file: %v", err)
	}

	if err := l.Remove("bc"); err != nil {
		t.Fatal(err)
	}
	if err := l.Remove("bc"); !errors.Is(err, ErrNotFound) {
		t.Error("removed twice")
	}
	if err := l.RemoveCoarse(); err != nil {
		t.Fatal(err)
	}
	if err := l.RemoveCoarse(); !errors.Is(err, ErrNotFound) {
		t.Error("the coarse archive removed twice")
	}
	if got := stored(t, dir); !slices.Equal(got, []string{"index.json", "notes.txt"}) {
		t.Fatalf("after removing: %v", got)
	}
	if st, err := os.Stat(filepath.Join(dir, "index.json")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("index.json: %v", err)
	}
}

func (l *Library) mustRegion(t *testing.T, id string) Region {
	t.Helper()
	r, ok := l.Region(id)
	if !ok {
		t.Fatalf("no region %s", id)
	}
	return r
}

func sortedNames(names ...string) []string { slices.Sort(names); return names }

// A broken index stops the server rather than losing the regions.
func TestBrokenIndex(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("opened")
	}
	// An index naming a file outside the library offers nothing.
	if err := os.WriteFile(filepath.Join(dir, "index.json"),
		[]byte(`{"regions": [{"id": "x", "sha256": "../../etc/passwd", "size": 1}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := Open(dir); err != nil || len(l.Regions()) != 0 {
		t.Fatalf("%v", err)
	}
	if !bytes.Equal(Region{SHA256: "00ff"}.Sum(), []byte{0, 0xff}) {
		t.Error("Sum")
	}
}
