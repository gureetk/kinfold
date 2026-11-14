// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tiles keeps the map files the server offers (API.md §13): whole regions for apps to
// download, and a coarse archive for the share viewer. They are PMTiles version 3 archives.
// Each is copied in, checked, and stored under the SHA-256 of its bytes, so a file never
// changes under a download; index.json beside them names the regions.
package tiles

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	// HeaderLen is the size of a PMTiles header.
	HeaderLen = 127
	// rootEnd is where the root directory must end (PMTiles v3 §2).
	rootEnd = 16384
	// MaxCoarseZoom is the most detail the coarse archive may hold (API.md §13).
	MaxCoarseZoom = 13
	// Attribution is the credit the map data needs (ODbL).
	Attribution = "© OpenStreetMap contributors"

	indexName = "index.json"
	suffix    = ".pmtiles"
)

var (
	ErrNotFound   = errors.New("no such region")
	ErrBadID      = errors.New("a region ID is 1 to 32 lower-case letters, digits and hyphens, and not \"coarse\"")
	ErrBadName    = errors.New("a region's name is at most 100 bytes of UTF-8")
	ErrNotPMTiles = errors.New("not a PMTiles version 3 archive")
	ErrTooFine    = fmt.Errorf("the coarse archive goes to zoom %d at most", MaxCoarseZoom)
)

// Header is what the server reads from a PMTiles header (PMTiles v3 §3).
type Header struct {
	MinZoom, MaxZoom uint8
	Bounds           [4]float64 // west, south, east, north, in degrees
}

// ParseHeader checks a PMTiles header against the archive's size: the magic number and
// version, sections that lie inside the archive, a root directory in the first 16 KiB, zoom
// levels in order and bounds on the globe.
func ParseHeader(b []byte, size int64) (Header, error) {
	if len(b) < HeaderLen || string(b[:7]) != "PMTiles" || b[7] != 3 || size < HeaderLen {
		return Header{}, ErrNotPMTiles
	}
	u64 := func(at int) uint64 { return binary.LittleEndian.Uint64(b[at:]) }
	deg := func(at int) float64 { return float64(int32(binary.LittleEndian.Uint32(b[at:]))) / 1e7 }
	for _, at := range []int{0x08, 0x18, 0x28, 0x38} { // root directory, metadata, leaf directories, tile data
		off, n := u64(at), u64(at+8)
		if off < HeaderLen || off > uint64(size) || n > uint64(size)-off {
			return Header{}, fmt.Errorf("%w: a section lies outside the file", ErrNotPMTiles)
		}
	}
	if root, n := u64(0x08), u64(0x10); n == 0 || root+n > rootEnd {
		return Header{}, fmt.Errorf("%w: the root directory isn't in the first 16 KiB", ErrNotPMTiles)
	}
	h := Header{MinZoom: b[0x64], MaxZoom: b[0x65], Bounds: [4]float64{deg(0x66), deg(0x6A), deg(0x6E), deg(0x72)}}
	w, s, e, n := h.Bounds[0], h.Bounds[1], h.Bounds[2], h.Bounds[3]
	if h.MinZoom > h.MaxZoom || h.MaxZoom > 30 {
		return Header{}, fmt.Errorf("%w: zoom levels", ErrNotPMTiles)
	}
	if !(-180 <= w && w < e && e <= 180 && -90 <= s && s < n && n <= 90) {
		return Header{}, fmt.Errorf("%w: bounds", ErrNotPMTiles)
	}
	return h, nil
}

// A Region is a map file on offer.
type Region struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Bounds    [4]float64 `json:"bbox"`
	MinZoom   uint8      `json:"minzoom"`
	MaxZoom   uint8      `json:"maxzoom"`
	Size      int64      `json:"size"`
	SHA256    string     `json:"sha256"` // hex; the file is stored under it
	UpdatedAt uint64     `json:"updated_at"`
}

// Sum is the file's SHA-256.
func (r Region) Sum() []byte {
	b, _ := hex.DecodeString(r.SHA256)
	return b
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ValidID says whether id can name a region.
func ValidID(id string) bool { return idPattern.MatchString(id) && id != "coarse" }

var storedName = regexp.MustCompile(`^[0-9a-f]{64}\.pmtiles$`)

// Library is the directory of map files. Reads never wait; changes go one at a time.
type Library struct {
	dir string
	mu  sync.Mutex
	idx atomic.Pointer[index]
}

type index struct {
	Regions []Region `json:"regions"` // sorted by ID
	Coarse  *Region  `json:"coarse,omitempty"`
}

// Open opens the library in dir, making the directory if it has to. A region whose file is
// missing, or isn't the size the index says, isn't offered; the server logs its ID.
func Open(dir string) (*Library, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &Library{dir: dir}
	ix := &index{}
	b, err := os.ReadFile(filepath.Join(dir, indexName))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(b, ix); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(dir, indexName), err)
		}
	}
	ix.Regions = slices.DeleteFunc(ix.Regions, func(r Region) bool {
		if !l.present(r) {
			slog.Warn("a map region's file is missing; it isn't offered", "region", r.ID)
			return true
		}
		return false
	})
	if ix.Coarse != nil && !l.present(*ix.Coarse) {
		slog.Warn("the coarse archive's file is missing; it isn't offered")
		ix.Coarse = nil
	}
	l.idx.Store(ix)
	l.collect()
	return l, nil
}

func (l *Library) path(sum string) string { return filepath.Join(l.dir, sum+suffix) }

func (l *Library) present(r Region) bool {
	st, err := os.Stat(l.path(r.SHA256))
	return err == nil && st.Mode().IsRegular() && st.Size() == r.Size && storedName.MatchString(r.SHA256+suffix)
}

// Regions lists the regions on offer, by ID.
func (l *Library) Regions() []Region { return append([]Region{}, l.idx.Load().Regions...) }

// Region returns the region with this ID.
func (l *Library) Region(id string) (Region, bool) {
	ix := l.idx.Load()
	i, ok := slices.BinarySearchFunc(ix.Regions, id, func(r Region, id string) int { return strings.Compare(r.ID, id) })
	if !ok {
		return Region{}, false
	}
	return ix.Regions[i], true
}

// Coarse returns the coarse archive, if there is one.
func (l *Library) Coarse() (Region, bool) {
	if c := l.idx.Load().Coarse; c != nil {
		return *c, true
	}
	return Region{}, false
}

// Open opens a region's file for reading. It fails only if the region was replaced or
// removed since the caller looked it up.
func (l *Library) Open(r Region) (*os.File, error) { return os.Open(l.path(r.SHA256)) }

// Add offers the PMTiles archive at src as region id, replacing any earlier file for it. The
// archive is copied, so the operator's file may change or go afterwards.
func (l *Library) Add(id, name, src string, now uint64) (Region, error) {
	if !ValidID(id) {
		return Region{}, ErrBadID
	}
	if name == "" {
		name = id
	}
	if len(name) > 100 || !validText(name) {
		return Region{}, ErrBadName
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	r, err := l.copyIn(src, nil)
	if err != nil {
		return Region{}, err
	}
	r.ID, r.Name, r.UpdatedAt = id, name, now
	ix := l.clone()
	i, found := slices.BinarySearchFunc(ix.Regions, id, func(r Region, id string) int { return strings.Compare(r.ID, id) })
	if found {
		ix.Regions[i] = r
	} else {
		ix.Regions = slices.Insert(ix.Regions, i, r)
	}
	return r, l.save(ix)
}

// Remove stops offering a region and deletes its file.
func (l *Library) Remove(id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	ix := l.clone()
	n := len(ix.Regions)
	ix.Regions = slices.DeleteFunc(ix.Regions, func(r Region) bool { return r.ID == id })
	if len(ix.Regions) == n {
		return ErrNotFound
	}
	return l.save(ix)
}

// SetCoarse makes the archive at src the coarse archive, replacing any earlier one.
func (l *Library) SetCoarse(src string, now uint64) (Region, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, err := l.copyIn(src, func(h Header) error {
		if h.MaxZoom > MaxCoarseZoom {
			return ErrTooFine
		}
		return nil
	})
	if err != nil {
		return Region{}, err
	}
	r.ID, r.Name, r.UpdatedAt = "coarse", "coarse", now
	ix := l.clone()
	ix.Coarse = &r
	return r, l.save(ix)
}

// RemoveCoarse stops offering the coarse archive.
func (l *Library) RemoveCoarse() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	ix := l.clone()
	if ix.Coarse == nil {
		return ErrNotFound
	}
	ix.Coarse = nil
	return l.save(ix)
}

func (l *Library) clone() *index {
	cur := l.idx.Load()
	ix := &index{Regions: slices.Clone(cur.Regions)}
	if cur.Coarse != nil {
		c := *cur.Coarse
		ix.Coarse = &c
	}
	return ix
}

// copyIn copies an archive into the library, hashing it on the way, and checks the copy's
// header, so what is checked is what will be served. The copy is named after its hash.
func (l *Library) copyIn(src string, check func(Header) error) (Region, error) {
	in, err := os.Open(src)
	if err != nil {
		return Region{}, err
	}
	defer in.Close()
	if st, err := in.Stat(); err != nil || !st.Mode().IsRegular() {
		return Region{}, fmt.Errorf("%s isn't a regular file", src)
	}
	tmp, err := os.CreateTemp(l.dir, "*.incoming")
	if err != nil {
		return Region{}, err
	}
	defer os.Remove(tmp.Name()) // nothing to remove once it is renamed
	defer tmp.Close()
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), in)
	if err != nil {
		return Region{}, err
	}
	head := make([]byte, HeaderLen)
	if _, err := tmp.ReadAt(head, 0); err != nil {
		return Region{}, ErrNotPMTiles
	}
	hdr, err := ParseHeader(head, size)
	if err != nil {
		return Region{}, err
	}
	if check != nil {
		if err := check(hdr); err != nil {
			return Region{}, err
		}
	}
	if err := tmp.Sync(); err != nil {
		return Region{}, err
	}
	if err := tmp.Close(); err != nil {
		return Region{}, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if err := os.Rename(tmp.Name(), l.path(sum)); err != nil {
		return Region{}, err
	}
	if err := syncDir(l.dir); err != nil {
		return Region{}, err
	}
	return Region{Bounds: hdr.Bounds, MinZoom: hdr.MinZoom, MaxZoom: hdr.MaxZoom, Size: size, SHA256: sum}, nil
}

// save writes the index and puts it in place, then deletes the files it no longer names.
// Downloads already under way keep their open file.
func (l *Library) save(ix *index) error {
	b, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(l.dir, indexName+".new")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(l.dir, indexName))
	}
	if err == nil {
		err = syncDir(l.dir)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	l.idx.Store(ix)
	l.collect()
	return nil
}

// collect deletes stored files that no entry names, and copies cut short. It leaves alone
// any file whose name the library didn't give it.
func (l *Library) collect() {
	ix := l.idx.Load()
	keep := map[string]bool{}
	for _, r := range ix.Regions {
		keep[r.SHA256+suffix] = true
	}
	if ix.Coarse != nil {
		keep[ix.Coarse.SHA256+suffix] = true
	}
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if n := e.Name(); (storedName.MatchString(n) && !keep[n]) || strings.HasSuffix(n, ".incoming") {
			os.Remove(filepath.Join(l.dir, n))
		}
	}
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// validText is UTF-8 without control characters.
func validText(s string) bool {
	for _, r := range s {
		if r == 0xFFFD || r < 0x20 || r == 0x7F {
			return false
		}
	}
	return true
}
