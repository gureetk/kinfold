// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clock is the server's time: the wall clock in milliseconds, whether it is
// synchronized, and a fake for tests. Phones build their trusted time on the server's
// (PROTOCOL.md §8.4), so a server whose clock isn't synchronized answers nothing but its
// health check (API.md §2).
package clock

import (
	"sync"
	"time"
)

// Clock is what the server reads time from.
type Clock interface {
	// Now is milliseconds since the Unix epoch.
	Now() uint64
	// Synced reports whether the clock is synchronized to a time source.
	Synced() bool
}

// System is the host's clock. CheckSync false skips the synchronization check, for hosts
// where it can't be read.
type System struct{ CheckSync bool }

func (System) Now() uint64 { return uint64(time.Now().UnixMilli()) }

func (s System) Synced() bool { return !s.CheckSync || kernelSynced() }

// Fake is a settable clock for tests.
type Fake struct {
	mu     sync.Mutex
	now    uint64
	synced bool
}

// NewFake returns a synchronized fake clock at now.
func NewFake(now uint64) *Fake { return &Fake{now: now, synced: true} }

func (f *Fake) Now() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *Fake) Synced() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.synced
}

// Set moves the clock to now.
func (f *Fake) Set(now uint64) {
	f.mu.Lock()
	f.now = now
	f.mu.Unlock()
}

// Advance moves the clock forward by d milliseconds.
func (f *Fake) Advance(d uint64) {
	f.mu.Lock()
	f.now += d
	f.mu.Unlock()
}

// SetSynced sets whether the clock reports itself synchronized.
func (f *Fake) SetSynced(s bool) {
	f.mu.Lock()
	f.synced = s
	f.mu.Unlock()
}
