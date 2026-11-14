// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package clock

// kernelSynced can't ask the kernel on this platform, so it trusts the clock.
func kernelSynced() bool { return true }
