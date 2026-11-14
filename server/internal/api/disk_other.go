// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package api

// diskFree is unknown off Linux.
func diskFree(string) (uint64, bool) { return 0, false }
