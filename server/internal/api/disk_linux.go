// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import "syscall"

// diskFree is how many bytes the server's user may still write in dir's file system.
func diskFree(dir string) (uint64, bool) {
	var st syscall.Statfs_t
	if dir == "" || syscall.Statfs(dir, &st) != nil {
		return 0, false
	}
	return st.Bavail * uint64(st.Bsize), true
}
