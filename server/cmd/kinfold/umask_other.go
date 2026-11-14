// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package main

// privateFiles does nothing where there is no umask; the data directory's own permissions
// protect it.
func privateFiles() {}
