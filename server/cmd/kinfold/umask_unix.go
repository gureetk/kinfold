// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import "syscall"

// privateFiles makes every file the server creates readable by its own user only: the
// database and the files SQLite keeps next to it, the key and the admin socket.
func privateFiles() { syscall.Umask(0o077) }
