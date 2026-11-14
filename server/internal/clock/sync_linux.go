// SPDX-License-Identifier: AGPL-3.0-or-later

package clock

import "syscall"

// timeError is TIME_ERROR from adjtimex(2): the kernel clock is not synchronized.
const timeError = 5

// kernelSynced asks the kernel whether NTP (or chrony, or systemd-timesyncd) keeps the
// clock synchronized. Reading the state changes nothing.
func kernelSynced() bool {
	var tx syscall.Timex
	state, err := syscall.Adjtimex(&tx)
	return err == nil && state != timeError
}
