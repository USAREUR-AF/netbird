//go:build linux && !android

package mapcache

import (
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// bootClock reads CLOCK_BOOTTIME, which counts time in suspend and is never
// stepped, and the kernel's boot ID.
func bootClock() (time.Duration, string, bool) {
	id, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return 0, "", false
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, "", false
	}
	return time.Duration(ts.Nano()), strings.TrimSpace(string(id)), true
}
