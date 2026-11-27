//go:build !linux || android

package mapcache

import "time"

// bootClock is not available: age is measured on the system clock only.
func bootClock() (time.Duration, string, bool) {
	return 0, "", false
}
