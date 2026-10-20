// SPDX-License-Identifier: Apache-2.0

package limits

import "time"

// WithTickInterval overrides the 1 Hz wall/stall check. Tests use it; a run does not.
func WithTickInterval(d time.Duration) Option {
	return func(w *Watcher) {
		if d > 0 {
			w.tick = d
		}
	}
}
