// SPDX-License-Identifier: Apache-2.0

package cgroup

import "context"

// What this file exports, only this package's tests call.

// WaitFrozen returns once c's cgroup.events says frozen as on asks, waking on inotify and re-reading at least every
// pollFallback; it waits at most FreezeWait, then answers ErrNotFrozen. ctx bounds it too.
func WaitFrozen(ctx context.Context, c Cgroup, on bool) error {
	return WaitFrozenWithin(ctx, c, on, FreezeWait)
}

// Missing lists the controllers l needs that c's cgroup.controllers does not offer, in write
// order without duplicates; empty when every write can succeed. Callers use it to note a limit
// that would fail with a *MissingControllerError before calling SetLimits.
func Missing(c Cgroup, l Limits) []string {
	have := make(map[string]bool, len(c.Controllers))
	for _, name := range c.Controllers {
		have[name] = true
	}
	var out []string
	seen := make(map[string]bool, 3)
	for _, f := range limitFiles(l) {
		if !have[f.Controller] && !seen[f.Controller] {
			seen[f.Controller] = true
			out = append(out, f.Controller)
		}
	}
	return out
}

// delegatedSubtree is delegatedSubtreeIn (whose doc is the contract) under the real mount.
func delegatedSubtree(procCgroup []byte, uid int) string {
	return delegatedSubtreeIn(Mount, procCgroup, uid)
}
