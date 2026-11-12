// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"io"
)

// What this file exports, only this package's tests (and its external test package) call.

// WriteResults is writeResults with no probe reported off.
func WriteResults(w io.Writer, rs []Result) error { return writeResults(w, rs, nil) }

// Probe runs every probe of R27 in order — D1 kernel, D2 BTF, D3 cgroup v2 delegation, D4 Landlock
// ABI, D5 the seccomp ADDFD/SEND self-test, D6 the active LSM list, D7 the program load tests and
// D8 fanotify — and stops early with the results so far when ctx ends. It needs no privilege; the
// probes that do answer "requires root to test" (§6 E18). It leaves nothing behind: the D3 and D7
// scratch cgroups are removed, no BPF object is pinned, and D5's filtered thread is destroyed with
// the goroutine that locked it (I7).
//
// Use Run for the derived report; this function is the flat result list.
func Probe(ctx context.Context, uid int) []Result {
	return runProbes(ctx, uid, "", nil).results
}

// probePrograms is D7 over every tier's rows and capture's, as a test drives it.
func probePrograms(root bool, uid int, kernel Version) (Result, []HookResult) {
	return probeHooks(root, uid, kernel, hooks, captureHooks)
}

// seccompVerdict is seccompVerdictOn for a kernel whose release is unknown.
func seccompVerdict(fd int, err error, pt PtraceState) Result {
	return seccompVerdictOn(fd, err, pt, Version{})
}

// The run-probe cache's and the probe state's shorthands below are test-only: production reads and keeps
// entries through loadIdentified, recordWith and storeID (runcache.go), which also return the file's identity.

// load returns the entry for k when there is a valid one: a regular file of owner's, with one link, no
// access for group or others, at most maxRunCacheBytes, whose key is k and whose answer vouches for tier
// cgroup with exactly this binary's tier-2 rows. Anything else is no entry, and the run probes.
func (c *runCache) load(k runCacheKey) (runCacheEntry, bool) {
	e, _, ok := c.loadIdentified(k)
	return e, ok
}

// record keeps a fresh answer that vouches for tier cgroup and removes k's entry otherwise. A plane answer in
// which a mode's probe faulted is not kept: its cause (a full or read-only fixtures directory, a timeout under
// load) is not in the key and may be gone by the next run, so that run probes the plane again. D7's tier-2 rows
// and D8's answer do not depend on it and are kept without a plane answer (runCacheEntry.Plane). It never fails
// the run: an entry it cannot write is an entry the next run does not find, and that run probes.
func (c *runCache) record(k runCacheKey, programs Result, rows []HookResult, plane *PlaneState, planeRows []HookResult,
	fan Result, fanState FanotifyState) {
	c.recordWith(k, programs, rows, plane, planeRows, fan, fanState, kernelAnswers{})
}

// store writes e as owner's 0600 file, through a temporary file and a rename in the same directory, so a
// reader sees the old entry or the new one and never part of one.
func (c *runCache) store(e runCacheEntry) error {
	_, err := c.storeID(e)
	return err
}

// hookOK reports whether one D7 hook loaded and attached. A hook that was never probed (no root)
// counts as not available: doctor never claims a capability it could not test.
func (st probeState) hookOK(name string) bool {
	for _, h := range st.hooks {
		if h.Hook == name {
			return h.OK()
		}
	}
	return false
}
