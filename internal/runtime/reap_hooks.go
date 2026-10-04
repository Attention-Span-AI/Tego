// SPDX-License-Identifier: Apache-2.0

package runtime

// The reaper's test seams. A product build leaves them as they are here; a build with -tags tegotesthooks sets
// them from the environment (reap_testhook.go), so a root test can hold a reaper, or refuse its start, in the
// real binary it runs.
var (
	// reapTestEnv is what of the launcher's environment the reaper's gets.
	reapTestEnv = func() []string { return nil }
	// reapHold runs in the reaper once its launcher is gone, before it acts.
	reapHold = func() {}
	// reapStartFails refuses the reaper's start.
	reapStartFails = func() bool { return false }
)
