// SPDX-License-Identifier: Apache-2.0

package runtime

import "github.com/attention-span-ai/tego/internal/runtime/limits"

// limitKiller is the Killer the budget watcher is given in place of the run's cgroup manager. A product build returns it
// as it is; a build with -tags tegotesthooks (limitkill_testhook.go) can make the kill land late, so a test can hold open
// the window between the limit line and the end of the run, which is a few hundred milliseconds on a loaded machine and
// otherwise a few hundred microseconds.
var limitKiller = func(k limits.Killer) limits.Killer { return k }

// EnvTestLimitKillLag makes a binary built with -tags tegotesthooks write the kill of a run its budget ended this long
// (a Go duration) after the limit line, instead of at once: the window the admission gate closes, held open on every machine.
const EnvTestLimitKillLag = "TEGO_TEST_LIMIT_KILL_LAG"
