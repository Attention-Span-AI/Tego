// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"errors"

	"github.com/attention-span-ai/tego/internal/runscope"
)

// ErrGoverned is a change to a run's governance asked by a process inside a run: an agent cannot lift what governs
// it. The dashboard refuses the same change from a connection made inside a run (internal/control/web
// governed.go), and the engine's CLI writers refuse it from a caller inside one (internal/cli governed.go).
var ErrGoverned = errors.New("a governed agent cannot change its own governance")

// selfInRun is runscope.InRun, replaced in tests.
var selfInRun = runscope.InRun

// SelfGoverned reports whether this process sits inside a tego run's cgroup, read from /proc/self/cgroup
// (runscope.InRun): inside a run's or an adoption's scope, or a look-alike of one. It fails closed: when the file
// cannot be read or this process is outside the initial cgroup namespace, it is true with the error (a process that
// unshares a cgroup namespace inside its run's scope reads like a container's, and InRun cannot tell them apart). A
// writer that would widen a run's governance (an unblock, a resume) refuses when it is true; one that only narrows
// need not ask.
func SelfGoverned() (bool, error) { return selfInRun() }
