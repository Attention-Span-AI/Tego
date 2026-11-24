// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"errors"

	"github.com/attention-span-ai/tego/internal/platform/peer"
	"github.com/attention-span-ai/tego/internal/runscope"
)

// ErrGoverned is a change to a run's governance asked by a process inside a run: an agent cannot lift what governs
// it. The dashboard refuses the same change from a connection made inside a run (internal/control/web
// governed.go), and the engine's CLI writers refuse it from a caller inside one (internal/cli governed.go).
var ErrGoverned = errors.New("a governed agent cannot change its own governance")

// selfAnswer is peer.Self, replaced in tests.
var selfAnswer = peer.Self

// SelfGoverned is this process's own answer to "outside every tego run?" (internal/platform/peer.Self, the rule of
// internal/runscope): inside a run's or an adoption's scope or a look-alike of one, unknown when that cannot be
// shown (a cgroup file that cannot be read, a cgroup namespace that is not the machine's first one and has no
// proof), or outside. A writer that would widen a run's governance (an unblock, a resume) refuses unless
// SelfGoverned().Outside(); one that only narrows need not ask.
func SelfGoverned() runscope.Answer { return selfAnswer() }
