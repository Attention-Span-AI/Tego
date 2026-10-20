// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"net/netip"
	"os"

	"github.com/attention-span-ai/tego/internal/runtime/deputy"
)

// DeputyPin is deputyPin (whose doc is the contract) for a process with no filter: it reads the follower's facts at
// each call and takes this process's thread group as the deputy's own.
func DeputyPin(q deputy.PinQuery) (deputy.Pinned, error) {
	return deputyPin(q, currentFollowFacts(), os.Getpid())
}

// pointers reads a NULL-terminated array of user pointers, at most argvEntries of them. more reports that
// the array did not end inside the cap.
func (r *reader) pointers(addr uint64) (out []uint64, more bool) {
	return r.pointersLimited(addr, argvEntries)
}

// owns reports what the binding b of the run's socket rs says of f (fileSB.owns).
func owns(k kernel, b unixBinding, rs *runSock, f unixFile) (ownership, error) {
	return (&fileSB{k: k, f: f}).owns(b, rs)
}

// match reports the guarded endpoint ap names, as the refusal decideGuarded records: the endpoint's rule and
// host, or rule unresolved with the host when ap is on the port of a name that has not resolved yet. Every
// protocol is matched, as a host:port entry decides TCP and UDP alike (SEMANTICS §5): QUIC to the model host
// bypasses the forwarder as surely as TCP does.
func (g *modelGuard) match(ap netip.AddrPort) (verdictOf, bool) {
	return g.matchAllowed(ap, false)
}
