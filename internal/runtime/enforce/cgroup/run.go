// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"log/slog"
	"net/netip"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Run identifies the run Prepare builds for. It mirrors enforce.RunRef and adds what the tier-2 backend needs
// and tier 1 does not: the cgroup's path, because a bpf_link is created against a cgroup directory rather than
// an id, the cgroup2 mount it is relative to, and the resolver endpoints.
//
// The import direction is enforce → this package, never the reverse, so the interface types stay out of here
// and enforce adapts between the two (docs/REPO-LAYOUT.md).
type Run struct {
	// Mounts is the one snapshot shared by composition, the listener, plane and recorder.
	Mounts   *MountSnapshot
	ID       string
	Agent    string
	CgroupID uint64
	// CgroupPath is the run scope's path relative to the cgroup2 mount, e.g.
	// "/user.slice/user-1000.slice/user@1000.service/tego.slice/tego-a.slice/run-b.scope".
	CgroupPath string
	// CgroupMount is the cgroup2 mount point; empty means identity.SystemCgroupRoot.
	CgroupMount string
	// Dir is the run directory and Contract the compiled contract copy, both implicit deny nodes in tier 1.
	Dir      string
	Contract string
	// Resolvers are the endpoints the supervisor's port-53 exception covers for this run (supervisor R14):
	// the list the runtime gives the supervisor's resolver set, so the kernel's rows and the supervisor's
	// exception name the same servers (BuildRuleMaps). Empty means no exception, and a query then needs a
	// declared entry, which is what the supervisor does with an empty list (supervisor E32).
	Resolvers []netip.AddrPort
	// StageExe is the binary the launcher execs as the child stage; empty means /proc/self/exe, the
	// launcher's own image, which is what `tego run` execs. The tier execs it again for its detached helpers
	// (linger, ring trim). The stage's own exec of it is never this tier's to decide: the run is armed after it
	// (Arm, ADR 0021 (2)).
	StageExe string
	// Log is the run's own log (tego's, never the ledger); nil discards. The fanotify listener writes the
	// few things it swallows there (§6 E10).
	Log *slog.Logger
	// PlaneRows is the table's rows for the decision plane (decide.CompilePlane), compiled once by the caller when
	// Options.Plane names a mode, so the inherited Landlock plan holds the keyed paths and adds their neutral rules
	// (landlock.Run.Plane) and the plane is filled from the same rows. Nil with a mode makes Prepare compile them.
	// The caller adds the mounted-root rows (PlaneRows.WithMounts over MountPoints, enforce-plane R12).
	PlaneRows *decide.PlaneRows
	// ExecPin asks for the run's execs to be pinned (ADR 0048 (3) P2): its table has command rules, or an exec gate that
	// may escalate, and its supervisor writes a pin for every exec it continues (Handle.PinExec). Prepare pins the
	// slot when a plane mode decides the run and the launcher's time and pid namespaces allow it, and the handle says
	// whether it did (Handle.ExecPins); otherwise the run runs unpinned, its log saying why.
	ExecPin bool
	// Drop, DropUID and DropGID are the credentials a root launch's child drops to (enforce.RunRef.Drop); this
	// tier only hands them to the tier-1 state it inherits, which creates a missing write directory with them.
	Drop             bool
	DropUID, DropGID int
	// PlaneErr is why the caller could not compile PlaneRows (decide.ErrPlaneCap, decide.ErrPlaneExecVerdict): the
	// run then decides through the fanotify listener, whole, and says so (choosePlane).
	PlaneErr error
}

// mount returns the cgroup2 mount point, defaulted.
func (r Run) mount() string {
	if r.CgroupMount == "" {
		return identity.SystemCgroupRoot
	}
	return r.CgroupMount
}
