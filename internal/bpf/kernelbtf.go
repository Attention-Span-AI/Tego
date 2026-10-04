// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"sync"

	"github.com/cilium/ebpf/btf"
)

// sharedKernelBTF is the process's one copy of the running kernel's BTF.
var sharedKernelBTF = sync.OnceValues(btf.LoadKernelSpec)

// KernelBTF is the running kernel's BTF, read once per process and shared: btf.LoadKernelSpec returns a fresh copy
// of the whole spec on every call (18 ms on a distro kernel, about twice that in a guest), and each of its name
// lookups builds an index over that copy (10 ms) before the first answer, so a run that asked from D2, from the
// reader choice and from Prepare's optional-hook lookups paid three copies and three indexes: 100 ms or more of a
// start at tier cgroup and bpflsm (enforce-plane §10, the perf suite's probe.btf and plane.hooks phases).
//
// The spec is shared, so it is read, never changed, and used by one goroutine at a time: a run's probes and its
// Prepare are sequential, and lookups build the index lazily without a lock. A caller that needs to change or hand
// a private copy on takes btf.LoadKernelSpec itself.
func KernelBTF() (*btf.Spec, error) { return sharedKernelBTF() }
