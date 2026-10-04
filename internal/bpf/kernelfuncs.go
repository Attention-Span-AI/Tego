// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"maps"
	"slices"
	"sync"

	"github.com/cilium/ebpf/btf"
)

// What a run asks of the kernel's BTF, and how it is answered without parsing it (enforce-plane §2.18).
//
// A root run that adopts its build's pinned programs loads nothing, yet it asked the kernel's BTF which functions
// exist: the reader (ReaderKfuncs), the optional tracing program (OptionalTracePrograms) and the plane's optional
// hooks (PlaneHook.Optional). One parse of /sys/kernel/btf/vmlinux and its name index is 50-100 ms of CPU in the
// KVM guests, most of an adopting run's own start. The answers cannot change within a boot, so doctor keeps them
// in its run-probe cache entry (keyed by boot, kernel and binary, owned by root) and seeds this process with them
// (SeedKernelFuncs); a name the seed lacks is asked of the parsed BTF as before.

// KernelFuncNames is every function a run asks the kernel's BTF about, sorted: ReaderKfuncs, the functions of
// OptionalTracePrograms, and the target of each optional plane hook in each mode.
func KernelFuncNames() []string {
	set := map[string]bool{}
	for _, name := range ReaderKfuncs {
		set[name] = true
	}
	for _, fn := range OptionalTracePrograms {
		set[fn] = true
	}
	for _, h := range PlaneHooks {
		if h.Optional {
			for _, m := range []PlaneMode{PlaneLSM, PlaneFmodRet} {
				set[h.Target(m)] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// KernelFuncFacts answers KernelFuncNames from a parsed BTF: whether each is a function in it.
func KernelFuncFacts(spec *btf.Spec) map[string]bool {
	out := map[string]bool{}
	for _, name := range KernelFuncNames() {
		out[name] = hasFunc(spec, name)
	}
	return out
}

// hasFunc reports whether spec declares a function of this name.
func hasFunc(spec *btf.Spec, name string) bool {
	var fn *btf.Func
	return spec.TypeByName(name, &fn) == nil
}

var (
	kernelFuncsMu sync.Mutex
	kernelFuncs   map[string]bool
)

// SeedKernelFuncs gives this process the answers a trusted cache kept for the running kernel (KernelFuncFacts on this
// boot's BTF). Names it does not hold are still asked of the parsed BTF. A seed given after KernelReader first ran
// changes nothing it chose.
func SeedKernelFuncs(facts map[string]bool) {
	kernelFuncsMu.Lock()
	defer kernelFuncsMu.Unlock()
	kernelFuncs = maps.Clone(facts)
}

// seededFunc is the seed's answer for name, and whether it holds one.
func seededFunc(name string) (has, ok bool) {
	kernelFuncsMu.Lock()
	defer kernelFuncsMu.Unlock()
	has, ok = kernelFuncs[name]
	return has, ok
}

// loadKernelBTF is the kernel's BTF, the process's one shared copy (KernelBTF): parsed and copied on the first call
// only. A variable so a test can count the parses.
var loadKernelBTF = KernelBTF

// kernelBTFLookupMu orders the name lookups in the shared spec, which build its index on first use.
var kernelBTFLookupMu sync.Mutex

// KernelHasFunc reports whether the running kernel's BTF has a function of this name: the seed's answer when it holds
// one, else the parsed BTF's. A kernel whose BTF cannot be read answers yes, so a load fails naming the function
// rather than quietly recording or deciding less.
func KernelHasFunc(name string) bool {
	if has, ok := seededFunc(name); ok {
		return has
	}
	spec, err := loadKernelBTF()
	if err != nil {
		return true
	}
	kernelBTFLookupMu.Lock()
	defer kernelBTFLookupMu.Unlock()
	return hasFunc(spec, name)
}
