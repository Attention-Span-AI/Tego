// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// Reader is how a build of an object reads kernel memory (ADR 0024's 2026-09-29 tier-2 note). Tier 2's
// trace_proc is compiled once per reader, as the plane is (plane.go), and Load hands out the build this kernel
// takes; the other tier-2 objects are one build that makes no bpf_probe_read_kernel call, so they have no reader.
type Reader string

const (
	// ReaderProbe reads through CO-RE bpf_probe_read_kernel: every supported kernel loads it, except under
	// lockdown=confidentiality, which refuses that helper at load on every kernel, 6.17 included.
	ReaderProbe Reader = "probe"
	// ReaderRdonly reads by direct BTF loads and bpf_rdonly_cast, in a bpf_loop, with no bpf_probe_read_kernel*
	// call: the build lockdown=confidentiality lets load. The kernel's BTF must carry both functions (6.2+, and
	// backports such as RHEL 9.8's); a kernel without them refuses the build outright.
	ReaderRdonly Reader = "rdonly"
)

// Readers lists both readers, probe first.
var Readers = []Reader{ReaderProbe, ReaderRdonly}

// ReaderKfuncs are the functions the rdonly build calls that not every supported kernel has, which ChooseReader
// looks for in the kernel's BTF.
var ReaderKfuncs = []string{"bpf_rdonly_cast", "bpf_loop"}

// ReaderChoice is the build ChooseReader picks and why, in words doctor prints.
type ReaderChoice struct {
	Reader Reader
	// Why names what decided: the functions found, or the one missing.
	Why string
	// Confidentiality reports lockdown=confidentiality, under which only ReaderRdonly loads.
	Confidentiality bool
}

// Loadable reports whether the chosen build can load here at all: false only for the probe build under
// lockdown=confidentiality, which is a kernel without the rdonly build's functions in that mode.
func (c ReaderChoice) Loadable() bool { return c.Reader == ReaderRdonly || !c.Confidentiality }

// ChooseReader picks the build for a kernel, the plane's rule (ADR 0024 (9)): the rdonly build wherever the
// kernel's BTF has every ReaderKfuncs function, the probe build elsewhere. The choice is by BTF, not by lockdown:
// a program naming a kfunc the kernel lacks fails to load, weak or not, and one build per kernel means the build a
// run loads is the one every run on that kernel loads. kernel may be nil (no BTF): the probe build, since the
// rdonly one cannot be checked. lockdown is /sys/kernel/security/lockdown as the kernel prints it.
func ChooseReader(kernel *btf.Spec, lockdown string) ReaderChoice {
	if kernel == nil {
		return chooseReaderBy(nil, lockdown)
	}
	return chooseReaderBy(func(name string) bool { return hasFunc(kernel, name) }, lockdown)
}

// chooseReaderBy is ChooseReader with the kernel's BTF asked through has; a nil has is no BTF.
func chooseReaderBy(has func(name string) bool, lockdown string) ReaderChoice {
	c := ReaderChoice{Reader: ReaderProbe, Confidentiality: strings.Contains(lockdown, "[confidentiality]")}
	if has == nil {
		c.Why = "the kernel's BTF is unavailable"
		return c
	}
	for _, name := range ReaderKfuncs {
		if !has(name) {
			c.Why = fmt.Sprintf("the kernel's BTF has no %s", name)
			return c
		}
	}
	c.Reader = ReaderRdonly
	c.Why = "the kernel's BTF has " + strings.Join(ReaderKfuncs, " and ")
	return c
}

// lockdownPath is securityfs's lockdown file.
const lockdownPath = "/sys/kernel/security/lockdown"

var (
	kernelReaderOnce sync.Once
	kernelReader     ReaderChoice
)

// KernelReader is ChooseReader for the running kernel, worked out once per process: the kernel's BTF and a
// lockdown that can only be raised do not change under a running process in a way that makes the rdonly build
// load where it did not. The functions are the seed's (SeedKernelFuncs) when it holds every one of ReaderKfuncs, so
// a run doctor seeded parses no BTF for the choice; the lockdown is read afresh either way.
func KernelReader() ReaderChoice {
	kernelReaderOnce.Do(func() {
		lockdown := ""
		if b, err := os.ReadFile(lockdownPath); err == nil {
			lockdown = strings.TrimSpace(string(b))
		}
		seeded := true
		for _, name := range ReaderKfuncs {
			if _, ok := seededFunc(name); !ok {
				seeded = false
			}
		}
		if seeded {
			kernelReader = chooseReaderBy(func(name string) bool { has, _ := seededFunc(name); return has }, lockdown)
			return
		}
		spec, err := loadKernelBTF()
		if err != nil {
			spec = nil
		}
		kernelReader = ChooseReader(spec, lockdown)
	})
	return kernelReader
}

// HasReaders reports whether an object is compiled once per reader in this binary.
func HasReaders(o Object) bool {
	_, ok := readerGenerated[o]
	return ok
}

// LoadReader returns a fresh CollectionSpec of one reader's build of an object. An object with one build answers
// that build for either reader.
func LoadReader(o Object, r Reader) (*ebpf.CollectionSpec, error) {
	b, err := readerBinding(o, r)
	if err != nil {
		return nil, err
	}
	spec, err := b.load()
	if err != nil {
		return nil, fmt.Errorf("bpf: load %s (%s): %w", o, r, err)
	}
	return spec, nil
}

// readerBinding is the binding of one reader's build of o.
func readerBinding(o Object, r Reader) (binding, error) {
	if r == ReaderRdonly {
		if b, ok := readerGenerated[o]; ok {
			return cachedBinding(o, true, b), nil
		}
	}
	b, ok := bindingOf(o)
	if !ok {
		return binding{}, fmt.Errorf("%w: %s", ErrNotGenerated, o)
	}
	return b, nil
}
