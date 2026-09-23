// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// Control files ReadResources reads. memory.events is fileMemoryEvents.
const (
	fileMemoryPeak = "memory.peak"
	filePidsPeak   = "pids.peak"
	fileCPUStat    = "cpu.stat"
)

// Resources is what a run's cgroup says the run used, read once before the cgroup is removed
// (docs/p0/runtime-launch.md §4.1 step 13, record-ledger.md run_end.resources). Every field is a
// pointer because a file the kernel does not have, or a key it does not write, is unknown rather than
// zero (docs/VERSIONING.md §2): memory.peak needs 5.19 and the memory controller, pids.peak needs a
// kernel that has it and the pids controller, cpu.stat's throttling keys need the cpu controller, and
// memory.events needs the memory controller. cpu.stat's usage keys exist on every cgroup v2 kernel.
type Resources struct {
	MemoryPeak       *uint64 // memory.peak: the most memory the cgroup was ever charged, in bytes
	PidsPeak         *uint64 // pids.peak: the most tasks it ever held
	CPUUsageUsec     *uint64 // cpu.stat usage_usec
	CPUUserUsec      *uint64 // cpu.stat user_usec
	CPUSystemUsec    *uint64 // cpu.stat system_usec
	CPUNrThrottled   *uint64 // cpu.stat nr_throttled: periods cpu.max throttled the cgroup in
	CPUThrottledUsec *uint64 // cpu.stat throttled_usec
	MemoryHigh       *uint64 // memory.events high: times reclaim was forced over memory.high
	MemoryMax        *uint64 // memory.events max: times an allocation met memory.max
	MemoryOOM        *uint64 // memory.events oom: times the cgroup hit its limit with nothing to reclaim
	MemoryOOMKill    *uint64 // memory.events oom_kill: processes the OOM killer took from it
}

// Empty reports whether no file gave a value, which is how a caller tells "nothing was read" from a run
// that used nothing.
func (r Resources) Empty() bool { return r == (Resources{}) }

// ReadResources reads the peaks and counters of c's own control files. A file that does not exist
// leaves its fields nil and is not an error; a key a file does not carry leaves its field nil. An
// unreadable file leaves all its fields nil, and a value that is not a count leaves its own field nil
// (memory.peak, pids.peak, or the one key of cpu.stat or memory.events that holds it); each is returned,
// joined with the others, beside everything that could be read.
func ReadResources(c Cgroup) (Resources, error) {
	var r Resources
	var errs []error
	read := func(name string) []byte {
		data, err := readControl(c, name)
		if err != nil {
			if !errors.Is(err, unix.ENOENT) {
				errs = append(errs, err)
			}
			return nil
		}
		return data
	}
	single := func(name string) *uint64 {
		data := read(name)
		if data == nil {
			return nil
		}
		n, err := strconv.ParseUint(string(bytes.TrimSpace(data)), 10, 64)
		if err != nil {
			errs = append(errs, fmt.Errorf("cgroup: %s: %q is not a count", filepath.Join(c.Path, name), data))
			return nil
		}
		return &n
	}
	// keyed differs from parseCounter in one way: a key that is present with a value that is not a count
	// is an error, not an absent key, since the kernel wrote the key and a nil would pass for "this kernel
	// has no such counter".
	keyed := func(name string, data []byte, key string) *uint64 {
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			k, v, found := bytes.Cut(bytes.TrimSpace(line), []byte{' '})
			if !found || string(k) != key {
				continue
			}
			n, err := strconv.ParseUint(string(bytes.TrimSpace(v)), 10, 64)
			if err != nil {
				errs = append(errs, fmt.Errorf("cgroup: %s: %s %q is not a count", filepath.Join(c.Path, name), key, v))
				return nil
			}
			return &n
		}
		return nil
	}

	r.MemoryPeak = single(fileMemoryPeak)
	r.PidsPeak = single(filePidsPeak)
	if data := read(fileCPUStat); data != nil {
		r.CPUUsageUsec = keyed(fileCPUStat, data, "usage_usec")
		r.CPUUserUsec = keyed(fileCPUStat, data, "user_usec")
		r.CPUSystemUsec = keyed(fileCPUStat, data, "system_usec")
		r.CPUNrThrottled = keyed(fileCPUStat, data, "nr_throttled")
		r.CPUThrottledUsec = keyed(fileCPUStat, data, "throttled_usec")
	}
	if data := read(fileMemoryEvents); data != nil {
		r.MemoryHigh = keyed(fileMemoryEvents, data, "high")
		r.MemoryMax = keyed(fileMemoryEvents, data, "max")
		r.MemoryOOM = keyed(fileMemoryEvents, data, "oom")
		r.MemoryOOMKill = keyed(fileMemoryEvents, data, "oom_kill")
	}
	return r, errors.Join(errs...)
}
