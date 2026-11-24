// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"strconv"
	"strings"
)

// Applied is the limits a scope holds for the files SetLimits wrote, as the kernel reports them back (GAPS C221): what
// holds, which is the number the kernel stored (memory rounded to a page) and not the contract's words for it. A
// member is its file's value; the zero value of a member whose file was not written (Wrote*) says nothing.
type Applied struct {
	CPUMax    string // cpu.max, "<quota|max> <period>"
	CPUWeight int    // cpu.weight, 1..10000; 0 when cpu.weight was not written
	// MemoryMax, MemoryHigh and PidsMax are -1 when the file reads "max" (no limit holds) and 0 or more otherwise; they
	// have a Wrote flag because 0 is a limit too.
	MemoryMax, MemoryHigh int64
	PidsMax               int64
	WroteMemoryMax        bool
	WroteMemoryHigh       bool
	WrotePidsMax          bool
}

// ReadApplied reads back, from c, each limit file l made SetLimits write (limitFiles), and nothing else: a file the run
// never wrote holds the kernel's default or an ancestor's choice, not this run's. A file that cannot be read is left out
// and the first such error is returned with the rest of what was read, so the caller records what it has and says it is
// short. It reads c's own files only: ReadEffective folds in the ancestors' lower ceilings.
func ReadApplied(c Cgroup, l Limits) (Applied, error) {
	var out Applied
	var first error
	for _, f := range limitFiles(l) {
		if f.Name == fileSwapMax {
			continue // memory.max's companion; not a limit the record names
		}
		data, err := readControl(c, f.Name)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		v := strings.TrimSpace(string(data))
		switch f.Name {
		case "cpu.max":
			out.CPUMax = v
		case "cpu.weight":
			n, err := strconv.Atoi(v)
			if err != nil {
				first = firstErr(first, fmt.Errorf("cgroup: %s/cpu.weight: %q is not a weight", c.Path, v))
				continue
			}
			out.CPUWeight = n
		case "memory.max":
			n, err := parseLimit(v)
			if err != nil {
				first = firstErr(first, fmt.Errorf("cgroup: %s/memory.max: %w", c.Path, err))
				continue
			}
			out.MemoryMax, out.WroteMemoryMax = n, true
		case "memory.high":
			n, err := parseLimit(v)
			if err != nil {
				first = firstErr(first, fmt.Errorf("cgroup: %s/memory.high: %w", c.Path, err))
				continue
			}
			out.MemoryHigh, out.WroteMemoryHigh = n, true
		case "pids.max":
			n, err := parseLimit(v)
			if err != nil {
				first = firstErr(first, fmt.Errorf("cgroup: %s/pids.max: %w", c.Path, err))
				continue
			}
			out.PidsMax, out.WrotePidsMax = n, true
		}
	}
	return out, first
}

// parseLimit is a limit file's value: "max" is -1, a count is itself.
func parseLimit(v string) (int64, error) {
	if v == "max" {
		return -1, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%q is not a limit", v)
	}
	return n, nil
}

func firstErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}
