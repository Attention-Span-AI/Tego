// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/bits"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// EffectiveTop is the directory ReadEffective stops at (inclusive) for a scope at scopePath whose manager is rooted at
// root: the cgroup2 mount root when the scope is under it, because the kernel holds a run to the lowest ceiling of every
// cgroup above it, those above the delegated subtree too (systemd's user-<uid>.slice carries pids.max); else root, the
// base the manager creates under (a manager over a test directory).
func EffectiveTop(scopePath, root string) string {
	if scopePath == Mount || strings.HasPrefix(scopePath, Mount+"/") {
		return Mount
	}
	return root
}

// ReadEffective is ReadApplied folded with the ceilings of the ancestor cgroups (GAPS N85): for each limit the run
// wrote, the value that holds is the smallest along the chain from c up to top (cpu.max by its bandwidth, quota over
// period; memory.max, memory.high and pids.max by their number, "max" being no ceiling). cpu.weight is a share and not
// a ceiling, so an ancestor's is not folded in. A file an ancestor lacks is no ceiling there only at top itself (the
// cgroup2 root has none); a lower ancestor that lacks it, one that cannot be read or one whose value is not a limit
// leaves that member out of the result, with the first such error returned beside what was read: the scope's own
// number alone is not what holds then, and a number that may be wrong is not offered as a fact. Nothing outside the
// chain is read, and what was read is the chain at this call (the launcher reads it once, at the run's start).
func ReadEffective(c Cgroup, l Limits, top string) (Applied, error) {
	a, first := ReadApplied(c, l)
	if a.CPUMax == "" && !a.WroteMemoryMax && !a.WroteMemoryHigh && !a.WrotePidsMax {
		return a, first
	}
	chain, err := ancestorChain(c.Path, top)
	if err == nil {
		err = hiddenAbove(top)
	}
	if err != nil {
		a.dropCeilings()
		return a, firstErr(first, err)
	}
	if a.CPUMax != "" {
		v, err := foldCPUMax(a.CPUMax, chain, top)
		if err != nil {
			a.CPUMax = ""
			first = firstErr(first, err)
		} else {
			a.CPUMax = v
		}
	}
	for _, m := range []struct {
		file  string
		val   *int64
		wrote *bool
	}{
		{"memory.max", &a.MemoryMax, &a.WroteMemoryMax},
		{"memory.high", &a.MemoryHigh, &a.WroteMemoryHigh},
		{"pids.max", &a.PidsMax, &a.WrotePidsMax},
	} {
		if !*m.wrote {
			continue
		}
		v, err := foldCount(m.file, *m.val, chain, top)
		if err != nil {
			*m.wrote, *m.val = false, 0
			first = firstErr(first, err)
			continue
		}
		*m.val = v
	}
	return a, first
}

// hiddenAbove is an error when top is not the real cgroup2 root, the only cgroup with nothing above it: in a private
// cgroup namespace the mount is a cgroup of its own, whose ceilings the kernel applies together with those of the pod
// and node cgroups above it that this process cannot see (review F1). The real root has neither cgroup.type nor
// cgroup.events and every other cgroup has both, so either file says the chain is cut short; a stat that fails for
// another reason than absence says nothing is known either.
func hiddenAbove(top string) error {
	for _, f := range []string{"cgroup.type", "cgroup.events"} {
		_, err := os.Stat(filepath.Join(top, f))
		if err == nil {
			return fmt.Errorf("cgroup: ancestor ceilings: %s is not the cgroup2 root (it has %s), so the ceilings of the cgroups above it, which the kernel applies, are not visible", top, f)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("cgroup: ancestor ceilings: %s/%s: %w", top, f, err)
		}
	}
	return nil
}

// dropCeilings leaves out every member ReadEffective folds, keeping cpu.weight, which no ancestor changes.
func (a *Applied) dropCeilings() {
	a.CPUMax = ""
	a.MemoryMax, a.MemoryHigh, a.PidsMax = 0, 0, 0
	a.WroteMemoryMax, a.WroteMemoryHigh, a.WrotePidsMax = false, false, false
}

// ancestorChain lists the cgroup directories above scope, nearest first, up to and including top. A scope that is not
// below top has no chain that can be said to hold it: an error, never a walk to the filesystem root.
func ancestorChain(scope, top string) ([]string, error) {
	if top == "" {
		return nil, errors.New("cgroup: ancestor ceilings: no root to read up to")
	}
	scope, top = filepath.Clean(scope), filepath.Clean(top)
	var chain []string
	for dir := filepath.Dir(scope); ; dir = filepath.Dir(dir) {
		chain = append(chain, dir)
		if dir == top {
			return chain, nil
		}
		if dir == "/" || dir == "." {
			return nil, fmt.Errorf("cgroup: ancestor ceilings: %s is not below %s", scope, top)
		}
	}
}

// ancestorValue reads file in dir. present is false when the file does not exist at top, the cgroup2 root, which has no
// limit files: no ceiling there. Anywhere else a missing file is an error, since a scope that holds the file has it in
// every cgroup above it.
func ancestorValue(dir, file, top string) (v string, present bool, err error) {
	f, err := os.Open(filepath.Join(dir, file))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && dir == filepath.Clean(top) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("cgroup: ancestor %s/%s: %w", dir, file, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", false, fmt.Errorf("cgroup: ancestor %s/%s: %w", dir, file, err)
	}
	return strings.TrimSpace(string(data)), true, nil
}

// foldCount is the smallest of own and each ancestor's count for file; -1 is "max", no ceiling.
func foldCount(file string, own int64, chain []string, top string) (int64, error) {
	best := own
	for _, dir := range chain {
		v, ok, err := ancestorValue(dir, file, top)
		if err != nil {
			return 0, err
		}
		if !ok {
			continue
		}
		n, err := parseLimit(v)
		if err != nil {
			return 0, fmt.Errorf("cgroup: ancestor %s/%s: %w", dir, file, err)
		}
		if n >= 0 && (best < 0 || n < best) {
			best = n
		}
	}
	return best, nil
}

// bandwidth is one cpu.max: quota and period in microseconds; unbounded when the quota reads "max".
type bandwidth struct {
	text          string
	quota, period uint64
	unbounded     bool
}

func parseBandwidth(v string) (bandwidth, error) {
	f := strings.Fields(v)
	if len(f) < 1 || len(f) > 2 {
		return bandwidth{}, fmt.Errorf("%q is not a cpu.max", v)
	}
	b := bandwidth{text: v, period: 100000}
	if len(f) == 2 {
		p, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil || p == 0 {
			return bandwidth{}, fmt.Errorf("%q is not a cpu.max", v)
		}
		b.period = p
	}
	if f[0] == "max" {
		b.unbounded = true
		return b, nil
	}
	q, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil {
		return bandwidth{}, fmt.Errorf("%q is not a cpu.max", v)
	}
	b.quota = q
	return b, nil
}

// lessThan reports whether b allows less CPU than o: quota/period compared as quota*o.period against o.quota*period in
// 128 bits. An unbounded one allows the most; two unbounded ones are equal.
func (b bandwidth) lessThan(o bandwidth) bool {
	if b.unbounded {
		return false
	}
	if o.unbounded {
		return true
	}
	h1, l1 := bits.Mul64(b.quota, o.period)
	h2, l2 := bits.Mul64(o.quota, b.period)
	return h1 < h2 || (h1 == h2 && l1 < l2)
}

// foldCPUMax is the cpu.max line that allows the least CPU among own and the ancestors'; own wins a tie, so a chain that
// ceilings nothing returns own's words unchanged.
func foldCPUMax(own string, chain []string, top string) (string, error) {
	var best bandwidth
	var haveBest bool
	for _, dir := range chain {
		v, ok, err := ancestorValue(dir, "cpu.max", top)
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		b, err := parseBandwidth(v)
		if err != nil {
			return "", fmt.Errorf("cgroup: ancestor %s/cpu.max: %w", dir, err)
		}
		if !b.unbounded && (!haveBest || b.lessThan(best)) {
			best, haveBest = b, true
		}
	}
	if !haveBest {
		return own, nil
	}
	o, err := parseBandwidth(own)
	if err != nil {
		return "", fmt.Errorf("cgroup: cpu.max %w: it cannot be compared with an ancestor's", err)
	}
	if best.lessThan(o) {
		return best.text, nil
	}
	return own, nil
}
