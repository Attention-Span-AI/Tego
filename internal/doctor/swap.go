// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
)

// swapFix is D9's remedy: swap accounting back on, or no swap to bypass the cap with.
const swapFix = "enable swap accounting: remove swapaccount=0 and cgroup.memory=noswap from the kernel command " +
	"line (or boot with swapaccount=1) and reboot, or turn swap off (swapoff -a)"

// probeSwap is D9: whether a run's memory cap holds the swap too (ADR 0038). It asks a cgroup of this
// process's own that has the memory controller, the nearest from its own cgroup up, since only such a cgroup
// shows whether the kernel gives it memory.swap.max.
func probeSwap() Result {
	data, _ := os.ReadFile("/proc/self/cgroup")
	return probeSwapIn(memoryCgroup(cgroup.Mount, data), cgroup.ReadProcSwaps)
}

// probeSwapIn is D9 against a cgroup directory ("" for none found) and a /proc/swaps reader. It fails when the
// directory has no memory.swap.max while swap is on (cgroup.UncappedSwap): a run's memory cap can then be
// exceeded into swap. It gates no tier: a run on such a host records the gap itself.
func probeSwapIn(dir string, readSwaps func() ([]byte, error)) Result {
	if dir == "" {
		return Result{ID: CheckSwap, OK: true, Detail: "no cgroup of this process has the memory controller to " +
			"ask; each run checks its own cgroup and records a limits gap when its memory cap does not hold swap"}
	}
	if areas := cgroup.UncappedSwap(dir, readSwaps); len(areas) > 0 {
		return Result{ID: CheckSwap, Detail: fmt.Sprintf("%s has no memory.swap.max (the kernel accounts no swap "+
			"to cgroups) while swap is on (%s): a run's memory cap can be exceeded into swap",
			dir, strings.Join(areas, ", ")), Fix: swapFix}
	}
	if _, err := os.Stat(filepath.Join(dir, "memory.swap.max")); errors.Is(err, fs.ErrNotExist) {
		return Result{ID: CheckSwap, OK: true, Detail: "the kernel accounts no swap to cgroups, and no swap is on"}
	}
	return Result{ID: CheckSwap, OK: true, Detail: "memory.swap.max present: a run's memory cap holds swap too"}
}

// memoryCgroup is the nearest cgroup, from the one procCgroup names up to below the mount root, that has the
// memory controller (memory.max); "" when none does or procCgroup names no unified cgroup.
func memoryCgroup(mount string, procCgroup []byte) string {
	var rel string
	sc := bufio.NewScanner(bytes.NewReader(procCgroup))
	for sc.Scan() {
		if p, ok := strings.CutPrefix(sc.Text(), "0::"); ok {
			rel = p
			break
		}
	}
	if !strings.HasPrefix(rel, "/") {
		return ""
	}
	for dir := filepath.Join(mount, filepath.Clean(rel)); dir != mount && strings.HasPrefix(dir, mount+"/"); dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "memory.max")); err == nil {
			return dir
		}
	}
	return ""
}
