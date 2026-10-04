// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ProcSwaps is the kernel's list of the active swap areas, one line each after a header.
const ProcSwaps = "/proc/swaps"

// fileMemoryMax is the memory controller's hard cap, present in every non-root cgroup the controller is enabled
// for; its presence is what says a missing memory.swap.max is swap accounting's absence and not the controller's.
const fileMemoryMax = "memory.max"

// ActiveSwaps reads /proc/swaps' content: the Filename column of each active area. Empty when no swap is on.
func ActiveSwaps(procSwaps []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(procSwaps))
	first := true
	for sc.Scan() {
		if first {
			first = false // "Filename Type Size Used Priority"
			continue
		}
		if f := strings.Fields(sc.Text()); len(f) > 0 {
			out = append(out, unescapeSwapName(f[0]))
		}
	}
	return out
}

// unescapeSwapName undoes the octal escapes /proc/swaps writes for white space in a path (seq_file_path's
// " \t\n\\"), so a swap file with a space in its name is named as it is.
func unescapeSwapName(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			if v, ok := octal3(s[i+1:]); ok {
				b.WriteByte(v)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// octal3 reads three octal digits at the start of s.
func octal3(s string) (byte, bool) {
	if len(s) < 3 {
		return 0, false
	}
	var v int
	for _, c := range s[:3] {
		if c < '0' || c > '7' {
			return 0, false
		}
		v = v*8 + int(c-'0')
	}
	if v > 0xff {
		return 0, false
	}
	return byte(v), true
}

// UncappedSwap reports the active swap areas a memory cap on dir cannot keep dir's processes out of: dir has
// the memory controller (memory.max) and no memory.swap.max, which is a kernel that accounts no swap to
// cgroups (swapaccount=0 or cgroup.memory=noswap on its command line) while readSwaps lists an active area.
// There memory.max still caps the RAM, and the kernel reclaims the processes' anonymous pages to swap instead
// of OOM-killing them, so the cap can be exceeded by the size of the swap (runtime-launch.md R10, ADR 0038).
// Nil when memory.swap.max exists, when no swap is active, and when dir has no memory controller or any of
// the three cannot be read: nothing then shows the bypass.
func UncappedSwap(dir string, readSwaps func() ([]byte, error)) []string {
	if _, err := os.Stat(filepath.Join(dir, fileMemoryMax)); err != nil {
		return nil
	}
	if _, err := os.Stat(filepath.Join(dir, fileSwapMax)); !errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	b, err := readSwaps()
	if err != nil {
		return nil
	}
	return ActiveSwaps(b)
}

// ReadProcSwaps reads ProcSwaps.
func ReadProcSwaps() ([]byte, error) { return os.ReadFile(ProcSwaps) }

// readProcSwaps is what FS.UncappedSwap reads the host's swap areas with; a test describes a host with it.
var readProcSwaps = ReadProcSwaps

// UncappedSwap is the package function for c's own directory against this host's /proc/swaps: what a run
// whose limits hold a memory cap records as a gap (SetLimits skips the missing memory.swap.max).
func (fs *FS) UncappedSwap(c Cgroup) []string { return UncappedSwap(c.Path, readProcSwaps) }
