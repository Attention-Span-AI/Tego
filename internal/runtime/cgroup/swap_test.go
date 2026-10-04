// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"reflect"
	"testing"
)

const swapsHeader = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"

// TestUncappedSwap is ADR 0038's reopened bypass (runtime-launch.md R10): a cgroup with the memory controller
// and no memory.swap.max, on a host whose /proc/swaps lists an active area, can be pushed past its memory cap
// into swap, and UncappedSwap names the areas. With the file, with no swap on, without the memory controller
// or with /proc/swaps unreadable, nothing shows the bypass and it names none.
func TestUncappedSwap(t *testing.T) {
	swaps := func(b string, err error) func() ([]byte, error) {
		return func() ([]byte, error) { return []byte(b), err }
	}
	on := swaps(swapsHeader+"/dev/zram0 partition 8388604 0 100\n/swap\\040file file 1048572 0 -2\n", nil)
	for _, tc := range []struct {
		name  string
		files []string
		read  func() ([]byte, error)
		want  []string
	}{
		{"swap accounting off, swap on", []string{"memory.max"}, on, []string{"/dev/zram0", "/swap file"}},
		{"swap accounting on", []string{"memory.max", "memory.swap.max"}, on, nil},
		{"no swap active", []string{"memory.max"}, swaps(swapsHeader, nil), nil},
		{"no /proc/swaps", []string{"memory.max"}, swaps("", errors.New("ENOENT")), nil},
		{"no memory controller", nil, on, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFS(t)
			c, err := fs.Create("a", "r-1")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			for _, f := range tc.files {
				writeCtl(t, c, f, "")
			}
			if got := UncappedSwap(c.Path, tc.read); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("UncappedSwap = %q, want %q", got, tc.want)
			}
			old := readProcSwaps
			readProcSwaps = tc.read
			t.Cleanup(func() { readProcSwaps = old })
			if got := fs.UncappedSwap(c); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("FS.UncappedSwap = %q, want %q", got, tc.want)
			}
		})
	}
}
