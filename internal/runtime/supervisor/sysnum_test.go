// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestDispatchNumbersAreTheKernels checks every (arch, nr) the dispatch table holds, on both architectures, against
// the syscall its entry names in golang.org/x/sys's generated tables (testutil.LinuxSyscalls). The nrX86* and nrARM*
// constants are hand-typed, and every other supervisor test reads them back, so a typo (arm64 mkdirat typed 33,
// which is mknodat) passed; the filter's completeness test asks only that a handler exists for each notified
// number. A typo that lands on another entry's number (mkdirat at 33 replaced mknodat's entry, or was replaced by
// it) panics in buildDispatchFor, so it fails here and in every test that builds a table. enforce/landlock's
// TestFilterNumbersAreTheKernels checks the filter's own tables against the same source, so the two agree per
// syscall name.
func TestDispatchNumbersAreTheKernels(t *testing.T) {
	for _, c := range []struct {
		arch   uint32
		goarch string
	}{{auditArchX86, "amd64"}, {auditArchARM, "arm64"}} {
		canon, err := testutil.LinuxSyscalls(c.goarch)
		if err != nil {
			t.Fatal(err)
		}
		table := buildDispatchFor(c.arch)
		if len(table) < 50 {
			t.Fatalf("%s: dispatch table has %d entries", c.goarch, len(table))
		}
		for k, e := range table {
			want, ok := canon[e.name]
			if !ok {
				t.Errorf("%s: dispatch entry %q (nr %d) names no syscall of this architecture", c.goarch, e.name, k.nr)
				continue
			}
			if uint32(k.nr) != want {
				t.Errorf("%s: %s is dispatched at %d, the kernel's number is %d", c.goarch, e.name, k.nr, want)
			}
		}
	}
}
