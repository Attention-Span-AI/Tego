// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// BenchmarkDecide is one exec's whole command-rule decision under deny: [rm -r] and allow: [git status]: an ordinary
// exec no rule guards (ls, one link), an ordinary guarded one (rm -f, one link), the same two on a file of 116 links
// (Ubuntu's uutils), and a name form only the multicall readings guard (argv[0] xrm through /proc/self/fd/3).
func BenchmarkDecide(b *testing.B) {
	ix := index(b, "deny: rm -r", "allow: git status")
	for _, c := range []struct {
		name string
		f    execmatch.Facts
	}{
		{"ordinary-unguarded", execmatch.Facts{Requested: "ls", Path: "/usr/bin/ls", Image: "ls", Argv0: "ls", Argv: []string{"ls", "-l", "out"}, ArgvComplete: true, Links: 1}},
		{"ordinary-guarded", execmatch.Facts{Requested: "rm", Path: "/usr/bin/rm", Image: "rm", Argv0: "rm", Argv: []string{"rm", "-f", "x"}, ArgvComplete: true, Links: 1}},
		{"multicall-unguarded", execmatch.Facts{Requested: "ls", Path: "/usr/bin/ls", Image: "ls", Argv0: "ls", Argv: []string{"ls", "-l", "out"}, ArgvComplete: true, Links: 116}},
		{"multicall-guarded", execmatch.Facts{Requested: "rm", Path: "/usr/bin/rm", Image: "rm", Argv0: "rm", Argv: []string{"rm", "-f", "x"}, ArgvComplete: true, Links: 116}},
		{"multicall-xrm", execmatch.Facts{Requested: "3", Path: "/proc/self/fd/3", Image: "ls", Argv0: "xrm", Argv: []string{"xrm", "-f", "x"}, ArgvComplete: true, Links: 116}},
	} {
		b.Run(c.name, func(b *testing.B) {
			f := c.f
			b.ReportAllocs()
			for b.Loop() {
				ix.Decide(&f)
			}
		})
	}
}
