// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"
)

// TestUnixCanonicalIsTheKernelsRule holds UnixCanonical to bpf/include/common.h's tego_unix_canonical, the rule
// connect_unix, sendmsg_unix and step D's hooks admit a pathname by: no empty, "." or ".." component and no
// trailing "/", "/" alone canonical. The supervisor's kernelRefusal and Evaluate's cgroup and bpflsm columns both ask
// it (moved here from the supervisor).
func TestUnixCanonicalIsTheKernelsRule(t *testing.T) {
	for p, want := range map[string]bool{
		"/": true, "/a": true, "/run/listed.dg": true, "/a/.b": true, "/a/..b": true, "/a/b.": true, "/a/...": true,
		"//": false, "/a//b": false, "/a/": false, "/./a": false, "/a/./b": false, "/a/../b": false, "/a/.": false,
		"/a/..": false, "/.": false, "/..": false,
	} {
		if got := UnixCanonical(p); got != want {
			t.Errorf("UnixCanonical(%q) = %t, want %t", p, got, want)
		}
	}
	long := "/" + strings.Repeat("a", unixPathMax-1)
	if !UnixCanonical(long) {
		t.Errorf("a %d-byte name that fills sun_path is canonical", len(long))
	}
}
