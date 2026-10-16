// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package landlock

import "testing"

// TestOmitNamedReadsACommaSeparatedList: the environment's list names syscalls by their table names; blanks and
// empty items are ignored and a name no table has omits nothing. The variable's name is the one the cgroup package's
// governed-run cells set, which cannot import this constant.
func TestOmitNamedReadsACommaSeparatedList(t *testing.T) {
	if EnvTestFilterOmit != "TEGO_TEST_FILTER_OMIT" {
		t.Fatalf("EnvTestFilterOmit is %q: internal/runtime/enforce/cgroup's plane_control_integration_test.go sets the old name", EnvTestFilterOmit)
	}
	omit := omitNamed(" bpf, keyctl ,,add_key,nosuchcall")
	for name, want := range map[string]bool{"bpf": true, "keyctl": true, "add_key": true, "nosuchcall": true,
		"request_key": false, "execve": false, "": false} {
		if got := omit(name); got != want {
			t.Errorf("omit(%q) = %v, want %v", name, got, want)
		}
	}
	if omitNamed("")("bpf") {
		t.Error("an empty list omits a syscall")
	}
}
