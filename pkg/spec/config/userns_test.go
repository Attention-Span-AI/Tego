// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIdentityUIDMap is ADR 0042 (5)(d)'s reading of /proc/self/uid_map: only the identity map of the whole uid
// range is the initial user namespace's. `unshare -r` writes "0 1000 1", a rootless container "0 100000 65536",
// and root's own `unshare -r` "0 0 1": uid 0 in each is not the host's root.
func TestIdentityUIDMap(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want bool
	}{
		{"initial namespace", "         0          0 4294967295\n", true},
		{"no padding", "0 0 4294967295", true},
		{"unshare -r", "         0       1000          1\n", false},
		{"root's unshare -r", "         0          0          1\n", false},
		{"rootless container", "0 100000 65536\n", false},
		{"two lines", "0 0 1\n1 1 4294967294\n", false},
		{"identity twice", "0 0 4294967295\n0 0 4294967295\n", false},
		{"empty: a map not yet written", "", false},
		{"garbage", "0 0 x\n", false},
	} {
		if got := identityUIDMap([]byte(tc.data)); got != tc.want {
			t.Errorf("%s: identityUIDMap(%q) = %v, want %v", tc.name, tc.data, got, tc.want)
		}
	}
}

// TestInitNSRootIsEffectiveRootInTheInitialNamespace: InitNSRoot is the conjunction of the two facts; neither
// alone is root of the host.
func TestInitNSRootIsEffectiveRootInTheInitialNamespace(t *testing.T) {
	for _, tc := range []struct {
		euid int
		init bool
		want bool
	}{{0, true, true}, {0, false, false}, {1000, true, false}, {1000, false, false}} {
		if got := initNSRoot(tc.euid, tc.init); got != tc.want {
			t.Errorf("initNSRoot(%d, %v) = %v, want %v", tc.euid, tc.init, got, tc.want)
		}
	}
}

// TestReadUserNamespace: the reader keeps three answers. A map it read is the initial namespace's or a child's; one
// it could not read (a chroot or minimal container with no /proc) is unknown, never a child, so ADR 0042 (3)(a)'s
// guard reads the capability sets there, and InitialUserNamespace's root gates still take it as not the initial one.
func TestReadUserNamespace(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		name string
		path string
		want UserNamespace
	}{
		{"initial namespace", write("initial", "         0          0 4294967295\n"), UserNamespaceInitial},
		{"unshare -r", write("unshare", "         0       1000          1\n"), UserNamespaceChild},
		{"a map not yet written", write("empty", ""), UserNamespaceChild},
		{"no /proc: the map is missing", filepath.Join(dir, "missing", "uid_map"), UserNamespaceUnknown},
		{"the map is a directory", dir, UserNamespaceUnknown},
	} {
		if got := readUserNamespace(tc.path); got != tc.want {
			t.Errorf("%s: readUserNamespace = %v, want %v", tc.name, got, tc.want)
		}
	}
	if UserNamespace(0) != UserNamespaceUnknown {
		t.Error("the zero UserNamespace is not unknown: a fact never read would pass for a known namespace")
	}
}
