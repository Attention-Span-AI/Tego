// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The owner-only authority premise requires an enforcing run to stay in its
// governed cgroup. A grant must not expose migration controls under any name.
// These are compiler tests over synthetic mounts, not kernel qualification.
func TestLocalRolesCgroupAliasesRefuseGrants(t *testing.T) {
	for _, tc := range []struct {
		name, fs, root, grant string
	}{
		{"bind_alias", "cgroup2", "/user.slice/delegated", "alias"},
		{"mounted_beneath_grant", "cgroup2", "/", "."},
		{"v1_controller", "cgroup", "/delegated", "alias"},
		{"ancestor_of_alias", "cgroup2", "/user.slice/delegated", "."},
		{"symlink_to_alias", "cgroup2", "/user.slice/delegated", "link"},
		{"inside_alias", "cgroup2", "/user.slice/delegated", "alias/outside"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			base := filepath.Join(f.project, "granted")
			alias := filepath.Join(base, "alias")
			if err := os.MkdirAll(filepath.Join(alias, "outside"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(alias, filepath.Join(base, "link")); err != nil {
				t.Fatal(err)
			}
			mi := fakeMountInfo(f, fmt.Sprintf("5 1 0:30 %s %s rw - %s cgroup rw", tc.root, alias, tc.fs))
			grant := filepath.Join(base, tc.grant)
			for _, kind := range []string{"write", "ask"} {
				t.Run(kind, func(t *testing.T) {
					body := strings.Replace(writeSection(grant), "write:", kind+":", 1)
					_, ds, err := Compile(f.load(body), f.machine, f.opts(mi)...)
					want := fmt.Sprintf("reaches the %s filesystem mounted at %s, a kernel control filesystem, whatever path names it", tc.fs, alias)
					if err == nil {
						t.Fatalf("fs.%s grant to %s compiled: writable cgroup migration controls escaped R10", kind, grant)
					}
					found := false
					for _, d := range ds {
						if d.Code == CodeContradiction && strings.Contains(d.Message, "fs."+kind) && strings.Contains(d.Message, want) {
							t.Log(d.Message)
							found = true
						}
					}
					if !found {
						t.Fatalf("missing mount-identity refusal %q: %s", want, render(ds))
					}
				})
			}
			// Ordinary storage beside the control mount remains usable.
			side := filepath.Join(f.project, "storage")
			if err := os.Mkdir(side, 0o755); err != nil {
				t.Fatal(err)
			}
			f.compile(f.load(writeSection(side)), mi)
		})
	}
}
