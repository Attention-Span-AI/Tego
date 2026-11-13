// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestCompileCapturedChrootMountTables replays the tables a process really sees in a chroot, after pivot_root, in
// systemd-nspawn and in bubblewrap (testdata/chroot-mountinfo, captured in a guest) through the 19 baseline contracts.
// A table without a row at / exists only where the process's root is not a mount's root (a chroot into a plain
// folder): there every write and ask grant is refused, as it was by the per-path analysis before the one reader
// (it refused the same 17 contracts, because / itself has no row and every walk starts there). A chroot whose root is a mount point, pivot_root and bubblewrap list their root at / and accept all 19.
// nspawn's three unlinked-root rows are valid; their old names do not establish aliases.
func TestCompileCapturedChrootMountTables(t *testing.T) {
	refusedAll := []string{
		"examples__agents__anthropic-sdk-python.yaml", "examples__agents__claude-code.yaml", "examples__agents__custom-agent.yaml",
		"examples__tests__agent.yaml", "internal__cli__agent.starter.yaml",
		"preset__no-prod", "preset__no-secrets", "preset__repo-only-writes",
		"variant__bpflsm-open", "variant__cgroup-all", "variant__deny-list-exec", "variant__landlock-unix", "variant__reads-direct",
		"variant__grant-devshm", "variant__grant-home", "variant__grant-project", "variant__grant-tmp",
	}
	var layouts []mountLayout
	for _, c := range []struct {
		name     string
		accepted int
	}{
		{"chroot-dir", 2}, {"chroot-dir-proc-only", 2}, {"chroot-selfbind", 19}, {"chroot-own-fs", 19},
		{"pivot-root", 19}, {"nspawn", 19}, {"bwrap", 19},
	} {
		data, err := os.ReadFile(filepath.Join("testdata", "chroot-mountinfo", c.name+".mountinfo"))
		if err != nil {
			t.Fatal(err)
		}
		rows := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
		var refused []string
		if c.accepted == 2 {
			refused = slices.Clone(refusedAll)
		}
		layouts = append(layouts, mountLayout{name: "captured " + c.name, refused: refused, accepted: c.accepted,
			lines: func(_, cwd string) []string {
				out := make([]string, 0, len(rows))
				for _, r := range rows {
					fields := strings.Split(r, " ")
					if len(fields) > 4 && fields[4] == "/home/runner/proj" {
						fields[4] = cwd
					}
					out = append(out, strings.Join(fields, " "))
				}
				return out
			}})
	}
	checkMountLayoutsCompatibility(t, layouts, false)
}
