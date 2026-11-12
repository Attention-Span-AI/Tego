// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestStartedByAnotherReadsTheLoginAndTheProcessTree: whether the person who reads tego's next: line is another user
// than the one tego runs as, from the login uid and the real uids of the process's ancestors, never the environment.
// The trees are the guests' (acceptance 3, 2026-11-11): uid 1000 the administrator, 1002 the service account.
func TestStartedByAnotherReadsTheLoginAndTheProcessTree(t *testing.T) {
	type proc struct{ pid, ppid, uid int }
	const unset = 4294967295
	for _, tc := range []struct {
		name     string
		loginuid int // -1: no loginuid file (a kernel without audit)
		tree     []proc
		want     bool
	}{
		{"sudo -u svc over SSH", 1000, []proc{{50, 40, 1002}, {40, 30, 0}, {30, 20, 0}, {20, 10, 1000}, {10, 5, 1000}, {5, 1, 0}}, true},
		{"sudo -u svc, no login uid", unset, []proc{{50, 40, 1002}, {40, 30, 0}, {30, 20, 0}, {20, 10, 1000}, {10, 5, 1000}, {5, 1, 0}}, true},
		{"sudo -u svc, no audit", -1, []proc{{50, 40, 1002}, {40, 30, 0}, {30, 20, 0}, {20, 1, 1000}}, true},
		{"sudo su -s /bin/bash svc, then tego", unset, []proc{{50, 45, 1002}, {45, 40, 1002}, {40, 30, 0}, {30, 25, 0}, {25, 20, 0}, {20, 1, 1000}}, true},
		{"root's console, su -s /bin/sh svc", 0, []proc{{50, 40, 1002}, {40, 30, 0}, {30, 1, 0}}, true},
		{"its own SSH login", 1002, []proc{{50, 40, 1002}, {40, 30, 1002}, {30, 20, 0}, {20, 1, 0}}, false},
		{"its own scope", unset, []proc{{50, 40, 1002}, {40, 30, 1002}, {30, 1, 1002}}, false},
		{"its own login, sudo -u itself", 1002, []proc{{50, 40, 1002}, {40, 30, 0}, {30, 20, 1002}, {20, 1, 0}}, false},
		{"a system service", unset, []proc{{50, 1, 1002}}, false},
		{"root's ancestors hidden (hidepid)", unset, []proc{{50, 40, 1002}}, false},
		{"another user namespace's process above", unset, []proc{{50, 40, 1002}, {40, 30, 65534}, {30, 1, 1000}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, p := range tc.tree {
				dir := filepath.Join(root, strconv.Itoa(p.pid))
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				status := fmt.Sprintf("Name:\tx\nPPid:\t%d\nUid:\t%d\t%d\t%d\t%d\n", p.ppid, p.uid, p.uid, p.uid, p.uid)
				if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.loginuid >= 0 {
				if err := os.WriteFile(filepath.Join(root, "50", "loginuid"), []byte(strconv.Itoa(tc.loginuid)), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := StartedByAnother(root, 50, 1002); got != tc.want {
				t.Errorf("StartedByAnother = %v, want %v", got, tc.want)
			}
		})
	}
}
