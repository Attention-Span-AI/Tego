// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardLogFileSafety(t *testing.T) {
	for _, link := range []bool{false, true} {
		t.Run(map[bool]string{false: "readable", true: "linked"}[link], func(t *testing.T) {
			server := dashboardStandIn(t)
			home := t.TempDir()
			if err := os.Chmod(home, 0700); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(home, ".tego")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			if link {
				if err := os.Symlink(outside, dashboardLog(home)); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(dashboardLog(home), nil, 0644); err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			for name, text := range map[string]string{
				"systemctl":   "exit 0\n",
				"systemd-run": "printf '%s\\n' '" + server.URL + "/?t=0123abcd'\n",
			} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+text), 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			got := guideDashboard(home)
			if b, _ := os.ReadFile(outside); string(b) != "unchanged" {
				t.Fatalf("outside clobbered: %q", b)
			}
			if link {
				if got != "" {
					t.Fatalf("linked log accepted: %s", got)
				}
				return
			}
			if !strings.Contains(got, "?t=0123abcd") {
				t.Fatalf("no link: %q", got)
			}
			fi, err := os.Stat(dashboardLog(home))
			if err != nil || fi.Mode().Perm() != 0600 {
				t.Fatalf("mode: %v %v", fi, err)
			}
		})
	}
}
