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

func TestDashboardDoesNotReuseReadableLog(t *testing.T) {
	home := t.TempDir()
	s := dashboardStandIn(t)
	if err := os.Mkdir(filepath.Join(home, ".tego"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dashboardLog(home), []byte(s.URL+"/?t=0123abcd"), 0644); err != nil {
		t.Fatal(err)
	}
	if u, _ := dashboardAt(home); u != "" {
		t.Fatalf("exposed sign-in link reused: %s", u)
	}
}

func TestDashboardRotatesExposedSignIn(t *testing.T) {
	home := t.TempDir()
	old := dashboardStandIn(t)
	fresh := dashboardStandIn(t, "4567cdef")
	if err := os.Mkdir(filepath.Join(home, ".tego"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dashboardLog(home), []byte(old.URL+"/?t=0123abcd"), 0644); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	link := fresh.URL + "/?t=4567cdef"
	for name, text := range map[string]string{"systemctl": "exit 0\n", "systemd-run": "printf '%s\\n' '" + link + "'\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+text), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	if got := guideDashboard(home); got != link {
		t.Fatalf("exposed link not rotated: %q, want %q", got, link)
	}
	if fi, err := os.Stat(dashboardLog(home)); err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("new log: %v %v", fi, err)
	}
}
