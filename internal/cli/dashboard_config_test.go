// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardConfigurationBoundToReuse(t *testing.T) {
	f := onFixture(t, "fresh")
	s := dashboardStandIn(t)
	if err := os.MkdirAll(filepath.Dir(dashboardLog(f.Home)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dashboardLog(f.Home), []byte(s.URL+"/?t=0123abcd"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := runningDashboard(f.Home); got == "" {
		t.Fatal("matching dashboard was not reused")
	}
	other := filepath.Join(t.TempDir(), "other.yaml")
	b, err := os.ReadFile(f.Config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", other)
	if got := runningDashboard(f.Home); got != "" {
		t.Fatalf("dashboard for another configuration reused: %s", got)
	}
	s = dashboardStandIn(t)
	// This test also checks the unit's argv, without starting a unit or either binary.
	bin := t.TempDir()
	args := filepath.Join(bin, "args")
	t.Setenv("DASHBOARD_ARGS", args)
	for name, text := range map[string]string{
		"systemctl":   "exit 0\n",
		"systemd-run": "printf '%s\\n' \"$@\" > \"$DASHBOARD_ARGS\"\nprintf '%s\\n' '" + s.URL + "/?t=0123abcd'\n",
	} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+text), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	if got := guideDashboard(f.Home); got == "" {
		t.Fatal("configured dashboard did not start")
	}
	argv, _ := os.ReadFile(args)
	if !strings.Contains(string(argv), "--setenv=TEGO_CONFIG="+other) || !strings.Contains(string(argv), "--ledger\n") {
		t.Fatalf("unit lost configuration: %s", argv)
	}
}
