// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"github.com/attention-span-ai/tego/pkg/spec/config"
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
	startedBy(t, f.Home, thisProgramFile(t), s.URL+"/?t=0123abcd")
	if got := runningDashboard(f.Home); got == "" {
		t.Fatal("matching dashboard was not reused")
	}
	otherDir := t.TempDir()
	if err := os.Chmod(otherDir, 0700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(otherDir, "other.yaml")
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
	if got := guideDashboard(context.Background(), f.Home); got == "" {
		t.Fatal("configured dashboard did not start")
	}
	argv, _ := os.ReadFile(args)
	if !strings.Contains(string(argv), "--setenv=TEGO_CONFIG="+other) || !strings.Contains(string(argv), "--ledger\n") {
		t.Fatalf("unit lost configuration: %s", argv)
	}
}

func TestDashboardConfigurationLayers(t *testing.T) {
	for _, layer := range []string{"etc", "user", "env"} {
		t.Run(layer, func(t *testing.T) {
			f := onFixture(t, "fresh")
			paths := map[string]string{}
			for _, name := range []string{"etc", "user", "env"} {
				dir := t.TempDir()
				if err := os.Chmod(dir, 0700); err != nil {
					t.Fatal(err)
				}
				p := filepath.Join(dir, name+".yaml")
				if err := os.WriteFile(p, []byte("version: 0\nledger_root: "+filepath.Join(f.Home, "runs")+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				paths[name] = p
			}
			// This account cannot create a trusted root-owned system layer. Keep
			// a previously known dashboard to prove unknown layers refuse its link.
			server := dashboardStandIn(t)
			old := machineSources
			t.Cleanup(func() { machineSources = old })
			machineSources = func(int, bool) (config.Sources, string, []config.Diagnostic) {
				return config.Sources{Etc: paths["etc"], User: paths["user"], EnvFile: paths["env"]}, f.Home, nil
			}
			t.Setenv(config.EnvConfigVar, paths["env"])
			if layer != "etc" {
				// Only the requested, user-owned layer is selected in these cases.
				machineSources = func(int, bool) (config.Sources, string, []config.Diagnostic) {
					src := config.Sources{}
					if layer == "user" {
						src.User = paths[layer]
					} else {
						src.EnvFile = paths[layer]
					}
					return src, f.Home, nil
				}
				server = dashboardStandIn(t)
			}
			link := server.URL + "/?t=0123abcd"
			if layer == "etc" {
				if _, _, _, err := dashboardConfiguration(); err == nil {
					t.Fatal("unknown system layer was treated as an authenticated configuration")
				}
				if probeDashboard(link) {
					t.Fatal("unknown system layer reused a dashboard link")
				}
			} else if !probeDashboard(link) {
				t.Fatal("loaded configuration does not match itself")
			}
			b, err := os.ReadFile(paths[layer])
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(paths[layer], append(b, []byte("limits: {tokens: 20}\n")...), 0600); err != nil {
				t.Fatal(err)
			}
			if probeDashboard(link) {
				m, ds, e := loadMachine(config.TrustWarn)
				t.Fatalf("dashboard with stale %s configuration was reused; tokens=%+v diags=%v error=%v", layer, m.Limits.Tokens, ds, e)
			}
		})
	}
}

func TestDashboardLedgerSpellings(t *testing.T) {
	f := onFixture(t, "fresh")
	root := filepath.Join(t.TempDir(), "ledger")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	link := root + "-link"
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	old := ledgerRootOf
	t.Cleanup(func() { ledgerRootOf = old })
	ledgerRootOf = func(*config.Machine) (string, error) { return root, nil }
	_, _, want, err := dashboardConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(f.Project, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root + "/", rel, link} {
		ledgerRootOf = func(*config.Machine) (string, error) { return path, nil }
		_, _, got, err := dashboardConfiguration()
		if err != nil || got != want {
			t.Errorf("ledger %q: scope %q, want %q (%v)", path, got, want, err)
		}
	}
	t.Setenv(config.EnvConfigVar, "")
	_, _, a, err := dashboardConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	_, _, b, err := dashboardConfiguration()
	if err != nil || a != b {
		t.Fatalf("unset configuration: %q/%q %v", a, b, err)
	}
}
