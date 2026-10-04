// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A path setting is an absolute path or "~/...": null, "~", relative and "~user/x" load as neither.
func TestPathSettingsValidated(t *testing.T) {
	bad := []struct{ key, val string }{
		{"ledger_root", "null"}, {"ledger_root", "~"}, {"ledger_root", ""}, {"ledger_root", "runs"},
		{"ledger_root", "~bob/x"}, {"prices", "null"}, {"prices", "~"}, {"profiles", "rel/dir"},
		{"registry", "rel/dir"}, {"registry", "~"}, {"privileged_binary", "null"}, {"privileged_binary", "bin/x"},
		// A path through procfs names a file relative to the process that opens it.
		{"registry", "/proc/self/cwd/reg"}, {"prices", "/proc/thread-self/cwd/p.yaml"}, {"profiles", "/dev/fd/../cwd/p"},
		{"ledger_root", "/proc/self/cwd/runs"}, {"privileged_binary", "/proc/self/exe"},
	}
	for _, c := range bad {
		_, diags := parseLayer("x.yaml", []byte(c.key+": "+c.val+"\n"))
		if !HasErrors(diags) {
			t.Errorf("%s: %q loaded", c.key, c.val)
		}
	}
	for _, c := range []struct{ key, val string }{
		{"ledger_root", "/var/runs"}, {"ledger_root", "~/.tego/runs"}, {"prices", "/etc/p.yaml"},
		{"prices", `""`}, {"profiles", "~/p"}, {"privileged_binary", "/usr/bin/tego"},
		{"registry", "~/r"}, {"registry", "/srv/tego"}, {"registry", `""`},
	} {
		if _, diags := parseLayer("x.yaml", []byte(c.key+": "+c.val+"\n")); HasErrors(diags) {
			t.Errorf("%s: %q refused: %v", c.key, c.val, diags)
		}
	}
}

// With no passwd home, prices, profiles and registry must not stay "~/..." (read against the cwd).
func TestNoHomeDropsRelativePathSettings(t *testing.T) {
	m, diags, err := LoadSources(Sources{}, "", 1000, TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	if m.Prices.Value != "" || m.Profiles.Value != "" || m.Registry.Value != "" {
		t.Errorf("prices %q profiles %q registry %q kept a literal ~", m.Prices.Value, m.Profiles.Value, m.Registry.Value)
	}
	if len(diags) != 0 {
		t.Errorf("the built-in default is not a choice to warn about: %v", diags)
	}
	src := layers(t, trustedDir(t), "prices: ~/p.yaml\n", "", "")
	m, diags, err = LoadSources(src, "", 1000, TrustAbort)
	if err != nil || m.Prices.Value != "" {
		t.Fatalf("prices %q, %v", m.Prices.Value, err)
	}
	if !slices.ContainsFunc(diags, func(d Diagnostic) bool { return d.Code == CodeIgnored && strings.Contains(d.Message, "~/p.yaml") }) {
		t.Errorf("no diagnostic for a configured prices: %v", diags)
	}
	if m.LedgerRoot.Value != "~/.tego/runs" {
		t.Errorf("ledger_root %q: the run refuses it, so it must stay for that", m.LedgerRoot.Value)
	}
}

func TestCostNegativeZeroRefused(t *testing.T) {
	for _, k := range []string{"cost_usd: -0", "cost_usd: -0.0"} {
		if _, diags := parseLayer("x.yaml", []byte("limits:\n  "+k+"\n")); !HasErrors(diags) {
			t.Errorf("%s loaded", k)
		}
	}
}

// The user registry (docs/p0/agent-contract.md R26) is ~/.config/tego by default, outside tego's own directory
// ~/.tego that every run read-denies (R6a), expanded against the passwd home, and a
// layer may move it, or turn it off with "".
func TestRegistryDefaultsToTheTegoHomeAndALayerMovesIt(t *testing.T) {
	m, _, err := LoadSources(Sources{}, "/home/u", os.Getuid(), TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	if m.Registry.Value != "/home/u/.config/tego" || m.Registry.Source.Layer != LayerBuiltin {
		t.Errorf("registry = %q from %v, want /home/u/.config/tego built in", m.Registry.Value, m.Registry.Source.Layer)
	}
	for val, want := range map[string]string{"/srv/tego": "/srv/tego", "~/reg": "/home/u/reg", `""`: ""} {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil { // the layer's directory is trusted only when no one else writes it
			t.Fatal(err)
		}
		file := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(file, []byte("version: 0\nregistry: "+val+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		m, diags, err := LoadSources(Sources{EnvFile: file}, "/home/u", os.Getuid(), TrustAbort)
		if err != nil || HasErrors(diags) {
			t.Fatalf("registry: %s: %v %v", val, err, diags)
		}
		if m.Registry.Value != want || m.Registry.Source.File != file {
			t.Errorf("registry: %s = %q from %q, want %q from the layer", val, m.Registry.Value, m.Registry.Source.File, want)
		}
	}
}
