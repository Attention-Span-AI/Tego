// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// TestTOMOYOFactsDirIsTheAdministrators: tomoyo.facts_dir names which files stand for TOMOYO's policy for a held open
// (ADR 0041, 2026-11-22), so it is honoured from /etc/tego/config.yaml only: an invoking user's layer that sets it is
// ignored with a warning, the default is empty (the kernel's own path), and a relative, unclean or root path is refused
// at its line. There is no key that assumes TOMOYO enforces nothing.
func TestTOMOYOFactsDirIsTheAdministrators(t *testing.T) {
	m, diags := mustLoad(t, layers(t, trustedDir(t), "tomoyo:\n  facts_dir: /run/tego-tomoyo\n", "tomoyo:\n  facts_dir: /tmp/mine\n", ""), "")
	if m.TOMOYO.FactsDir.Value != "/run/tego-tomoyo" || m.TOMOYO.FactsDir.Source.Layer != LayerEtc {
		t.Errorf("tomoyo.facts_dir %+v, want /run/tego-tomoyo from /etc", m.TOMOYO.FactsDir)
	}
	if countCode(diags, CodeIgnored) != 1 || !strings.Contains(diags[0].Message, "tomoyo.facts_dir is honoured from /etc/tego/config.yaml only") {
		t.Errorf("diags %v", diags)
	}
	// Only the invoking user's layer sets it: nothing is honoured.
	m, diags = mustLoad(t, layers(t, trustedDir(t), "", "tomoyo:\n  facts_dir: /tmp/mine\n", ""), "")
	if m.TOMOYO.FactsDir.Value != "" || countCode(diags, CodeIgnored) != 1 {
		t.Errorf("a user layer's tomoyo.facts_dir %q, diags %v; want it ignored with a warning", m.TOMOYO.FactsDir.Value, diags)
	}
	if m, _ := mustLoad(t, layers(t, trustedDir(t), "", "", ""), ""); m.TOMOYO.FactsDir.Value != "" {
		t.Errorf("default tomoyo.facts_dir %q, want empty", m.TOMOYO.FactsDir.Value)
	}
	for _, bad := range []string{"relative/dir", "/run/../run/x", "/run//x", "/run/x/", "/"} {
		_, ds := parseLayer("/etc/tego/config.yaml", []byte("tomoyo:\n  facts_dir: "+bad+"\n"))
		if len(ds) != 1 || !strings.Contains(ds[0].Message, "tomoyo.facts_dir: ") {
			t.Errorf("tomoyo.facts_dir %q parsed: %v", bad, ds)
		}
	}
	_, ds := parseLayer("/etc/tego/config.yaml", []byte("tomoyo:\n  assume_unenforced: true\n"))
	if len(ds) != 1 || !strings.Contains(ds[0].Message, "unknown key tomoyo.assume_unenforced") {
		t.Errorf("an assume-style key parsed: %v", ds)
	}
}
