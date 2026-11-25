// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// TestLSMListFileIsTheAdministrators: lsm.list_file names the file a held open reads the active security-module list from
// when the kernel's own two ways fail (ADR 0041, 2026-11-25), so it is honoured from /etc/tego/config.yaml only: an
// invoking user's layer that sets it is ignored with a warning, the default is empty (no file), and a relative, unclean or
// root path is refused at its line.
func TestLSMListFileIsTheAdministrators(t *testing.T) {
	m, diags := mustLoad(t, layers(t, trustedDir(t), "lsm:\n  list_file: /run/tego-lsm/lsm-list\n", "lsm:\n  list_file: /tmp/mine\n", ""), "")
	if m.LSM.ListFile.Value != "/run/tego-lsm/lsm-list" || m.LSM.ListFile.Source.Layer != LayerEtc {
		t.Errorf("lsm.list_file %+v, want /run/tego-lsm/lsm-list from /etc", m.LSM.ListFile)
	}
	if countCode(diags, CodeIgnored) != 1 || !strings.Contains(diags[0].Message, "lsm.list_file is honoured from /etc/tego/config.yaml only") {
		t.Errorf("diags %v", diags)
	}
	m, diags = mustLoad(t, layers(t, trustedDir(t), "", "lsm:\n  list_file: /tmp/mine\n", ""), "")
	if m.LSM.ListFile.Value != "" || countCode(diags, CodeIgnored) != 1 {
		t.Errorf("a user layer's lsm.list_file %q, diags %v; want it ignored with a warning", m.LSM.ListFile.Value, diags)
	}
	if m, _ := mustLoad(t, layers(t, trustedDir(t), "", "", ""), ""); m.LSM.ListFile.Value != "" {
		t.Errorf("default lsm.list_file %q, want empty", m.LSM.ListFile.Value)
	}
	for _, bad := range []string{"relative/lsm", "/run/../run/x", "/run//x", "/run/x/", "/"} {
		_, ds := parseLayer("/etc/tego/config.yaml", []byte("lsm:\n  list_file: "+bad+"\n"))
		if len(ds) != 1 || !strings.Contains(ds[0].Message, "lsm.list_file: ") {
			t.Errorf("lsm.list_file %q parsed: %v", bad, ds)
		}
	}
	_, ds := parseLayer("/etc/tego/config.yaml", []byte("lsm:\n  assume: [capability]\n"))
	if len(ds) != 1 || !strings.Contains(ds[0].Message, "unknown key lsm.assume") {
		t.Errorf("a key that supplies a list inline parsed: %v", ds)
	}
	// It is shown with its source where the effective settings are listed.
	var found bool
	m, _ = mustLoad(t, layers(t, trustedDir(t), "lsm:\n  list_file: /run/tego-lsm/lsm-list\n", "", ""), "")
	for _, v := range m.Effective() {
		if v.Key == "lsm.list_file" && v.Value == "/run/tego-lsm/lsm-list" {
			found = true
		}
	}
	if !found {
		t.Error("lsm.list_file is not among the effective settings")
	}
}
