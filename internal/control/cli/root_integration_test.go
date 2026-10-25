// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestControlRefusesRootAsRoot: [control-as-root] at a real euid 0 (test/vm/root-suites.sh runs it as root in a KVM
// guest, CI's root-suites job under sudo). The guard reads this process's own euid and capability sets, so Main
// itself, not a privilege the test made up, refuses every command, version and help included, before it does
// anything.
func TestControlRefusesRootAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: test/vm/root-suites.sh runs it")
	}
	if p := hostPrivilege(); p.euid != 0 || p.effective == 0 || p.permitted == 0 {
		t.Fatalf("root's privilege read as %+v, want euid 0 with its capabilities", p)
	}
	argvs := [][]string{nil, {"help"}, {"--help"}, {"version"}, {"nonesuch"}}
	for _, n := range Names() {
		argvs = append(argvs, []string{n}, []string{n, "--json"})
	}
	for _, argv := range argvs {
		var out, errs bytes.Buffer
		code := Main(append([]string{handoff.Name}, argv...), &out, &errs)
		if code != identity.ExitError || out.Len() != 0 || !strings.Contains(errs.String(), "["+handoff.CodeAsRoot+"]") {
			t.Errorf("%v as root: exit %d stdout %q stderr %q, want 125 [%s] and nothing else", argv, code, out.String(), errs.String(), handoff.CodeAsRoot)
		}
		if !strings.Contains(errs.String(), "never as root") {
			t.Errorf("%v as root: stderr %q, want the root sentence (euid 0 is named before the capabilities)", argv, errs.String())
		}
	}
}
