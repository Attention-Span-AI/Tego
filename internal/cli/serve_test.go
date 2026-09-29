// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	controlcli "github.com/attention-span-ai/tego/internal/control/cli"
	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestServeWithoutControlSaysNotInstalled is limits-check-doctor-cli.md R35 as amended for ADR 0100: `tego serve`
// hands off to tego-control, and with no tego-control beside this binary (the test binary's directory has none) it
// says [control-not-installed] on one line, exits with that code's pkg/spec/identity exit and runs nothing. Every
// other handed-off noun says the same. The usage text lists each of them as "(tego-control)".
func TestServeWithoutControlSaysNotInstalled(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(self), handoff.Name)); err == nil {
		t.Skip("a tego-control is beside the test binary")
	}
	want := handoff.CodeNotInstalled
	if os.Geteuid() == 0 {
		want = handoff.CodeAsRoot // the handoff refuses root before it looks for the file
	}
	for _, n := range handoff.Nouns() {
		code, out, errs := run(t, n.Name, "--listen", "127.0.0.1:7433")
		if code != handoff.Exit(want) || code != identity.ExitError {
			t.Errorf("tego %s: exit %d, want %d", n.Name, code, handoff.Exit(want))
		}
		if out != "" || strings.Count(errs, "\n") != 1 || !strings.Contains(errs, "["+want+"]") || !strings.HasPrefix(errs, "tego "+n.Name+": ") {
			t.Errorf("tego %s: stdout %q stderr %q, want one line [%s]", n.Name, out, errs, want)
		}
	}
	// Help lists a built noun as a (tego-control) command, and names an unbuilt one only on its "planned" line.
	_, out, _ := run(t, "help")
	for _, n := range handoff.Nouns() {
		listed := strings.Contains(out, "\n  "+n.Name+" ") || strings.Contains(out, "("+handoff.Name+") "+n.Summary)
		if n.Built && !listed {
			t.Errorf("usage does not list built %s as (tego-control): %q", n.Name, out)
		}
		if !n.Built && listed {
			t.Errorf("usage lists %s, which this build does not have, as a command: %q", n.Name, out)
		}
	}
	if planned := handoff.Planned(); len(planned) == 0 {
		if strings.Contains(out, "planned, not in this build") {
			t.Errorf("usage has a planned line, and no noun is planned: %q", out)
		}
	} else if want := "\nplanned, not in this build: " + strings.Join(planned, ", ") + "\n"; !strings.Contains(out, want) {
		t.Errorf("usage lacks %q: %q", want, out)
	}
}

// TestHandedOffNounsTakeArgumentsVerbatim: tego parses none of a handed-off noun's flags; they reach the handoff
// untouched, -h included.
func TestHandedOffNounsTakeArgumentsVerbatim(t *testing.T) {
	saved := openControl
	t.Cleanup(func() { openControl = saved })
	calls := 0
	openControl = func() (*handoff.Binary, error) {
		calls++
		return nil, &handoff.Error{Code: handoff.CodeUnpinned, What: "test", Fix: "none"}
	}
	for _, args := range [][]string{{"serve", "-h"}, {"serve", "--nonesuch", "--", "x"}, {"serve"}} {
		code, _, errs := run(t, args...)
		if code != identity.ExitError || !strings.Contains(errs, "[control-unpinned]") {
			t.Errorf("%v: exit %d %q", args, code, errs)
		}
	}
	if calls != 3 {
		t.Fatalf("%d handoffs, want 3", calls)
	}
}

// TestNoNounInBothBinaries: ADR 0100 (2). No command of tego's own has the name of a tego-control command, except
// version, which each binary has for itself; every tego-control noun is in tego only as a handoff.
func TestNoNounInBothBinaries(t *testing.T) {
	control := controlcli.Names()
	if len(control) < 2 {
		t.Fatalf("tego-control registers %v", control)
	}
	for _, c := range commands() {
		if !slices.Contains(control, c.Name) || c.Name == "version" {
			if c.Raw != nil {
				t.Errorf("tego %s is a handoff, but tego-control has no %s", c.Name, c.Name)
			}
			continue
		}
		if c.Raw == nil || c.Run != nil || c.Flags != nil || !handoff.IsNoun(c.Name) {
			t.Errorf("tego %s is a command of tego's own, and tego-control has a %s too", c.Name, c.Name)
		}
	}
	var handed []string
	for _, c := range commands() {
		if c.Raw != nil {
			handed = append(handed, c.Name)
		}
	}
	if want := slices.DeleteFunc(slices.Clone(control), func(s string) bool { return s == "version" }); !slices.Equal(handed, want) {
		t.Fatalf("tego hands off %v, tego-control has %v", handed, want)
	}
}

// TestUsageIsSorted: the usage lists the registered commands in name order, hidden ones left out.
func TestUsageIsSorted(t *testing.T) {
	_, out, _ := run(t, "help")
	var listed []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "   ") {
			listed = append(listed, strings.Fields(l)[0])
		}
	}
	if !slices.IsSorted(listed) || len(listed) < 20 {
		t.Fatalf("usage lists %v, want every command, sorted", listed)
	}
}
