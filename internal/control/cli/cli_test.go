// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

var user = privilege{euid: 1000}

func run(t *testing.T, p privilege, args ...string) (int, string, string) {
	t.Helper()
	var out, errs bytes.Buffer
	code := mainWith(context.Background(), append([]string{handoff.Name}, args...), &out, &errs, p)
	return code, out.String(), errs.String()
}

// TestControlRefusesRoot: [control-as-root]. Every command, version, help, an unknown one and none at all, is
// refused at euid 0, and with an effective or a permitted capability, before it does anything.
func TestControlRefusesRoot(t *testing.T) {
	argvs := [][]string{nil, {"help"}, {"--help"}, {"nonesuch"}}
	for _, n := range Names() {
		argvs = append(argvs, []string{n}, []string{n, "--json"})
	}
	for _, p := range []privilege{{euid: 0}, {euid: 1000, effective: 1 << 21}, {euid: 1000, permitted: 1 << 12}, {euid: 0, effective: ^uint64(0)}} {
		for _, argv := range argvs {
			code, out, errs := run(t, p, argv...)
			if code != identity.ExitError || out != "" || !strings.Contains(errs, "["+handoff.CodeAsRoot+"]") {
				t.Errorf("%+v %v: exit %d stdout %q stderr %q, want 125 [%s] and nothing else", p, argv, code, out, errs, handoff.CodeAsRoot)
			}
			if strings.Count(errs, "\n") != 1 {
				t.Errorf("%+v %v: stderr %q, want one line", p, argv, errs)
			}
		}
	}
}

// TestHostPrivilegeOfThisProcess: the guard reads the real euid and capability sets; the test process is no
// root and holds no capability unless the suite runs as root.
func TestHostPrivilegeOfThisProcess(t *testing.T) {
	p := hostPrivilege()
	if p.euid != os.Geteuid() {
		t.Fatalf("euid %d, want %d", p.euid, os.Geteuid())
	}
	if os.Geteuid() != 0 && (p.effective != 0 || p.permitted != 0) {
		t.Skipf("this test process holds capabilities %+v", p)
	}
	if os.Geteuid() != 0 {
		if code, _, errs := run(t, p, "help"); code != identity.ExitOK {
			t.Fatalf("help as the user: exit %d %q", code, errs)
		}
	}
}

// TestHandoffNounsMatchControlCommands: tego-control's commands are exactly the nouns tego hands to it, with the
// summaries tego's usage gives them, plus its own version.
func TestHandoffNounsMatchControlCommands(t *testing.T) {
	var want []string
	for _, n := range handoff.Nouns() {
		want = append(want, n.Name)
		c, ok := Lookup(n.Name)
		if !ok {
			t.Errorf("tego hands %s to tego-control, which has no such command", n.Name)
			continue
		}
		if c.Summary != n.Summary {
			t.Errorf("%s: tego-control's summary %q, tego's %q", n.Name, c.Summary, n.Summary)
		}
	}
	want = append(want, "version")
	slices.Sort(want)
	if got := Names(); !slices.Equal(got, want) {
		t.Fatalf("tego-control's commands %v, want the handoff's nouns and version %v", got, want)
	}
}

// TestUsageIsGeneratedAndSorted: help lists every registered command this build has once, sorted, and names the nouns
// it does not have yet on one "planned" line only.
func TestUsageIsGeneratedAndSorted(t *testing.T) {
	code, out, _ := run(t, user, "help")
	if code != identity.ExitOK {
		t.Fatalf("exit %d", code)
	}
	var listed []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "  ") {
			listed = append(listed, strings.Fields(l)[0])
		}
	}
	var want []string
	for _, n := range Names() {
		if !slices.Contains(handoff.Planned(), n) {
			want = append(want, n)
		}
	}
	if !slices.Equal(listed, want) || !slices.IsSorted(listed) || !slices.Contains(listed, "serve") {
		t.Fatalf("usage lists %v, want %v sorted", listed, want)
	}
	if planned := handoff.Planned(); len(planned) == 0 {
		if strings.Contains(out, "planned, not in this build") {
			t.Fatalf("usage has a planned line, and no noun is planned:\n%s", out)
		}
	} else if line := "\nplanned, not in this build: " + strings.Join(planned, ", ") + "\n"; !strings.Contains(out, line) {
		t.Fatalf("usage lacks %q:\n%s", line, out)
	}
	if code, _, errs := run(t, user); code != identity.ExitUsage || !strings.Contains(errs, "commands:") {
		t.Fatalf("no command: exit %d %q, want usage on stderr and 2", code, errs)
	}
	if code, _, errs := run(t, user, "nonesuch"); code != identity.ExitUsage || !strings.Contains(errs, "[usage]") {
		t.Fatalf("unknown: exit %d %q", code, errs)
	}
}

// TestNotBuiltNounSaysSo: a noun whose service has not landed says [not-built] on one line, prints nothing on
// stdout and exits 125; handoff's Built is true exactly for the nouns that do not (help reads it).
func TestNotBuiltNounSaysSo(t *testing.T) {
	for _, n := range handoff.Nouns() {
		if n.Built {
			if _, _, errs := run(t, user, n.Name, "--anything"); strings.Contains(errs, "[not-built]") {
				t.Errorf("%s is Built in internal/handoff, and its command says [not-built]: %q", n.Name, errs)
			}
			continue
		}
		code, out, errs := run(t, user, n.Name, "--anything")
		if code != identity.ExitError || out != "" || !strings.Contains(errs, "[not-built]") || strings.Count(errs, "\n") != 1 {
			t.Errorf("%s: exit %d stdout %q stderr %q", n.Name, code, out, errs)
		}
	}
}

// TestControlCodesMapToIdentityExits: tego-control's own reason codes map to pkg/spec/identity's subcommand exits.
func TestControlCodesMapToIdentityExits(t *testing.T) {
	for code, exit := range exits {
		switch exit {
		case identity.ExitUsage, identity.ExitError:
		default:
			t.Errorf("[%s] exits %d", code, exit)
		}
	}
	if exits[codeUsage] != identity.ExitUsage || exits[codeNotBuilt] != identity.ExitError {
		t.Fatalf("exits %v", exits)
	}
}

// TestControlVersion: version prints the shared build stamp and the SHA-256 of the image it runs, in text and JSON.
func TestControlVersion(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	want := hex.EncodeToString(sum[:])
	code, out, errs := run(t, user, "version")
	if code != identity.ExitOK || errs != "" {
		t.Fatalf("exit %d %q", code, errs)
	}
	var keys []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		k, v, _ := strings.Cut(l, "=")
		keys = append(keys, k)
		if v == "" {
			t.Errorf("empty %s", k)
		}
	}
	if !slices.Equal(keys, []string{"tego-control", "commit", "date", "go", "sha256"}) || !strings.Contains(out, "sha256="+want+"\n") {
		t.Fatalf("version %q, want the five fields and sha256=%s", out, want)
	}
	code, out, _ = run(t, user, "version", "--json")
	var v Version
	if code != identity.ExitOK || json.Unmarshal([]byte(out), &v) != nil || v.SHA256 != want || !strings.HasPrefix(out, `{"tego-control":`) {
		t.Fatalf("version --json %q", out)
	}
	if code, _, _ := run(t, user, "version", "extra"); code != identity.ExitUsage {
		t.Fatalf("version extra: exit %d", code)
	}
}
