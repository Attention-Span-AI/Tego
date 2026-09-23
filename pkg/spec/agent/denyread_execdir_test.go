// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestDenyReadUnderExecDirIsUnenforced covers the Landlock tier's union rule: an exec.allow entry naming a
// directory grants READ_FILE across its subtree (the kernel opens a program O_RDONLY|__FMODE_EXEC, so
// EXECUTE alone never satisfies file_open), which makes a deny_read target beneath it readable exactly as a
// write entry would. The compiler must mark it unenforced and say so, not report protection it cannot give.
func TestDenyReadUnderExecDirIsUnenforced(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(bin, "token")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  deny_read: [\"" + secret + "\"]\nexec:\n  allow: [\"" + bin + "\"]\n")
	rt, ds, err := Compile(c, f.machine, f.opts()...)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	var found bool
	for _, r := range rt.FS {
		if r.Kind == FSDenyRead && r.Path == secret {
			found = true
			if !r.Unenforced {
				t.Errorf("deny_read %s under exec.allow dir %s is not marked unenforced", secret, bin)
			}
		}
	}
	if !found {
		t.Fatalf("deny_read rule for %s missing from the table", secret)
	}
	if !hasCode(ds, CodeUnenforced) {
		t.Errorf("no unenforced warning:\n%s", render(ds))
	}
}

// TestDenyReadOutsideExecDirStaysEnforced is the control: a deny_read target that is not beneath any exec
// directory grant keeps its protection and produces no warning.
func TestDenyReadOutsideExecDirStaysEnforced(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	secrets := filepath.Join(root, "secrets")
	for _, d := range []string{bin, secrets} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(secrets, "token")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  deny_read: [\"" + secret + "\"]\nexec:\n  allow: [\"" + bin + "\"]\n")
	rt, ds, err := Compile(c, f.machine, f.opts()...)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	for _, r := range rt.FS {
		if r.Kind == FSDenyRead && r.Path == secret && r.Unenforced {
			t.Errorf("deny_read %s marked unenforced though no grant covers it", secret)
		}
	}
	if hasCode(ds, CodeUnenforced) {
		t.Errorf("unexpected unenforced warning:\n%s", render(ds))
	}
}

// An exec.allow directory inside an enforced deny_read keeps its grant (enforce-landlock I11
// (1)), and an exec grant carries READ_FILE (R5), so tier 1 reads every file beneath it. Evaluate's read arm
// knows only write entries as nested grants (nestedReadGrant) and answers refused.
func TestEvaluateReadUnderExecDirInsideDenyRead(t *testing.T) {
	rt := &RuleTable{Tier: backend.TierLandlock, Contract: &Contract{Exec: &ExecSection{}},
		FS:   []FSRule{{Kind: FSDenyRead, Path: "/s", Raw: "/s"}},
		Exec: []ExecRule{{Raw: "/s/bin/", Path: "/s/bin", IsDir: true, Verdict: VerdictAllow}},
	}
	r := rt.Evaluate(Action{Kind: ActionFSRead, Path: "/s/bin/data.txt"}, backend.TierLandlock)
	x := rt.Evaluate(Action{Kind: ActionExec, Path: "/s/bin/tool"}, backend.TierLandlock)
	if r.Verdict != x.Verdict {
		t.Errorf("tier 1: exec /s/bin/tool = %s but read /s/bin/data.txt = %+v; both ride the exec dir's READ_FILE", x.Verdict, r)
	}
}
