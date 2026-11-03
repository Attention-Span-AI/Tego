// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestCompileCrossCheck is I5 end to end without a kernel: agent.Compile and Prepare run on the same
// contract; the entry compile marks unenforced is the one the handle reports, and the other deny_read
// is enumerated.
//
// Spec: docs/p0/enforce-landlock.md I5.
func TestCompileCrossCheck(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "work/.env", "work/src/main.py", "secret/key", "public/x", "ledger/")
	contract := filepath.Join(root, "agent.yaml")
	yaml := "version: 0\nname: cross\ncommand: [\"/bin/sh\", \"-c\", \"true\"]\n" +
		"fs:\n  write: [\"" + filepath.Join(root, "work") + "\"]\n" +
		"  deny_read: [\"" + filepath.Join(root, "work", ".env") + "\", \"" + filepath.Join(root, "secret") + "\"]\n" +
		"exec:\n  allow: [\"sh\"]\ntier: landlock\n"
	if err := os.WriteFile(contract, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, ds, err := agent.LoadBytes(contract, []byte(yaml), nil)
	if err != nil {
		t.Fatalf("Load: %v\n%v", err, ds)
	}
	m := config.Builtin()
	m.LedgerRoot.Value = filepath.Join(root, "ledger")
	rt, ds, err := agent.Compile(c, m, agent.WithPATH("/usr/bin:/bin"), agent.WithCwd(root), agent.WithHome(root), agent.WithMountInfo(""), agent.Offline())
	if err != nil {
		t.Fatalf("Compile: %v\n%v", err, ds)
	}
	if rt.Tier != backend.TierLandlock {
		t.Fatalf("tier %s", rt.Tier)
	}
	warned := false
	for _, d := range ds {
		if d.Code == agent.CodeHeldReads { // the nested .env: reads are held at tier landlock (ADR 0069)
			warned = true
		}
	}
	if !warned {
		t.Fatalf("compile did not warn held-reads: %v", ds)
	}
	h, _ := prepare(t, 7, rt)
	if got := h.unenforced; len(got) != 1 || got[0] != filepath.Join(root, "work", ".env") {
		t.Errorf("Unenforced = %v", got)
	}
	if h.Capabilities().Has(backend.CapReadDeny) {
		t.Error("fs.deny_read still reported")
	}
	if e, ok := h.entry(filepath.Join(root, "secret")); !ok || e.Kind != kindDenyTarget {
		t.Errorf("secret = %+v, %v", e, ok)
	}
	// The ledger root is read-denied as well, whatever deny_read says (agent-contract R6a).
	assertLevel(t, h, root, []string{"secret", "ledger"})
	if e, ok := h.entry("/bin/sh"); !ok || e.Access != execAccess {
		t.Errorf("/bin/sh = %+v, %v", e, ok)
	}
	// Implicit entries are held for identity; as siblings of the secret they may union a read grant,
	// never a write-side right (R8).
	for _, p := range []string{contract} {
		if e, ok := h.entry(p); !ok || e.Access&accessFS(agent.AccessWriteSet) != 0 {
			t.Errorf("implicit %s = %+v, %v", p, e, ok)
		}
	}
}

// TestCompileCrossCheckNested is E29 through the real pipeline: a contract may legitimately name a
// deny_read entry inside another one (a base contract denying a directory, an extending contract
// denying one file in it), and nothing before this package rejects or merges the pair. Compile must
// still emit both, and Prepare must not turn the more specific entry into a grant on the broader
// target's other children — the whole subtree stays denied and the run still reports CapReadDeny.
//
// The pair is read off the entries the fixture decides, not off a count of every deny_read, because compile
// also denies what the machine holds: R6a denies tego's host state directory, /run/tego, wherever a root
// launcher has made it (ADR 0034). CI's root-suites job runs every suite on one runner, where
// enforce/cgroup's root tests have made it (pinState) by the time this suite runs, so a count of every
// entry but the ledger root's found three there on every push to main, and two in a fresh guest.
func TestCompileCrossCheckNested(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "secrets/prod/app.key", "secrets/staging/db.pem", "secrets/aws.json", "work/src/main.py", "ledger/")
	secrets := filepath.Join(root, "secrets")
	contract := filepath.Join(root, "agent.yaml")
	yaml := "version: 0\nname: nested\ncommand: [\"/bin/sh\", \"-c\", \"true\"]\n" +
		"fs:\n  write: [\"" + filepath.Join(root, "work") + "\"]\n" +
		"  deny_read: [\"" + secrets + "\", \"" + filepath.Join(secrets, "prod", "app.key") + "\"]\n" +
		"exec:\n  allow: [\"sh\"]\ntier: landlock\n"
	if err := os.WriteFile(contract, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, ds, err := agent.LoadBytes(contract, []byte(yaml), nil)
	if err != nil {
		t.Fatalf("Load: %v\n%v", err, ds)
	}
	m := config.Builtin()
	m.LedgerRoot.Value = filepath.Join(root, "ledger")
	rt, ds, err := agent.Compile(c, m, agent.WithPATH("/usr/bin:/bin"), agent.WithCwd(root), agent.WithHome(root), agent.WithMountInfo(""), agent.Offline())
	if err != nil {
		t.Fatalf("Compile: %v\n%v", err, ds)
	}
	// Every deny_read the contract declared, and every one inside the fixture's tree, whatever added it; a
	// built-in entry outside the tree is the machine's (R6a's /run/tego), not this contract's.
	var denied []string
	for _, r := range rt.FS {
		if r.Kind != agent.FSDenyRead || r.Path == m.LedgerRoot.Value { // the ledger root's is R6a's
			continue
		}
		if !r.BuiltIn || strings.HasPrefix(r.Path, root+"/") {
			denied = append(denied, r.Path)
		}
	}
	slices.Sort(denied)
	if want := []string{secrets, filepath.Join(secrets, "prod", "app.key")}; !slices.Equal(denied, want) {
		t.Fatalf("compile emitted deny_read %q, want the nested pair %q (the shape E29 must handle)", denied, want)
	}
	h, _ := prepare(t, 7, rt)
	if len(h.unenforced) != 0 || !h.Capabilities().Has(backend.CapReadDeny) {
		t.Fatalf("Unenforced = %v, CapReadDeny = %v", h.unenforced, h.Capabilities().Has(backend.CapReadDeny))
	}
	for _, e := range h.fds.open {
		if (e.Path == secrets || strings.HasPrefix(e.Path, secrets+"/")) && e.Access != 0 {
			t.Errorf("%s holds %#x (%s) inside the denied subtree", e.Path, e.Access, kindName(e.Kind))
		}
	}
}

// TestCompileCrossCheckExecDirSymlink is I5 for the exec.allow half of writablePaths. An exec.allow
// directory carries READ_FILE beneath it (execAccess), so a deny_read target inside one is unenforceable
// in this tier exactly as beneath a write entry, and compile says so through denyReadUnderExecDirs. That
// check asks containment of the *resolved* grant, because the O_PATH open follows the link and the
// recursive rule lands on the target's inode (E8) — so this side has to resolve the exec directory too.
// Asking it of the declared name makes a symlinked exec.allow directory look disjoint from a target it
// really encloses: compile marks the entry unenforced, Prepare computes false, and I5's cross-check
// fails a contract that is merely unusual. The run never starts (exit 125) on a shape the fs half of
// this same function was already fixed for.
func TestCompileCrossCheckExecDirSymlink(t *testing.T) {
	root, err := filepath.EvalSymlinks(tempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	mkTree(t, root, "real/tools/secret", "work/src/main.py", "ledger/")
	if err := os.WriteFile(filepath.Join(root, "real", "tools", "tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The one symlink the test is about: exec.allow names it, the deny_read target lives under its target.
	link := filepath.Join(root, "tools")
	if err := os.Symlink(filepath.Join(root, "real", "tools"), link); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "real", "tools", "secret")
	contract := filepath.Join(root, "agent.yaml")
	yaml := "version: 0\nname: execdir\ncommand: [\"/bin/sh\", \"-c\", \"true\"]\n" +
		"fs:\n  deny_read: [\"" + secret + "\"]\n" +
		"exec:\n  allow: [\"sh\", \"" + link + "\"]\ntier: landlock\n"
	if err := os.WriteFile(contract, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, ds, err := agent.LoadBytes(contract, []byte(yaml), nil)
	if err != nil {
		t.Fatalf("Load: %v\n%v", err, ds)
	}
	m := config.Builtin()
	m.LedgerRoot.Value = filepath.Join(root, "ledger")
	rt, ds, err := agent.Compile(c, m, agent.WithPATH("/usr/bin:/bin"), agent.WithCwd(root), agent.WithHome(root), agent.WithMountInfo(""), agent.Offline())
	if err != nil {
		t.Fatalf("Compile: %v\n%v", err, ds)
	}
	// The fixture only means something while compile still marks the entry through the exec-directory
	// route: if that ever stops, the cross-check below would pass for the wrong reason.
	marked := false
	for _, r := range rt.FS {
		if r.Kind == agent.FSDenyRead && r.Path == secret {
			marked = r.Unenforced
		}
	}
	if !marked {
		t.Fatalf("compile did not mark deny_read %q unenforced under the symlinked exec.allow directory", secret)
	}
	h, _ := prepare(t, 7, rt) // fails here with ErrRulesetBuild when the exec grant is compared unresolved
	if got := h.unenforced; len(got) != 1 || got[0] != secret {
		t.Errorf("Unenforced = %v, want [%s]", got, secret)
	}
	if h.Capabilities().Has(backend.CapReadDeny) {
		t.Error("fs.deny_read still reported although an exec.allow directory grants read over the target")
	}
}
