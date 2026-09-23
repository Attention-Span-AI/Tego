// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func fsRule(kind agent.FSKind, path, mount, raw string) agent.FSRule {
	return agent.FSRule{Kind: kind, Path: path, Mount: mount, Raw: raw}
}

func policyTable(fs []agent.FSRule, exec []agent.ExecRule) *agent.RuleTable {
	return &agent.RuleTable{FS: fs, Exec: exec, Tier: backend.TierCgroup, Record: agent.RecordFull}
}

// TestPolicyMarksOnlyWhatItDecides asserts the listener marks a mount only when it can refuse something on
// it: a deny_read entry's mount and an exec allow-list entry's mount. A write entry, a watch entry and the
// implicit run-directory entries mark nothing, which is what makes an unruled filesystem free (§5 R8).
func TestPolicyMarksOnlyWhatItDecides(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	work := filepath.Join(dir, "work")
	tool := filepath.Join(dir, "tool")
	for _, p := range []string{secret, work, tool} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	t.Run("write only marks nothing", func(t *testing.T) {
		p := newPolicy(policyTable([]agent.FSRule{
			fsRule(agent.FSWrite, work, "", "work"),
			fsRule(agent.FSImplicit, dir, "", ""),
		}, nil), "/run.scope")
		if len(p.mounts) != 0 {
			t.Fatalf("mounts = %v, want none", p.mounts)
		}
	})

	t.Run("deny_read marks its mount", func(t *testing.T) {
		p := newPolicy(policyTable([]agent.FSRule{
			fsRule(agent.FSDenyRead, secret, "", "secret"),
			fsRule(agent.FSWrite, work, "", "work"),
		}, nil), "/run.scope")
		if len(p.mounts) != 1 {
			t.Fatalf("mounts = %v, want exactly one for the shared mount", p.mounts)
		}
	})

	t.Run("exec rules mark their mount", func(t *testing.T) {
		p := newPolicy(policyTable(nil, []agent.ExecRule{
			{Path: tool, Raw: "tool", Verdict: agent.VerdictAllow},
		}), "/run.scope")
		if len(p.mounts) != 1 || p.mounts[0] != tool {
			t.Fatalf("mounts = %v, want [%s]: FAN_OPEN_EXEC_PERM is mount-scoped too", p.mounts, tool)
		}
	})

	t.Run("one mark per mount", func(t *testing.T) {
		p := newPolicy(policyTable([]agent.FSRule{
			fsRule(agent.FSDenyRead, secret, "", "secret"),
			fsRule(agent.FSDenyRead, work, "", "work"),
		}, []agent.ExecRule{{Path: tool, Raw: "tool", Verdict: agent.VerdictAllow}}), "/run.scope")
		if len(p.mounts) != 1 {
			t.Fatalf("mounts = %v: three paths on one mount must collapse to one mark", p.mounts)
		}
	})

	t.Run("a path that does not exist yet is kept by name", func(t *testing.T) {
		missing := filepath.Join(dir, "created-at-run-time")
		p := newPolicy(policyTable([]agent.FSRule{
			fsRule(agent.FSDenyRead, missing, "", "later"),
		}, nil), "/run.scope")
		if len(p.mounts) != 1 || p.mounts[0] != missing {
			t.Fatalf("mounts = %v, want [%s]", p.mounts, missing)
		}
	})

	if len(newPolicy(policyTable(nil, nil), "/run.scope").mounts) != 0 {
		t.Fatal("a contract with no rules must mark nothing")
	}
	if newPolicy(nil, "/run.scope") == nil {
		t.Fatal("a nil table must produce an empty policy, not a nil one")
	}
}

// TestPolicyDecideOpen is the deny_read decision table: a denied subtree, a file inside it, a more specific
// write entry that reopens one path, and everything else, which fanotify never refuses because it cannot see
// whether the open is for reading or writing (§5 R8).
func TestPolicyDecideOpen(t *testing.T) {
	t.Parallel()
	p := newPolicy(policyTable([]agent.FSRule{
		fsRule(agent.FSDenyRead, "/home/u/.ssh", "/home", "~/.ssh"),
		fsRule(agent.FSDenyRead, "/home/u/secrets", "/home", "~/secrets"),
		fsRule(agent.FSWrite, "/home/u/secrets/scratch", "/home", "~/secrets/scratch"),
		fsRule(agent.FSWrite, "/home/u/work", "/home", "~/work"),
	}, nil), "/run.scope")

	cases := []struct {
		name  string
		path  string
		allow bool
		rule  string
	}{
		{"denied directory itself", "/home/u/.ssh", false, "fs.deny_read[~/.ssh]"},
		{"file inside a denied directory", "/home/u/.ssh/id_ed25519", false, "fs.deny_read[~/.ssh]"},
		{"deep inside a denied directory", "/home/u/.ssh/a/b/c", false, "fs.deny_read[~/.ssh]"},
		{"a more specific write entry wins", "/home/u/secrets/scratch/out.txt", true, ""},
		{"the write entry's own path", "/home/u/secrets/scratch", true, ""},
		{"still denied beside the write entry", "/home/u/secrets/key.pem", false, "fs.deny_read[~/secrets]"},
		{"sibling with a shared prefix", "/home/u/.sshfoo", true, ""},
		{"an unruled path", "/usr/lib/libc.so.6", true, ""},
		{"a declared write path", "/home/u/work/main.go", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.decideOpen(tc.path)
			if got.allow != tc.allow {
				t.Fatalf("decideOpen(%q).allow = %v, want %v", tc.path, got.allow, tc.allow)
			}
			if tc.allow {
				return
			}
			if got.reason != record.ReasonReadDenied {
				t.Fatalf("reason = %q, want %q", got.reason, record.ReasonReadDenied)
			}
			if got.rule != tc.rule {
				t.Fatalf("rule = %q, want %q", got.rule, tc.rule)
			}
			if got.path != tc.path {
				t.Fatalf("path = %q, want the file that was opened, %q", got.path, tc.path)
			}
		})
	}
}

// TestPolicyDecideExec is the exec decision table: the named binaries, a binary under a named directory, a
// PT_INTERP loader the compiler resolved, and anything else, which is refused with exec-not-allowed.
//
// A symlinked entry is also held under the file it resolves to on this machine (newPolicy's resolveNow),
// so what /usr/bin/python3 admits besides itself is the host's: python3.12 on Ubuntu 24.04, python3.13 on
// 25.10. The symlinked entry is therefore made in a directory of the test's own, where the link and its
// target are known: the target is admitted, and a sibling whose name extends the link's is not.
func TestPolicyDecideExec(t *testing.T) {
	t.Parallel()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	link, target := filepath.Join(dir, "python3"), filepath.Join(dir, "python3.11")
	if err := os.WriteFile(target, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("python3.11", link); err != nil {
		t.Fatal(err)
	}
	p := newPolicy(policyTable(nil, []agent.ExecRule{
		{Path: "/usr/bin/python3", Raw: "python3", Verdict: agent.VerdictAllow,
			Interp: "/lib64/ld-linux-x86-64.so.2"},
		{Path: link, Raw: link, Verdict: agent.VerdictAllow},
		{Path: "/opt/tools", Raw: "/opt/tools", Verdict: agent.VerdictAllow, IsDir: true},
		{Path: "/usr/bin/forbidden", Raw: "forbidden", Verdict: agent.VerdictRefused},
	}), "/run.scope")

	cases := []struct {
		path  string
		allow bool
	}{
		{"/usr/bin/python3", true},
		{"/lib64/ld-linux-x86-64.so.2", true},
		{link, true},
		{target, true},
		{"/opt/tools/build", true},
		{"/opt/tools/nested/deep/tool", true},
		{"/usr/bin/curl", false},
		{"/usr/bin/forbidden", false},
		{"/opt/toolsfoo/x", false},
		{filepath.Join(dir, "python3.12"), false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got := p.decideExec(tc.path)
			if got.allow != tc.allow {
				t.Fatalf("decideExec(%q).allow = %v, want %v", tc.path, got.allow, tc.allow)
			}
			if !tc.allow && (got.reason != record.ReasonExecNotAllowed || got.path != tc.path) {
				t.Fatalf("refusal = %+v, want reason %q and path %q", got, record.ReasonExecNotAllowed, tc.path)
			}
		})
	}
}

// TestPolicyEmptyExecRefusesEverything asserts a contract that names no binary refuses every exec rather than
// falling open, which is what makes exec denial a capability at all.
func TestPolicyEmptyExecRefusesEverything(t *testing.T) {
	t.Parallel()
	p := newPolicy(policyTable(nil, nil), "/run.scope")
	if v := p.decideExec("/bin/sh"); v.allow {
		t.Fatal("an empty exec allow-list must refuse every exec")
	}
	if v := p.decideOpen("/bin/sh"); !v.allow {
		t.Fatal("an empty deny_read list must refuse no open")
	}
}

// TestUnderPath covers the component-wise prefix test both decisions rest on.
func TestUnderPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		parent, child string
		want          bool
	}{
		{"/a", "/a/b", true},
		{"/a", "/a", false},
		{"/a", "/ab", false},
		{"/a/b", "/a/b/c/d", true},
		{"/a/", "/a/b", true},
		{"/", "/anything", true},
		{"/", "/", false},
		{"", "/a", false},
		{"/a", "", false},
	}
	for _, tc := range cases {
		if got := underPath(tc.parent, tc.child); got != tc.want {
			t.Errorf("underPath(%q, %q) = %v, want %v", tc.parent, tc.child, got, tc.want)
		}
	}
}

// TestARefusalNamesTheFirstEntryNamingAPath: of several deny_read entries naming one path, a refusal names the
// first declared, as decide.PathIndex, decide.Evaluate and `tego drift` do. The lists were ordered by an
// unstable sort, which above 12 entries could move a later duplicate ahead and name it in the ledger's rule.
func TestARefusalNamesTheFirstEntryNamingAPath(t *testing.T) {
	for n := 13; n <= 100; n++ {
		first, last := n/3, n-2
		var fs []agent.FSRule
		for i := range n {
			path := fmt.Sprintf("/w/r%d", i)
			if i == first || i == last {
				path = "/w/dup"
			}
			fs = append(fs, agent.FSRule{Kind: agent.FSDenyRead, Path: path, Raw: fmt.Sprintf("r%d", i)})
		}
		p := newPolicyWith(policyTable(fs, nil), "/run.scope", func(string) ([]string, error) { return nil, nil },
			func(string) (mountKey, error) { return mountKey{unique: true, id: 1}, nil })
		v := p.decideOpen("/w/dup/f")
		if want := fs[first].RuleName(); v.allow || v.rule != want {
			t.Errorf("%d entries: decideOpen = %+v, want a refusal naming %s", n, v, want)
		}
	}
}
