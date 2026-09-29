// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestExecDirectoryGrantMatchesThePhysicalPath: a directory exec entry is matched against where the kernel's
// exec lands, not against the lexically cleaned spelling. /grant/link/../x, with link a symlink to
// /elsewhere/sub, cleans to /grant/x, but the kernel resolves ".." physically and runs /elsewhere/x, which
// Landlock's EXECUTE on /grant refuses; the ledger said allowed, and an MCP server declared at /grant/x
// could be recorded as started. Real files, the real describeImage, StatID and EvalSymlinks.
func TestExecDirectoryGrantMatchesThePhysicalPath(t *testing.T) {
	dir := t.TempDir()
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	grant := filepath.Join(dir, "grant")
	sub := filepath.Join(dir, "elsewhere", "sub")
	for _, d := range []string{grant, sub} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	inside := filepath.Join(grant, "y")
	outside := filepath.Join(dir, "elsewhere", "x")
	for _, f := range []string{inside, outside, filepath.Join(grant, "x")} {
		if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // an executable fixture
			t.Fatal(err)
		}
	}
	if err := os.Symlink(sub, filepath.Join(grant, "link")); err != nil {
		t.Fatal(err)
	}
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Exec = []agent.ExecRule{{Raw: grant + "/", Path: grant + "/", IsDir: true, Source: agent.ExecSourceAllow}}
	l := &Loop{k: sysKernel{}}
	c := l.resolveExecEntries(&compiled{pol: pol})
	image := func(p string) execImage {
		t.Helper()
		fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd) //nolint:errcheck // a test descriptor
		img, err := describeImage(fd)
		if err != nil {
			t.Fatal(err)
		}
		return img
	}
	for _, tc := range []struct {
		name, spelled, walked string
		want                  record.Verdict
	}{
		{"a file of the granted directory", inside, inside, record.VerdictAllow},
		// R6's spelling of grant/link/../x is its lexical cleaning, grant/x; the kernel lands on elsewhere/x.
		{"a symlinked directory's ..", filepath.Clean(grant + "/link/../x"), grant + "/link/../x", record.VerdictRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := image(tc.walked)
			d := c.decideExec(tc.spelled, tc.walked, img, nil, ruleUnmatched)
			if d.verdict != tc.want {
				t.Errorf("exec %s (kernel: %s) under exec.allow [%s/]: verdict %s (rule %s), want %s", tc.spelled,
					img.link, grant, d.verdict, d.rule, tc.want)
			}
			if tc.want == record.VerdictAllow && d.rule != pol.Rules.Exec[0].RuleName() {
				t.Errorf("rule %s, want the entry's own name %s", d.rule, pol.Rules.Exec[0].RuleName())
			}
			if tc.want == record.VerdictRefused && d.answer.cont {
				t.Error("a refused exec is answered by the loop, never continued")
			}
		})
	}
}

// TestExecFileGrantMatchesThePhysicalPath is TestExecDirectoryGrantMatchesThePhysicalPath for a file entry:
// under exec.allow [/grant/x], /grant/link/../x cleans to /grant/x, which the entry names, while the kernel
// runs /elsewhere/x, another inode no entry grants. The file entry's spelling match ran first and
// unconditionally, so the exec was recorded allowed (and an mcp[] command[0] of /grant/x recorded started)
// while Landlock refused it. The entry's own spelling, and a symlink the agent made to it, still match.
func TestExecFileGrantMatchesThePhysicalPath(t *testing.T) {
	dir := t.TempDir()
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	grant := filepath.Join(dir, "grant")
	sub := filepath.Join(dir, "elsewhere", "sub")
	for _, d := range []string{grant, sub} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	granted := filepath.Join(grant, "x")
	outside := filepath.Join(dir, "elsewhere", "x")
	for _, f := range []string{granted, outside} {
		if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // an executable fixture
			t.Fatal(err)
		}
	}
	if err := os.Symlink(sub, filepath.Join(grant, "link")); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(granted, alias); err != nil {
		t.Fatal(err)
	}
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Exec = []agent.ExecRule{{Raw: granted, Path: granted, Source: agent.ExecSourceAllow}}
	l := &Loop{k: sysKernel{}}
	c := l.resolveExecEntries(&compiled{pol: pol})
	image := func(p string) execImage {
		t.Helper()
		fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd) //nolint:errcheck // a test descriptor
		img, err := describeImage(fd)
		if err != nil {
			t.Fatal(err)
		}
		return img
	}
	for _, tc := range []struct {
		name, spelled, walked string
		want                  record.Verdict
	}{
		{"the granted file", granted, granted, record.VerdictAllow},
		{"a symlink to the granted file", alias, alias, record.VerdictAllow},
		{"a symlinked directory's ..", filepath.Clean(grant + "/link/../x"), grant + "/link/../x", record.VerdictRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := image(tc.walked)
			d := c.decideExec(tc.spelled, tc.walked, img, nil, ruleUnmatched)
			if d.verdict != tc.want {
				t.Errorf("exec %s (kernel: %s) under exec.allow [%s]: verdict %s (rule %s), want %s", tc.spelled,
					img.link, granted, d.verdict, d.rule, tc.want)
			}
			if tc.want == record.VerdictAllow && d.rule != pol.Rules.Exec[0].RuleName() {
				t.Errorf("rule %s, want the entry's own name %s", d.rule, pol.Rules.Exec[0].RuleName())
			}
			if tc.want == record.VerdictRefused && d.answer.cont {
				t.Error("a refused exec is answered by the loop, never continued")
			}
		})
	}
}
