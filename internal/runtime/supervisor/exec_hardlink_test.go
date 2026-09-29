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

// TestExecHardLinkOfGrantedBinaryIsRefused: on Ubuntu 25.10
// /usr/bin/sleep, ls, dd, env and the rest are hard links of one uutils multi-call binary, and an inode
// match alone let exec.allow: [/usr/bin/sleep] run /usr/bin/ls ("exec seccomp allow exec[/usr/bin/sleep]
// /usr/bin/ls"). A hard link is another name of the inode, not a spelling of the entry: tier 2 matches exec
// by path and refuses it, and so must the supervisor, since Landlock's EXECUTE on the inode allows it. Real
// files, the real describeImage, and the real StatID and EvalSymlinks.
func TestExecHardLinkOfGrantedBinaryIsRefused(t *testing.T) {
	dir := t.TempDir()
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	a := filepath.Join(dir, "sleep")
	b := filepath.Join(dir, "ls")
	sym := filepath.Join(dir, "sleep-link")
	if err := os.WriteFile(a, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // an executable fixture
		t.Fatal(err)
	}
	if err := os.Link(a, b); err != nil {
		t.Skipf("hard link: %v", err)
	}
	if err := os.Symlink(a, sym); err != nil {
		t.Fatal(err)
	}
	pol := testPolicy(nil, nil, nil)
	pol.Rules.Exec = []agent.ExecRule{{Raw: a, Path: a, Source: agent.ExecSourceAllow}}
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
	if image(a).id != image(b).id {
		t.Fatal("fixture: the hard link must share the entry's inode")
	}
	for _, tc := range []struct {
		name, path string
		want       record.Verdict
	}{
		{"the entry itself", a, record.VerdictAllow},
		{"a symlink leading to the entry", sym, record.VerdictAllow},
		{"a hard link of the entry", b, record.VerdictRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := c.decideExec(tc.path, tc.path, image(tc.path), nil, ruleUnmatched)
			if d.verdict != tc.want {
				t.Errorf("exec %s under exec.allow [%s]: verdict %s (rule %s), want %s", tc.path, a, d.verdict, d.rule, tc.want)
			}
			if tc.want == record.VerdictRefused && d.answer.cont {
				t.Error("a refused exec is answered by the loop, never continued to Landlock, which allows the inode")
			}
		})
	}
}
