// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// TestShortLivedProcessNamesItsBinary is the Go agent in the KVM guest: it exits in milliseconds, so by
// the time the recorder's drain hands its exec to the source, /proc/<pid> is gone and R4 can read nothing.
// The gap it leaves must still say which binary went uncaptured, and the only record of that left is the path
// the kernel's exec record carries. A path that names no file of its own (relative, or a /proc alias that
// meant something only inside the process) names nothing rather than something misleading.
func TestShortLivedProcessNamesItsBinary(t *testing.T) {
	cases := []struct {
		name, path, want string
	}{
		{"absolute path", "/usr/local/bin/go-agent", "/usr/local/bin/go-agent"},
		{"relative path", "./go-agent", ""},
		{"a /proc alias", "/proc/self/exe", ""},
		{"an fexecve descriptor", "/dev/fd/3", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := newProcTree(t) // holds no entry for pid 701: the process has already exited
			u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: &fakeAttacher{}})
			if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
				t.Fatal(err)
			}
			u.OnExec(701, 41, tc.path)
			u.OnExit(701)
			if err := u.Stop(); err != nil {
				t.Fatal(err)
			}
			gaps := u.Gaps()
			if len(gaps) != 1 || gaps[0].Why != GapNoOpenSSL || gaps[0].Count != 1 || gaps[0].Binary != tc.want {
				t.Errorf("gaps %+v, want one no-openssl naming %q", gaps, tc.want)
			}
		})
	}
}

// TestLiveProcessIsNamedByItsImage is the other side: while the process lives, /proc/<pid>/exe is the file
// itself, and it names the gap whatever the exec record's path spelled (a script, a symlink, a relative name).
func TestLiveProcessIsNamedByItsImage(t *testing.T) {
	tree := newProcTree(t)
	tree.process(t, 702, "/usr/bin/sh", nil)
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: &fakeAttacher{}})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	u.OnExec(702, 41, "./run.sh")
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
	if b := gapBinary(u.Gaps(), GapStaticTLSNoSymbols); b != "/usr/bin/sh" {
		t.Errorf("gaps %+v, want static-tls-no-symbols naming /usr/bin/sh", u.Gaps())
	}
}

// TestVerdictsSettleThroughCoverage is the one classifier: every per-process line the source reports is
// a verdict settled in the run's derive.Coverage, so its reason is derive.Classify's. It also pins why the
// source settles rather than observes: a pid the kernel hands out again inside the run is a second process,
// and each is counted, where Coverage.Observe would take the second for the first seen again.
func TestVerdictsSettleThroughCoverage(t *testing.T) {
	tree := newProcTree(t)
	tree.process(t, 703, "/usr/bin/sh", nil)
	u, sink := newTestUprobe(t, nil, Options{Proc: proc.NewAt(tree.root), Attacher: &fakeAttacher{}})
	if err := u.Start(context.Background(), source.RunRef{ID: "r-1", Agent: "a", CgroupID: 41}, sink); err != nil {
		t.Fatal(err)
	}
	u.OnExec(703, 41, "/usr/bin/sh")
	u.OnExit(703)
	u.OnExec(703, 41, "/usr/bin/sh") // the pid, reused by another process of the same binary
	u.OnExit(703)
	if err := os.RemoveAll(tree.root); err != nil {
		t.Fatal(err)
	}
	u.OnExec(704, 41, "/usr/local/bin/go-agent") // gone before its exec was handled
	u.OnExit(704)
	if err := u.Stop(); err != nil {
		t.Fatal(err)
	}
	settled := u.cov.Gaps()
	want := []derive.Gap{
		{What: "capture", Why: derive.GapNoOpenSSL, Binary: "/usr/local/bin/go-agent", Count: 1},
		{What: "capture", Why: derive.GapStaticTLSNoSymbols, Binary: "/usr/bin/sh", Count: 2},
	}
	if len(settled) != len(want) {
		t.Fatalf("coverage %+v, want %+v", settled, want)
	}
	for i := range want {
		if settled[i] != want[i] {
			t.Errorf("coverage line %d = %+v, want %+v", i, settled[i], want[i])
		}
	}
	for _, g := range u.Gaps() {
		if why, _ := derive.Classify(derive.Process{Binary: g.Binary}); g.Binary == "/usr/local/bin/go-agent" && g.Why != why {
			t.Errorf("gap %+v disagrees with derive.Classify's %q for a process nothing could be read of", g, why)
		}
	}
}
