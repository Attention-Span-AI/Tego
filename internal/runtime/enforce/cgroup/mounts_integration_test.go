// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestFanotifyMarksEveryBindMount is §5 R8's mark per mount against the kernel: one filesystem mounted at two
// paths is two mounts with one st_dev, and a deny_read entry under each is refused through its own mount.
// Collapsing the marks by device left the second mount unmarked, and the open under it went through with no
// event at all. It needs CAP_SYS_ADMIN for mount(2) and the group, so it runs as root in the KVM guest.
func TestFanotifyMarksEveryBindMount(t *testing.T) {
	requireFanotify(t)
	dir := t.TempDir()
	src, bind := filepath.Join(dir, "src"), filepath.Join(dir, "bind")
	for _, d := range []string{src, bind} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mount("tego-res8", src, "tmpfs", 0, "mode=0700"); err != nil {
		t.Skipf("mount a tmpfs needs CAP_SYS_ADMIN: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(src, unix.MNT_DETACH) })
	if err := unix.Mount(src, bind, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind %s at %s: %v", src, bind, err)
	}
	t.Cleanup(func() { _ = unix.Unmount(bind, unix.MNT_DETACH) })
	for _, name := range []string{"one.txt", "two.txt", "plain.txt"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	one, two := filepath.Join(src, "one.txt"), filepath.Join(bind, "two.txt")
	var a, b unix.Stat_t
	if err := unix.Stat(one, &a); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(two, &b); err != nil {
		t.Fatal(err)
	}
	if a.Dev != b.Dev {
		t.Fatalf("a bind mount must share its source's device: %d, %d", a.Dev, b.Dev)
	}

	cg, err := cgroupPathOfPID(os.Getpid())
	if err != nil {
		t.Skipf("no cgroup v2 path for this process: %v", err)
	}
	p := newPolicy(&agent.RuleTable{
		FS: []agent.FSRule{
			{Kind: agent.FSDenyRead, Path: one, Raw: "deny_read: " + one},
			{Kind: agent.FSDenyRead, Path: two, Raw: "deny_read: " + two},
		},
		Tier: backend.TierCgroup, Record: agent.RecordFull,
	}, cg)
	// An error, not a stop: the opens below are what a missing mark costs, and they are the point.
	if len(p.mounts) != 2 {
		t.Errorf("mounts = %v: one filesystem on two mounts needs two marks", p.mounts)
	}

	events := &sink{}
	l, err := newFanotifyListener(p, Run{ID: "it", Agent: "a", CgroupPath: cg}, events, time.Second)
	if err != nil {
		t.Fatalf("newFanotifyListener: %v", err)
	}
	defer l.Close()
	for _, m := range p.mounts {
		if err := l.mark(m); err != nil {
			t.Fatalf("mark %s: %v", m, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	loopErr := make(chan error, 1)
	go func() { loopErr <- l.loop(ctx) }()

	for _, denied := range []string{one, two} {
		if _, err := os.ReadFile(denied); !errors.Is(err, unix.EPERM) {
			t.Errorf("open %s = %v, want EPERM: its mount must be marked", denied, err)
		}
	}
	if _, err := os.ReadFile(filepath.Join(bind, "plain.txt")); err != nil {
		t.Errorf("an unruled file on the bind mount must open: %v", err)
	}
	cancel()
	if err := <-loopErr; err != nil {
		t.Fatalf("listener loop: %v", err)
	}
	if _, refused, _, _ := l.stats(); refused != 2 {
		t.Errorf("refused %d opens, want 2", refused)
	}
}
