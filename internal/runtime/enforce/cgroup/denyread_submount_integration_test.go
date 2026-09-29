// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestFanotifyMarksMountsBeneathADeniedTree: at the listener, a deny_read directory with a
// mount beneath it. The policy marked only the entry's own mount, so an open on the submount raised no event
// and was not refused; every mount point beneath the entry is marked now.
func TestFanotifyMarksMountsBeneathADeniedTree(t *testing.T) {
	dir := t.TempDir()
	denied := filepath.Join(dir, "denied")
	sub := filepath.Join(denied, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(denied, "top"), []byte("top"), 0o644)
	if err := unix.Mount("tmpfs", sub, "tmpfs", 0, ""); err != nil {
		t.Skip(err)
	}
	defer unix.Unmount(sub, unix.MNT_DETACH)
	_ = os.WriteFile(filepath.Join(sub, "key"), []byte("key"), 0o644)
	mount := mountOf(t, dir)
	cg, err := cgroupPathOfPID(os.Getpid())
	if err != nil {
		t.Skip(err)
	}
	p := newPolicy(&agent.RuleTable{
		FS:   []agent.FSRule{{Kind: agent.FSDenyRead, Path: denied, Mount: mount, Raw: "deny_read: denied/"}},
		Tier: backend.TierCgroup, Record: agent.RecordFull,
	}, cg)
	t.Logf("policy marks %v masks %v", p.mounts, p.masks)
	l, err := newFanotifyListener(p, Run{ID: "it", Agent: "a", CgroupPath: cg}, &sink{}, time.Second)
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	for _, m := range p.mounts {
		if err := l.markFor(m, p.masks[m]); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.loop(ctx) }()
	_, errTop := os.ReadFile(filepath.Join(denied, "top"))
	_, errSub := os.ReadFile(filepath.Join(sub, "key"))
	t.Logf("read denied/top: %v; read denied/sub/key (submount): %v", errTop, errSub)
	if errTop == nil {
		t.Fatal("control: the denied file on the marked mount was read")
	}
	if errSub == nil {
		t.Errorf("a file under the deny_read entry, on a mount beneath it, was read with no refusal")
	}
}
