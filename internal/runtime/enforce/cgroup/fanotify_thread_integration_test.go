// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Two simultaneously live threads in one process must keep distinct refusal identities.
func TestFanotifyDistinguishesSiblingReads(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	mount := mountOf(t, dir)
	cg, err := cgroupPathOfPID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	sink := &sink{}
	p := newPolicy(&agent.RuleTable{FS: []agent.FSRule{{Kind: agent.FSDenyRead, Path: secret, Mount: mount, Raw: "secret"}}, Tier: backend.TierCgroup, Record: agent.RecordFull}, cg)
	l, err := newFanotifyListener(p, Run{ID: "threads", Agent: "a", CgroupPath: cg}, sink, time.Second)
	if errors.Is(err, unix.EPERM) {
		t.Skipf("fanotify needs CAP_SYS_ADMIN: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.mark(mount); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- l.loop(ctx) }()
	ready := make(chan int, 2)
	start := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	opened := make(chan error, 2)
	for range 2 {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready <- unix.Gettid()
			<-start
			_, err := os.ReadFile(secret)
			opened <- err
			<-release
		}()
	}
	tids := map[int]bool{<-ready: true, <-ready: true}
	if len(tids) != 2 {
		t.Fatal("test did not start distinct threads")
	}
	close(start)
	for range 2 {
		if err := <-opened; !errors.Is(err, unix.EPERM) {
			t.Errorf("read = %v, want EPERM", err)
		}
	}
	cancel()
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	for _, e := range sink.all() {
		if e.Kind != record.KindFS {
			continue
		}
		if e.PID != os.Getpid() || !tids[e.TID] {
			t.Errorf("wrong opener pid=%d tid=%d", e.PID, e.TID)
		}
		delete(tids, e.TID)
	}
	if len(tids) != 0 {
		t.Fatalf("missing refusal for threads %v", tids)
	}
}
