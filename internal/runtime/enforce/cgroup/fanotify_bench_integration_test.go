// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// BenchmarkFanotifyRoundTrip measures what one open(2) costs on a mount this listener has marked, against the
// same open before the mark: the kernel's permission event, the read, the hand-off to a worker, the readlink
// and policy decision, and the response the opener waits for. docs/P0-DESIGN.md §9 budgets it at under
// 30 µs per open, and the acceptance asks for the row. BenchmarkListenerHandle measures only this
// package's share over a pipe; this is the whole round trip, so it needs CAP_SYS_ADMIN and skips without it.
//
// Every sub-benchmark opens a file in the run's own cgroup (this process's), so the refused case exercises
// the membership read too; the allowed case is decided on the path alone, as the host's opens are (§6 E34).
func BenchmarkFanotifyRoundTrip(b *testing.B) {
	dir := b.TempDir()
	plain := filepath.Join(dir, "plain.txt")
	secret := filepath.Join(dir, "secret.txt")
	for _, p := range []string{plain, secret} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			b.Fatalf("write %s: %v", p, err)
		}
	}
	cg, err := cgroupPathOfPID(os.Getpid())
	if err != nil {
		b.Skipf("no cgroup v2 path: %v", err)
	}
	mount := benchMountOf(b, dir)

	open := func(b *testing.B, path string, wantErr bool) {
		b.Helper()
		b.ReportAllocs()
		for b.Loop() {
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if (err != nil) != wantErr {
				b.Fatalf("open %s: %v (want error %v)", path, err, wantErr)
			}
			if err == nil {
				_ = unix.Close(fd)
			}
		}
	}

	b.Run("unmarked", func(b *testing.B) { open(b, plain, false) })

	p := newPolicy(&agent.RuleTable{
		FS:     []agent.FSRule{{Kind: agent.FSDenyRead, Path: secret, Mount: mount, Raw: "deny_read: secret.txt"}},
		Tier:   backend.TierCgroup,
		Record: agent.RecordFull,
	}, cg)
	l, err := newFanotifyListener(p, Run{ID: "bench", Agent: "a", CgroupPath: cg}, nil, time.Second)
	if err != nil {
		b.Skipf("fanotify needs CAP_SYS_ADMIN: %v", err)
	}
	defer l.Close()
	if err := l.mark(mount); err != nil {
		b.Skipf("marking %s needs CAP_SYS_ADMIN: %v", mount, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	loopErr := make(chan error, 1)
	go func() { loopErr <- l.loop(ctx) }()
	defer func() {
		cancel()
		if err := <-loopErr; err != nil {
			b.Errorf("listener loop: %v", err)
		}
	}()

	b.Run("marked, allowed on the path", func(b *testing.B) { open(b, plain, false) })
	b.Run("marked, refused after the membership read", func(b *testing.B) { open(b, secret, true) })
}

// benchMountOf is mountOf for a benchmark: the mount point that holds a path, read from /proc/self/mountinfo's
// longest matching mount point so the benchmark needs no df.
func benchMountOf(b *testing.B, path string) string {
	b.Helper()
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		b.Skipf("mountinfo: %v", err)
	}
	best := "/"
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		mp := fields[4]
		if (path == mp || underPath(mp, path)) && len(mp) > len(best) {
			best = mp
		}
	}
	return best
}
