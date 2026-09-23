// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// benchPolicy builds a policy of a realistic size: a handful of denied trees and a few dozen binaries.
func benchPolicy(b *testing.B) *policy {
	b.Helper()
	fs := []agent.FSRule{
		fsRule(agent.FSDenyRead, "/home/u/.ssh", "/home", "~/.ssh"),
		fsRule(agent.FSDenyRead, "/home/u/.aws", "/home", "~/.aws"),
		fsRule(agent.FSDenyRead, "/etc/shadow", "/", "/etc/shadow"),
		fsRule(agent.FSWrite, "/home/u/work", "/home", "~/work"),
		fsRule(agent.FSWrite, "/tmp/run", "/tmp", "/tmp/run"),
	}
	var exec []agent.ExecRule
	for _, p := range []string{"/usr/bin/python3", "/usr/bin/git", "/bin/sh", "/usr/bin/node", "/usr/bin/go"} {
		exec = append(exec, agent.ExecRule{Path: p, Raw: p, Verdict: agent.VerdictAllow})
	}
	return newPolicy(&agent.RuleTable{FS: fs, Exec: exec, Tier: backend.TierCgroup, Record: agent.RecordFull}, "/run.scope")
}

// BenchmarkPolicyDecideOpen measures the decision itself, the part of the fanotify round trip this package
// controls; docs/P0-DESIGN.md §9 budgets the whole round trip at 30µs.
func BenchmarkPolicyDecideOpen(b *testing.B) {
	p := benchPolicy(b)
	b.ReportAllocs()
	for b.Loop() {
		if v := p.decideOpen("/home/u/work/src/main.go"); !v.allow {
			b.Fatal("unexpected refusal")
		}
	}
}

// BenchmarkPolicyDecideOpenRefused measures the refusing path, which also builds a ledger event.
func BenchmarkPolicyDecideOpenRefused(b *testing.B) {
	p := benchPolicy(b)
	b.ReportAllocs()
	for b.Loop() {
		if v := p.decideOpen("/home/u/.ssh/id_ed25519"); v.allow {
			b.Fatal("unexpected allow")
		}
	}
}

// BenchmarkPolicyDecideExec measures the exec allow-list lookup.
func BenchmarkPolicyDecideExec(b *testing.B) {
	p := benchPolicy(b)
	b.ReportAllocs()
	for b.Loop() {
		if v := p.decideExec("/usr/bin/python3"); !v.allow {
			b.Fatal("unexpected refusal")
		}
	}
}

// BenchmarkListenerHandle measures one whole permission event: the deadline machinery, the decision, the
// response write and, on a refusal, the ledger event. The descriptor is a pipe, so what is measured is this
// package's cost and not the kernel's.
func BenchmarkListenerHandle(b *testing.B) {
	r, w, err := os.Pipe()
	if err != nil {
		b.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	// The listener owns its own descriptor for the pipe's write end, as it would a real fanotify group's.
	// Both copies have to be closed before the drain goroutine below sees end of file.
	dup, err := unix.Dup(int(w.Fd()))
	if err != nil {
		b.Fatalf("dup: %v", err)
	}
	l := &fanotifyListener{
		fd: dup, run: Run{ID: "run-1", Agent: "a", CgroupID: 99}, out: &sink{},
		deadline: time.Second, now: time.Now, marks: map[string]uint64{},
		markMount: func(string, uint64) error { return nil }, unmarkMounts: func() error { return nil },
	}
	l.decide = func(fanEvent) (verdict, error) {
		return verdict{rule: "~/.ssh", reason: record.ReasonReadDenied}, nil
	}

	// Drain the responses so the pipe never fills.
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			if _, err := r.Read(buf); err != nil {
				return
			}
		}
	}()

	fd, err := unix.Open(os.DevNull, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		b.Fatalf("open: %v", err)
	}
	b.ReportAllocs()
	for b.Loop() {
		dupFD, err := unix.Dup(fd)
		if err != nil {
			b.Fatalf("dup: %v", err)
		}
		l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: int32(dupFD), PID: 1})
	}
	b.StopTimer()
	unix.Close(fd)
	_ = l.Close()
	w.Close()
	<-done
}

// BenchmarkBuildRuleMaps measures the per-run compilation Prepare pays once, over a contract with a hundred
// destinations.
func BenchmarkBuildRuleMaps(b *testing.B) {
	var rules []agent.NetRule
	for i := 0; i < 100; i++ {
		rules = append(rules, agent.NetRule{
			Raw: "h:443", Port: 443, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow,
			IPs: []netip.Addr{netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})},
		})
	}
	rt := &agent.RuleTable{Net: rules, Tier: backend.TierCgroup, Record: agent.RecordFull}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := BuildRuleMaps(rt, 1, nil, nil); err != nil {
			b.Fatalf("BuildRuleMaps: %v", err)
		}
	}
}

// BenchmarkSlotAcquireRelease measures the cross-process slot allocation Prepare pays once per run.
func BenchmarkSlotAcquireRelease(b *testing.B) {
	s, err := openSlotTable(b, b.TempDir(), "bench")
	if err != nil {
		b.Fatalf("openSlotTable: %v", err)
	}
	b.ReportAllocs()
	for b.Loop() {
		idx, err := s.acquire(nil)
		if err != nil {
			b.Fatalf("acquire: %v", err)
		}
		if err := s.release(idx); err != nil {
			b.Fatalf("release: %v", err)
		}
	}
}

// BenchmarkDecideEventOffTheRun measures what every *other* process on the machine pays for this run's marks.
//
// A FAN_MARK_MOUNT mark covers the whole mount (§6 E34), so this is the per-open cost on the whole host for
// the life of the run, not a per-run cost: systemd, sshd and the user's shell each pay it on every open. The
// two cases are the two orderings — resolving the path and consulting the in-memory policy first, which is
// what this decides with now, against the /proc/<pid>/cgroup read that used to come first. Only the second
// touches procfs, and only refusable events reach it.
func BenchmarkDecideEventOffTheRun(b *testing.B) {
	dir := b.TempDir()
	target := filepath.Join(dir, "unruled.txt")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		b.Fatalf("write: %v", err)
	}
	fd, err := unix.Open(target, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		b.Fatalf("open: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()

	l := &fanotifyListener{
		run: Run{ID: "run-1", CgroupPath: "/tego.slice/run-1.scope"}, policy: benchPolicy(b),
		now: time.Now, deadline: time.Second, marks: map[string]uint64{},
	}
	ev := fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: int32(fd), PID: int32(os.Getpid())}

	b.Run("path the policy allows", func(b *testing.B) {
		l.cgroupOfPID = func(int) (string, error) {
			b.Fatal("an allowed open must not read /proc/<pid>/cgroup (§6 E34)")
			return "", nil
		}
		b.ReportAllocs()
		for b.Loop() {
			if v, err := l.decideEvent(ev); err != nil || !v.allow {
				b.Fatalf("decideEvent = %+v, %v", v, err)
			}
		}
	})

	b.Run("with the membership read in front", func(b *testing.B) {
		l.cgroupOfPID = cgroupPathOfPID
		b.ReportAllocs()
		for b.Loop() {
			if _, err := cgroupPathOfPID(int(ev.PID)); err != nil {
				b.Fatalf("cgroupPathOfPID: %v", err)
			}
			if v, err := l.decideEvent(ev); err != nil || !v.allow {
				b.Fatalf("decideEvent = %+v, %v", v, err)
			}
		}
	})
}
