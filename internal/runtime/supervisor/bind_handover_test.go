// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"golang.org/x/sys/unix"
)

func TestBindHandoffDelegatesUnixOnlyWhenActualReady(t *testing.T) {
	for _, ready := range []bool{false, true} {
		t.Run(map[bool]string{false: "fallback", true: "handoff"}[ready], func(t *testing.T) {
			f := newFake()
			f.tgid[42] = 40
			f.stats[40] = procStat{ppid: 1, start: 1234}
			raw := sockaddrUn("@unlisted")
			f.put(0x40000, raw)
			p := testPolicy(nil, nil, nil)
			p.Rules.Listen = []agent.ListenRule{}
			l, sink := newTestLoop(t, f, p)
			l.kernelBindHandoff = func() bool { return ready }
			l.mono = func() uint64 { return 100 }
			handleBind(l, notifFor(connectNR(), 42, 5, 0x40000, uint64(len(raw))))
			resp, ok := f.lastResp()
			if !ok {
				t.Fatal("not answered")
			}
			if (resp.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0) != ready {
				t.Fatalf("readiness=%v response=%+v", ready, resp)
			}
			if ready {
				if len(sink.all()) != 0 {
					t.Fatal("supervisor fabricated Unix terminal result")
				}
				n, found := l.ContinuedBind(42, 40, 1234*proc.NanosPerTick+99, 110)
				if !found || n.Path != "unlisted" || !n.Abstract || n.Rule != "" || n.AttemptMonoNS != 100 || n.SupervisorOwned {
					t.Fatalf("wrong metadata: %+v found=%v", n, found)
				}
				if _, found := l.ContinuedBind(42, 40, 1234*proc.NanosPerTick, 111); found {
					t.Fatal("terminal result reused consumed naming")
				}
			} else if len(sink.all()) != 1 {
				t.Fatal("fallback refused bind lost its line")
			}
		})
	}
}

func TestBindNamingTombstonesPreventOldAttemptReuse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		latest continuedBind
	}{
		{"unreadable", continuedBind{tid: 42, naming: BindNaming{AttemptMonoNS: 20}}},
		{"different PID", continuedBind{tid: 42, pid: 41, startNS: 100 * proc.NanosPerTick, named: true, naming: BindNaming{AttemptMonoNS: 20}}},
		{"different birth", continuedBind{tid: 42, pid: 40, startNS: 101 * proc.NanosPerTick, named: true, naming: BindNaming{AttemptMonoNS: 20}}},
		{"consumed", continuedBind{tid: 42, pid: 40, startNS: 100 * proc.NanosPerTick, named: true, consumed: true, naming: BindNaming{AttemptMonoNS: 20}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var h bindHandover
			h.put(continuedBind{tid: 42, pid: 40, startNS: 100 * proc.NanosPerTick, named: true, naming: BindNaming{Path: "old", AttemptMonoNS: 10}})
			h.put(tc.latest)
			if n, found := h.find(42, 40, 100*proc.NanosPerTick, 30); found {
				t.Fatalf("stale bind name: %+v", n)
			}
		})
	}
	var h bindHandover
	h.put(continuedBind{tid: 42, naming: BindNaming{AttemptMonoNS: 10}})
	h.put(continuedBind{tid: 42, pid: 40, startNS: 100 * proc.NanosPerTick, named: true, naming: BindNaming{Path: "new", AttemptMonoNS: 10}})
	if n, found := h.find(42, 40, 100*proc.NanosPerTick, 11); !found || n.Path != "new" {
		t.Fatalf("same attempt tombstone not replaced: %+v %v", n, found)
	}
}
