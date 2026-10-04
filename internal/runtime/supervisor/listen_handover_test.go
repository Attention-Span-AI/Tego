// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"golang.org/x/sys/unix"
)

func TestListenHandoffUsesActualBoundSocketForUnixSpelling(t *testing.T) {
	for _, spelling := range []string{"relative.sock", "/symlinked-parent/listener.sock", "@abstract"} {
		for _, ready := range []bool{false, true} {
			t.Run(spelling+map[bool]string{false: "/fallback", true: "/actual-ready"}[ready], func(t *testing.T) {
				f := newFake()
				f.sockType = unix.SOCK_STREAM
				f.tgid[42] = 40
				f.stats[40] = procStat{ppid: 1, start: 1234}
				p := testPolicy(nil, nil, nil)
				p.Rules.Listen = []agent.ListenRule{{Proto: agent.ProtoUnix, UnixPath: "/canonical-parent/listener.sock"}}
				l, sink := newTestLoop(t, f, p)
				k := &listenerFake{bindFake: &bindFake{fakeKernel: f}, name: sockaddrUn(spelling), cookie: 9}
				l.k = k
				l.kernelListenHandoff = func() bool { return ready }
				l.mono = func() uint64 { return 100 }
				handleListen(l, notifFor(connectNR(), 42, 5, 8))
				resp, answered := f.lastResp()
				if !answered || (resp.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0) != ready || k.listens != 0 {
					t.Fatalf("ready=%v response=%+v relay=%d", ready, resp, k.listens)
				}
				if !ready {
					if len(sink.all()) != 1 || resp.Error == 0 {
						t.Fatal("unready fallback silently delegated")
					}
					return
				}
				if len(sink.all()) != 0 {
					t.Fatal("Unix listen fabricated a terminal result before the kernel syscall")
				}
				n, found := l.ContinuedListen(42, 40, 1234*proc.NanosPerTick+99, 110)
				want := spelling
				if spelling[0] == '@' {
					want = spelling[1:]
				}
				if !found || n.Path != want || n.SupervisorOwned || n.Rule != "" || n.Abstract != (spelling[0] == '@') {
					t.Fatalf("raw naming gained authority or changed spelling: %+v %v", n, found)
				}
				if _, found := l.ContinuedListen(42, 40, 1234*proc.NanosPerTick, 111); found {
					t.Fatal("consumed listener naming reused")
				}
			})
		}
	}
}

func TestListenHandoffTombstonesSupervisorOwnedRelay(t *testing.T) {
	f := newFake()
	f.sockType = unix.SOCK_STREAM
	f.tgid[42] = 40
	f.stats[40] = procStat{ppid: 1, start: 1234}
	p := testPolicy(nil, nil, nil)
	p.Rules.Listen = []agent.ListenRule{}
	l, sink := newTestLoop(t, f, p)
	k := &listenerFake{bindFake: &bindFake{fakeKernel: f}, name: sockaddrIn4("0.0.0.0", 0)}
	l.k = k
	l.kernelListenHandoff = func() bool { return true }
	l.mono = func() uint64 { return 100 }
	handleListen(l, notifFor(connectNR(), 42, 5, 8))
	n, found := l.ContinuedListen(42, 40, 1234*proc.NanosPerTick, 110)
	if !found || !n.SupervisorOwned || len(sink.all()) != 1 {
		t.Fatalf("relay refusal lost completion owner: %+v %v events=%d", n, found, len(sink.all()))
	}
	// The bind and listen rings must not lend names to each other.
	if _, found := l.ContinuedBind(42, 40, 1234*proc.NanosPerTick, 110); found {
		t.Fatal("listen outcome consumed unrelated bind metadata")
	}
}
