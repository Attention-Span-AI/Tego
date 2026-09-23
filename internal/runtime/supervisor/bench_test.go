// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"strconv"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// discardSink is a sink whose cost is not part of the measurement.
type discardSink struct{}

func (discardSink) Emit(*record.Event) {}

// benchLoop builds a loop over the fake kernel with the events discarded.
func benchLoop(b *testing.B, f *fakeKernel, pol *Policy) *Loop {
	b.Helper()
	f.quietWalks = true
	l, err := New(testListener(), pol, discardSink{}, Options{kernel: f, Workers: 1})
	if err != nil {
		b.Fatal(err)
	}
	return l
}

// BenchmarkNotificationRoundTrip measures the fast path P0-DESIGN §9 budgets at under 10 µs per notified
// syscall: dispatch, the bracketed read of the argument, the verdict, the response and the event. The
// kernel is faked, so what this reports is the share of the budget this package's own work takes; the
// ioctl round trip itself is measured by BenchmarkSeccompNotifyRoundTrip (integration build tag), over a real
// listener.
func BenchmarkNotificationRoundTrip(b *testing.B) {
	fs := []agent.FSRule{{Path: "/work/proj", Kind: agent.FSWrite}}
	nr := func(name string) int32 {
		for k, e := range buildDispatch() {
			if e.name == name {
				return k.nr
			}
		}
		b.Skipf("%s does not exist on this architecture", name)
		return 0
	}
	cases := []struct {
		name  string
		build func(f *fakeKernel) (*Policy, *notif)
	}{
		{
			name: "write_open_continue",
			build: func(f *fakeKernel) (*Policy, *notif) {
				f.put(0x1000, cstr("/work/proj/out.txt"))
				return testPolicy(nil, fs, nil), notifFor(nr("openat"), 42, argCWD, 0x1000, 0x241)
			},
		},
		{
			name: "mkdir_continue",
			build: func(f *fakeKernel) (*Policy, *notif) {
				f.put(0x1000, cstr("/work/proj/d"))
				return testPolicy(nil, fs, nil), notifFor(nr("mkdirat"), 42, argCWD, 0x1000, 0o755)
			},
		},
		{
			name: "connect_allow",
			build: func(f *fakeKernel) (*Policy, *notif) {
				f.put(0x2000, sockaddrIn4("93.184.216.34", 443))
				f.sockType = unix.SOCK_STREAM
				rules := []agent.NetRule{netRule("api:443", "api", 443, "93.184.216.34")}
				return testPolicy(rules, fs, nil), notifFor(connectNR(), 42, 5, 0x2000, 16)
			},
		},
		{
			name: "connect_refuse",
			build: func(f *fakeKernel) (*Policy, *notif) {
				f.put(0x2000, sockaddrIn4("203.0.113.9", 443))
				f.sockType = unix.SOCK_STREAM
				return testPolicy(nil, fs, nil), notifFor(connectNR(), 42, 5, 0x2000, 16)
			},
		},
		{
			name: "execve_argv",
			build: func(f *fakeKernel) (*Policy, *notif) {
				f.put(0x1000, cstr("/usr/bin/python3"))
				execFixture(f, 0x20000, []string{"python3", "-c", "print(1)"})
				f.stats[42] = procStat{ppid: 1, start: 10}
				return testPolicy(nil, fs, nil), notifFor(nr("execve"), 42, 0x1000, 0x20000, 0)
			},
		},
		{
			// A PATH search's miss (R16b (0)): answered with the walk's ENOENT, no line.
			name: "execve_miss",
			build: func(f *fakeKernel) (*Policy, *notif) {
				f.put(0x1000, cstr("/usr/local/bin/python3"))
				f.imageErrs["/usr/local/bin/python3"] = unix.ENOENT
				execFixture(f, 0x20000, []string{"python3", "-c", "print(1)"})
				f.stats[42] = procStat{ppid: 1, start: 10}
				return testPolicy(nil, fs, nil), notifFor(nr("execve"), 42, 0x1000, 0x20000, 0)
			},
		},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			f := newFake()
			pol, proto := tc.build(f)
			l := benchLoop(b, f, pol)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				n := *proto
				n.answered, n.gone = false, false
				l.admit(&n) // receive's bookkeeping: the receipt's mono_ns and the thread's order (R23a)
				l.handle(&n)
			}
		})
	}
}

// BenchmarkParseSockaddr and BenchmarkNearestFS isolate the two hot pure functions. Neither allocates, which
// allocs_test.go holds them to; b.Loop keeps their setup out of B/op, which CI's bench gate compares with the
// parent commit's (a b.N loop counted compile's allocations as 1 B/op at small N).
func BenchmarkParseSockaddr(b *testing.B) {
	sa := sockaddrIn4("93.184.216.34", 443)
	b.ReportAllocs()
	for b.Loop() {
		if d := parseSockaddr(sa); !d.ok {
			b.Fatal("parse failed")
		}
	}
}

func BenchmarkNearestFS(b *testing.B) {
	c := compile(testPolicy(nil, []agent.FSRule{
		{Path: "/work/proj", Kind: agent.FSWrite},
		{Path: "/work/proj/secrets", Kind: agent.FSDenyRead},
		{Path: "/home/u/.cache", Kind: agent.FSWrite},
	}, nil))
	b.ReportAllocs()
	for b.Loop() {
		if c.nearestFS("/work/proj/src/main.go") == nil {
			b.Fatal("no match")
		}
	}
}

// BenchmarkSendMMsgTail measures R13b's cost past the 64th message, where each tail message is decided
// against the policy. The dedupe collapses a run of identical addresses into one decision, so the batch
// of identical messages decides the tail once; the alternating batches are the worst case, one decision per
// message. The fake kernel makes the reads and the cwd readlink nearly free, so the unix row's real cost
// adds one readlink(/proc/<pid>/cwd) and one ID_VALID per message on top of what this reports.
func BenchmarkSendMMsgTail(b *testing.B) {
	const arrayAddr, aAddr, bAddr = 0x100000, 0x40000, 0x41000
	rules := []agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5"), netRule("10.0.0.6:8080", "", 8080, "10.0.0.6")}
	for _, bc := range []struct {
		name     string
		a, b     []byte
		sockType int
		alt      bool
	}{
		{"identical inet", sockaddrIn4("10.0.0.5", 8080), nil, unix.SOCK_DGRAM, false},
		{"alternating inet", sockaddrIn4("10.0.0.5", 8080), sockaddrIn4("10.0.0.6", 8080), unix.SOCK_DGRAM, true},
		{"alternating relative unix", sockaddrUn("a.sock"), sockaddrUn("b.sock"), unix.SOCK_DGRAM, true},
	} {
		b.Run(bc.name, func(b *testing.B) {
			f := newFake()
			f.sockType = bc.sockType
			f.links["/proc/4242/cwd"] = "/work"
			f.put(arrayAddr, mmsgArray(mmsgKernelMax, func(i int) uint64 {
				if bc.alt && i%2 == 1 {
					return bAddr
				}
				return aAddr
			}))
			f.put(aAddr, bc.a)
			if bc.b != nil {
				f.put(bAddr, bc.b)
			}
			l := benchLoop(b, f, testPolicy(rules, []agent.FSRule{{Path: "/work", Kind: agent.FSWrite}}, nil))
			if bc.sockType == unix.SOCK_DGRAM && bc.a[0] == unix.AF_UNIX {
				// The run's own sockets, so the write entry's implicit admit holds for them (R11a) and each
				// decision pays the identity check: a stat and one cached sock_diag lookup.
				f.bindsSocket(b, l, sockID{ino: 9001, cookie: 1}, "/work/a.sock")
				f.bindsSocket(b, l, sockID{ino: 9002, cookie: 2}, "/work/b.sock")
			}
			b.ResetTimer()
			for range b.N {
				f.mu.Lock()
				f.responses = f.responses[:0]
				f.mu.Unlock()
				l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, mmsgKernelMax, 0))
			}
		})
	}
}

// BenchmarkSendMMsgForeignUnix is R11a's cost where no remembered socket is bound to the file a name resolves to: a
// batch of 1,024 datagrams alternating between two socket files under a write entry that no
// process of the run bound, with the run holding many remembered sockets, bound elsewhere or bound to nothing. It
// reports the sock_diag lookups one batch makes (lookups/op); the fake answers each in nanoseconds, where the real
// kernel takes 14 to 25 µs (BenchmarkUnixBound). One batch is sent before the measurement: the first lookup of a
// bound socket is paid once in its life, and TestR11aWorkIsBoundedPerNotification counts it. The unrecorded case
// holds the paths of 255 binds R11a could not record, each stat'ed once per batch.
func BenchmarkSendMMsgForeignUnix(b *testing.B) {
	const arrayAddr, aAddr, bAddr = 0x100000, 0x40000, 0x41000
	for _, bc := range []struct {
		name                       string
		bound, unbound, unrecorded int
	}{
		{"4096 bound elsewhere", runSocketsMax, 0, 0},
		{"200 bound to nothing", 0, 200, 0},
		{"4096 bound to nothing", 0, runSocketsMax, 0},
		{"255 unrecorded binds", 0, 0, unrecordedMax - 1},
	} {
		b.Run(bc.name, func(b *testing.B) {
			f := newFake()
			f.sockType, f.sockDomain = unix.SOCK_DGRAM, unix.AF_UNIX
			f.put(arrayAddr, mmsgArray(mmsgKernelMax, func(i int) uint64 {
				if i%2 == 1 {
					return bAddr
				}
				return aAddr
			}))
			f.put(aAddr, sockaddrUn("/work/fa"))
			f.put(bAddr, sockaddrUn("/work/fb"))
			l := benchLoop(b, f, contractPolicy(&agent.Contract{Net: &agent.NetSection{}}, nil,
				[]agent.FSRule{{Path: "/work", Kind: agent.FSWrite}}))
			f.boundFiles, f.unboundSocks = map[sockID]fileID{}, map[sockID]bool{}
			for i := range bc.bound + bc.unbound {
				id := sockID{ino: uint64(1<<20 + i), cookie: 1}
				if i < bc.bound {
					f.boundFiles[id] = fileID{dev: 1, ino: uint64(1<<21 + i)}
				} else {
					f.unboundSocks[id] = true
				}
				if !l.runSockets.add(f, id, bindNow()) {
					b.Fatal("the set refused a socket below its bound")
				}
			}
			for i := range bc.unrecorded {
				l.runSockets.lost("/work/d/" + strconv.Itoa(i) + ".sock")
			}
			l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, mmsgKernelMax, 0))
			f.mu.Lock()
			f.diagLookups = 0
			f.mu.Unlock()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				f.mu.Lock()
				f.responses = f.responses[:0]
				f.mu.Unlock()
				l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, mmsgKernelMax, 0))
			}
			b.StopTimer()
			f.mu.Lock()
			b.ReportMetric(float64(f.diagLookups)/float64(b.N), "lookups/op")
			f.mu.Unlock()
			if r, _ := f.lastResp(); r.Flags != 0 {
				b.Fatalf("a batch to foreign sockets was answered %+v", r)
			}
		})
	}
}
