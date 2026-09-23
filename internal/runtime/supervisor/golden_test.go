// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// updateGolden rewrites the frozen event lines instead of comparing against them.
var updateGolden = flag.Bool("update", false, "rewrite testdata/golden/events.jsonl")

// goldenFile is the frozen slice of what this package writes, one line per dispatch kind (§10
// "Fixtures/golden files"). It is a real chain: seq, prev and id link the lines the way a ledger writes
// them, so internal/check views can replay it.
const goldenFile = "testdata/golden/events.jsonl"

// goldenCase is one notification driven end to end for the record.
type goldenCase struct {
	name    string
	syscall string
	setup   func(f *fakeKernel) *notif
}

// TestGoldenEvents freezes one canonical event line per dispatch kind. It fails when a field, a rule name
// or a payload key changes, which is exactly the review this package's output needs: every consumer of
// events.jsonl reads these lines.
func TestGoldenEvents(t *testing.T) {
	// Raw is the entry as a contract declares it, which is what agent.FSRule.RuleName puts in the
	// event's `rule` field (spec/record/v1/README.md: "the declared entry or unmatched"). A declared
	// entry always has one after Compile, so the frozen lines carry the shape a real ledger holds.
	fs := []agent.FSRule{
		{Path: "/work/proj", Kind: agent.FSWrite, Raw: "./proj"},
		{Path: "/work/proj/.env", Kind: agent.FSDenyRead, Raw: "./proj/.env"},
	}
	netRules := []agent.NetRule{
		netRule("api.example.com:443", "api.example.com", 443, "93.184.216.34"),
		unixRuleOf("unix:/run/pg.sock", "/run/pg.sock", false),
	}
	resolvers := mustAddrPorts(t, "127.0.0.53:53")

	cases := []goldenCase{
		{
			name: "connect-allow", syscall: "connect",
			setup: func(f *fakeKernel) *notif {
				f.sockType = unix.SOCK_STREAM
				f.put(0x40000, sockaddrIn4("93.184.216.34", 443))
				return notifFor(connectNR(), 4242, 5, 0x40000, 16)
			},
		},
		{
			name: "connect-refuse", syscall: "connect",
			setup: func(f *fakeKernel) *notif {
				f.sockType = unix.SOCK_STREAM
				f.put(0x40000, sockaddrIn4("203.0.113.9", 443))
				return notifFor(connectNR(), 4242, 5, 0x40000, 16)
			},
		},
		{
			name: "connect-resolver", syscall: "connect",
			setup: func(f *fakeKernel) *notif {
				f.sockType = unix.SOCK_DGRAM
				f.put(0x40000, sockaddrIn4("127.0.0.53", 53))
				return notifFor(connectNR(), 4242, 5, 0x40000, 16)
			},
		},
		{
			name: "unix-connect", syscall: "connect",
			setup: func(f *fakeKernel) *notif {
				f.sockType = unix.SOCK_STREAM
				sa := sockaddrUn("/run/pg.sock")
				f.put(0x40000, sa)
				return notifFor(connectNR(), 4242, 5, 0x40000, uint64(len(sa)))
			},
		},
		{
			name: "fast-open", syscall: "sendto",
			setup: func(f *fakeKernel) *notif {
				f.sockType = unix.SOCK_STREAM
				f.put(0x40000, sockaddrIn4("93.184.216.34", 443))
				f.put(0x50000, []byte("GET / HTTP/1.1\r\n"))
				return notifFor(sendToNR(), 4242, 5, 0x50000, 16, unix.MSG_FASTOPEN, 0x40000, 16)
			},
		},
		{
			name: "datagram-send", syscall: "sendto",
			setup: func(f *fakeKernel) *notif {
				f.sockType = unix.SOCK_DGRAM
				f.put(0x40000, sockaddrIn4("127.0.0.53", 53))
				f.put(0x50000, []byte{0, 1})
				return notifFor(sendToNR(), 4242, 5, 0x50000, 2, 0, 0x40000, 16)
			},
		},
		{
			name: "write-open", syscall: "openat",
			setup: func(f *fakeKernel) *notif {
				f.put(0x10000, cstr("/work/proj/out.txt"))
				return notifFor(nrFor(t, "openat"), 4242, argCWD, 0x10000, 0x241)
			},
		},
		{
			name: "write-open-refused", syscall: "openat",
			setup: func(f *fakeKernel) *notif {
				f.put(0x10000, cstr("/etc/passwd"))
				return notifFor(nrFor(t, "openat"), 4242, argCWD, 0x10000, 0x241)
			},
		},
		{
			name: "exec-truncated-argv", syscall: "execve",
			setup: func(f *fakeKernel) *notif {
				f.put(0x10000, cstr("/usr/bin/python3"))
				execFixture(f, 0x20000, []string{"python3", "-c", "print(1)"})
				f.stats[4242] = procStat{ppid: 4100, start: 1234}
				f.stats[4100] = procStat{ppid: 1, start: 99}
				return notifFor(nrFor(t, "execve"), 4242, 0x10000, 0x20000, 0)
			},
		},
		{
			name: "unlink", syscall: "unlinkat",
			setup: func(f *fakeKernel) *notif {
				f.put(0x10000, cstr("/work/proj/tmp.txt"))
				return notifFor(nrFor(t, "unlinkat"), 4242, argCWD, 0x10000, 0)
			},
		},
		{
			name: "rename", syscall: "renameat",
			setup: func(f *fakeKernel) *notif {
				f.put(0x10000, cstr("/work/proj/a"))
				f.put(0x11000, cstr("/work/proj/b"))
				return notifFor(nrFor(t, "renameat"), 4242, argCWD, 0x10000, argCWD, 0x11000)
			},
		},
		{
			name: "mkdir", syscall: "mkdirat",
			setup: func(f *fakeKernel) *notif {
				f.put(0x10000, cstr("/work/proj/sub"))
				return notifFor(nrFor(t, "mkdirat"), 4242, argCWD, 0x10000, 0o755)
			},
		},
		{
			name: "symlink", syscall: "symlinkat",
			setup: func(f *fakeKernel) *notif {
				f.put(0x10000, cstr("../target"))
				f.put(0x11000, cstr("/work/proj/link"))
				return notifFor(nrFor(t, "symlinkat"), 4242, 0x10000, argCWD, 0x11000)
			},
		},
		{
			// A hard link gives existing content a second name (R11 "inherently mutating"). Both paths are
			// read, existing name first, matching rename's from/to order.
			name: "link", syscall: "linkat",
			setup: func(f *fakeKernel) *notif {
				f.put(0x10000, cstr("/work/proj/a"))
				f.put(0x11000, cstr("/work/proj/b"))
				return notifFor(nrFor(t, "linkat"), 4242, argCWD, 0x10000, argCWD, 0x11000)
			},
		},
	}

	var buf bytes.Buffer
	prev := ""
	seq := uint64(0)
	for _, tc := range cases {
		f := newFake()
		n := tc.setup(f)
		pol := testPolicy(netRules, fs, resolvers)
		pol.MaxArgvSize = 12 // small enough that the golden exec line carries argv_truncated
		l, sink := newTestLoop(t, f, pol)
		l.handle(n)
		evs := sink.all()
		if len(evs) != 1 {
			t.Fatalf("%s: %d events, want exactly one", tc.name, len(evs))
		}
		ev := evs[0]
		// Freeze the fields a ledger stamps, so the golden line is a function of this package alone.
		ev.TS = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
		ev.MonoNS = 1_000_000 * (seq + 1)
		ev.Seq = seq
		ev.Prev = prev
		line, err := ev.MarshalLine()
		if err != nil {
			t.Fatalf("%s: marshal: %v", tc.name, err)
		}
		if err := ev.Validate(); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
		prev = ev.ID
		seq++
	}

	path := filepath.Join(".", goldenFile)
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run: go test ./internal/runtime/supervisor -run TestGoldenEvents -update)", err)
	}
	if !bytes.Equal(want, buf.Bytes()) {
		t.Errorf("the frozen event lines changed.\n--- want\n%s\n--- got\n%s", want, buf.Bytes())
	}
}

// TestGoldenChainVerifies replays the frozen slice the way a reader does: every line's digest and every
// seq/prev link must hold (record I3, I4).
func TestGoldenChainVerifies(t *testing.T) {
	data, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Skipf("no golden file yet: %v", err)
	}
	prev := ""
	for i, line := range bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n")) {
		id, err := record.VerifyLine(line)
		if err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		ev, err := record.Decode(line)
		if err != nil {
			t.Fatalf("line %d: decode: %v", i, err)
		}
		if ev.Prev != prev {
			t.Errorf("line %d: prev = %q, want %q", i, ev.Prev, prev)
		}
		if err := ev.Validate(); err != nil {
			t.Errorf("line %d: %v", i, err)
		}
		if ev.Source != record.SourceSeccomp && ev.Source != record.SourceSupervisor {
			t.Errorf("line %d: source = %s", i, ev.Source)
		}
		prev = id
	}
}

// mustAddrPorts parses the resolver fixtures.
func mustAddrPorts(t *testing.T, ss ...string) []netip.AddrPort {
	t.Helper()
	out := make([]netip.AddrPort, 0, len(ss))
	for _, s := range ss {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		out = append(out, ap)
	}
	return out
}
