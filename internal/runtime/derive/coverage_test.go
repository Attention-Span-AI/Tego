// SPDX-License-Identifier: Apache-2.0

package derive_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The closed reason set per process (R37). Each row is a real shape ARCHITECTURE §12 names.
func TestClassify(t *testing.T) {
	cases := []struct {
		name    string
		process derive.Process
		want    string
		gap     bool
	}{
		{
			name: "system python on OpenSSL 3.5 is captured",
			process: derive.Process{PID: 1, Binary: "/usr/bin/python3.12", Library: "/usr/lib/x86_64-linux-gnu/libssl.so.3",
				Symbols: []string{"SSL_write", "SSL_write_ex2", "SSL_read", "SSL_read_ex"}},
		},
		{
			name: "node exports the plain entry points",
			process: derive.Process{PID: 2, Binary: "/usr/bin/node", Library: "/usr/bin/node",
				Symbols: []string{"SSL_write", "SSL_read"}},
		},
		{
			name:    "a process discovery could read nothing of: a Go binary gone before its exec was handled",
			process: derive.Process{PID: 3, Binary: "/usr/bin/gh"},
			want:    derive.GapNoOpenSSL, gap: true,
		},
		{
			// R37 as amended: without E71 a Go binary's own TLS cannot be told from none at all, and its
			// executable is the candidate R4 read.
			name:    "a live Go binary whose own executable was read and exports none of the symbols",
			process: derive.Process{PID: 8, Binary: "/usr/bin/gh", Library: "/usr/bin/gh"},
			want:    derive.GapStaticTLSNoSymbols, gap: true,
		},
		{
			name: "Claude Code's Bun runtime: a TLS library with none of the symbols",
			process: derive.Process{PID: 4, Binary: "/usr/local/bin/claude", Library: "/usr/local/bin/claude",
				Symbols: []string{"BORINGSSL_bcm_power_on_self_test"}},
			want: derive.GapStaticTLSNoSymbols, gap: true,
		},
		{
			name: "a rustls binary: writes but no reads is still half a conversation",
			process: derive.Process{PID: 5, Binary: "/usr/local/bin/codex", Library: "/usr/local/bin/codex",
				Symbols: []string{"SSL_write"}},
			want: derive.GapStaticTLSNoSymbols, gap: true,
		},
		{
			name: "a container's own libssl, resolved through /proc/<pid>/root (R39)",
			process: derive.Process{PID: 7, Binary: "/proc/4242/root/usr/bin/python3.11",
				Library: "/proc/4242/root/usr/lib/libssl.so.3", Symbols: []string{"SSL_write_ex", "SSL_read_ex"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			why, gap := derive.Classify(tc.process)
			if gap != tc.gap || why != tc.want {
				t.Errorf("(%q, %v), want (%q, %v)", why, gap, tc.want, tc.gap)
			}
			if gap && !derive.IsCaptureWhy(why) {
				t.Errorf("%q is outside the closed why set %v", why, derive.CaptureWhys)
			}
		})
	}
}

// Coverage is per (binary, reason): a process that execs many times is one gap with a count,
// and a captured process is no gap at all (R37, I4).
func TestCoverage(t *testing.T) {
	c := derive.NewCoverage()
	gh := func(pid int) derive.Process { return derive.Process{PID: pid, Binary: "/usr/bin/gh"} }

	if why, gap := c.Settle(gh(101)); why != derive.GapNoOpenSSL || !gap {
		t.Errorf("(%q, %v), want the process counted as a gap", why, gap)
	}
	c.Settle(gh(102))
	c.Settle(derive.Process{PID: 103, Binary: "/usr/bin/python3.12", Library: "libssl.so.3",
		Symbols: []string{"SSL_write", "SSL_read"}})
	c.Note("/usr/bin/python3.12", derive.GapRingBufferDrop, 17)
	c.Note("/usr/bin/python3.12", "invented-reason", 1)

	gaps := c.Gaps()
	want := []derive.Gap{
		{What: record.GapCapture, Why: derive.GapMalformed, Binary: "/usr/bin/python3.12", Count: 1},
		{What: record.GapCapture, Why: derive.GapNoOpenSSL, Binary: "/usr/bin/gh", Count: 2},
		{What: record.GapCapture, Why: derive.GapRingBufferDrop, Binary: "/usr/bin/python3.12", Count: 17},
	}
	if len(gaps) != len(want) {
		t.Fatalf("gaps = %+v, want %+v", gaps, want)
	}
	for i := range want {
		if gaps[i] != want[i] {
			t.Errorf("gap %d = %+v, want %+v", i, gaps[i], want[i])
		}
	}
}

// Settle is the uprobe source's way in. It holds each process's verdict until the process can no
// longer be captured and settles it once, so a pid seen again is another process (the kernel reused it, or
// the process exec'd a new image) and is counted again. A captured
// process is still no gap.
func TestCoverageSettle(t *testing.T) {
	c := derive.NewCoverage()
	gh := derive.Process{PID: 101, Binary: "/usr/bin/gh", Library: "/usr/bin/gh"}
	for i := 0; i < 2; i++ {
		if why, gap := c.Settle(gh); why != derive.GapStaticTLSNoSymbols || !gap {
			t.Fatalf("Settle = (%q, %v), want static-tls-no-symbols", why, gap)
		}
	}
	if _, gap := c.Settle(derive.Process{PID: 102, Binary: "/usr/bin/python3.12", Library: "libssl.so.3",
		Symbols: []string{"SSL_write", "SSL_read"}}); gap {
		t.Error("a captured process was settled as a gap")
	}
	gaps := c.Gaps()
	if len(gaps) != 1 || gaps[0].Binary != "/usr/bin/gh" || gaps[0].Count != 2 {
		t.Errorf("gaps = %+v, want /usr/bin/gh counted twice", gaps)
	}
}

// The report renders as v1 gap lines, one per reason and binary.
func TestCoverageEvents(t *testing.T) {
	c := derive.NewCoverage()
	c.Settle(derive.Process{PID: 1, Binary: "/usr/bin/gh"})
	c.Note("/usr/bin/python3.12", derive.GapRingBufferDrop, 4)
	meta := derive.Meta{
		Run: "r-3f9c2a1b-0dllq06ts7400-k7m2pq", Agent: "retriever", PID: 48212, TID: 48212,
		Cgroup: 44821, Source: record.SourceSSL, TS: time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC),
		MonoNS: 812_357_500_000,
	}
	events := c.Events(meta)
	if len(events) != 2 {
		t.Fatalf("%d events, want one per gap", len(events))
	}
	for _, e := range events {
		if err := e.Validate(); err != nil {
			t.Errorf("%v", err)
		}
		if _, err := e.MarshalLine(); err != nil {
			t.Errorf("marshal: %v", err)
		}
		var p record.GapPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.What != record.GapCapture {
			t.Errorf("what = %q", p.What)
		}
		switch p.Why {
		case derive.GapNoOpenSSL:
			if p.Binary != "/usr/bin/gh" || p.Count != 0 {
				t.Errorf("gap = %+v, want the binary and no count for a single sighting", p)
			}
		case derive.GapRingBufferDrop:
			if p.Count != 4 {
				t.Errorf("count = %d, want the number of events lost", p.Count)
			}
		default:
			t.Errorf("why = %q", p.Why)
		}
	}
}

// The ledger is bounded: binaries are agent-named, so past the cap gaps count into one entry per reason.
func TestCoverageCapsDistinctBinaries(t *testing.T) {
	c := derive.NewCoverage()
	const n = 100000
	for i := 0; i < n; i++ {
		c.Settle(derive.Process{PID: i, Binary: fmt.Sprintf("/tmp/go-build%d/x.test", i)})
	}
	gaps := c.Gaps()
	if len(gaps) > derive.MaxCoverageKeys+1 {
		t.Fatalf("len(Gaps()) = %d, want <= %d", len(gaps), derive.MaxCoverageKeys+1)
	}
	var total int64
	for _, g := range gaps {
		total += g.Count
	}
	if total != n {
		t.Fatalf("total count = %d, want %d", total, n)
	}
}
