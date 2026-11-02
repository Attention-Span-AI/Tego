// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The Contracts benchmarks read a generated ledger root of benchRuns runs of benchContracts contract files, every
// tenth run a generated contract (no contract_source), as a dashboard serving a long-used root reads it.
const (
	benchRuns      = 5000
	benchContracts = 25
)

// benchRoot writes a ledger root of runs runs of contracts contract files under tb's temporary folder, the newest
// three listed in the live index as starting runs are, and returns a service over it with the real liveness probe
// and the real guarded read, whose clock says the root last changed an hour ago, as between runs (listingSettle). A
// run is its first line only: Contracts reads nothing else of it.
func benchRoot(tb testing.TB, runs, contracts int) *Service {
	tb.Helper()
	dir := tb.TempDir()
	proj, root := filepath.Join(dir, "proj"), filepath.Join(dir, "ledger")
	for _, d := range []string{proj, filepath.Join(root, ledger.LiveDir)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			tb.Fatal(err)
		}
	}
	paths := make([]string, contracts)
	for i := range paths {
		paths[i] = filepath.Join(proj, fmt.Sprintf("agent-%02d.yaml", i))
		text := strings.Replace(baseText, "name: tester", fmt.Sprintf("name: agent-%02d", i), 1)
		if err := os.WriteFile(paths[i], []byte(text), 0o600); err != nil {
			tb.Fatal(err)
		}
	}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := range runs {
		run := fmt.Sprintf("r-%05d-bench", i)
		p := record.RunStartPayload{Tier: "landlock", Capture: "off", ContractHash: strings.Repeat("0", 64),
			Command: []string{"sh"}, Cwd: proj, Kernel: "6", StopGrace: "1s", RecordMinor: record.Minor}
		if i%10 != 9 {
			p.ContractSource = &record.ContractSource{Path: paths[i%contracts]}
		}
		e := ledgertest.Event(tb, record.KindRunStart, p)
		e.Run, e.TS = run, t0.Add(time.Duration(i)*time.Second)
		l, err := e.MarshalLine()
		if err != nil {
			tb.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(root, run), 0o700); err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, run, ledger.EventsFile), append(l, '\n'), 0o600); err != nil {
			tb.Fatal(err)
		}
		if i >= runs-3 { // listed, with a lock file no one holds: probed, and not live
			for _, p := range []string{filepath.Join(root, ledger.LiveDir, run), filepath.Join(root, run, ledger.LockFile)} {
				if err := os.WriteFile(p, nil, 0o600); err != nil {
					tb.Fatal(err)
				}
			}
		}
	}
	later := time.Now().Add(time.Hour)
	return &Service{Ledger: root, Home: filepath.Join(dir, "home"), clock: func() time.Time { return later }}
}

// BenchmarkContracts is Contracts over a root of 5,000 runs: warm, as the Rules and Change rules pages ask it again on
// every request and live update with nothing changed; relist, as the first request after a run started or ended
// lists the root again, every run's run_start already read; cold, as the first page after the dashboard starts reads
// every run's first line.
func BenchmarkContracts(b *testing.B) {
	s := benchRoot(b, benchRuns, benchContracts)
	b.Run("warm", func(b *testing.B) {
		if cs, err := s.Contracts(); err != nil || len(cs) != benchContracts {
			b.Fatalf("Contracts: %d contracts, err %v; want %d", len(cs), err, benchContracts)
		}
		for b.Loop() {
			if _, err := s.Contracts(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("relist", func(b *testing.B) {
		for b.Loop() {
			s.listing = nil // what a run directory made or removed does to the key
			if _, err := s.Contracts(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("cold", func(b *testing.B) {
		for b.Loop() {
			if _, err := (&Service{Ledger: s.Ledger, Home: s.Home}).Contracts(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkChangePage is the service's part of one GET of Change rules for a contract over a root of 5,000 runs
// (internal/control/web changePage): Contracts, the guarded read of the file (Current) and its History.
func BenchmarkChangePage(b *testing.B) {
	s := benchRoot(b, benchRuns, benchContracts)
	cs, err := s.Contracts()
	if err != nil || len(cs) != benchContracts {
		b.Fatalf("Contracts: %d contracts, err %v; want %d", len(cs), err, benchContracts)
	}
	ref := cs[0].Ref
	for b.Loop() {
		if _, err := s.Contracts(); err != nil {
			b.Fatal(err)
		}
		if _, err := s.Current(ref); err != nil {
			b.Fatal(err)
		}
		if _, err := s.History(ref); err != nil {
			b.Fatal(err)
		}
	}
}
