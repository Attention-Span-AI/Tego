// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"sync"

	"github.com/attention-span-ai/tego/internal/check/measure"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdMeasure) }

// cmdMeasure is `tego measure <run> [--json]` (R29): the run's P0 columns — steps, refused, tokens
// in and out, cache, estimated cost, wall, idle max and repeats — recomputed from the ledger alone
// (R18-R23). It is a report, never a finding, so it exits 0 whatever it shows (R25).
func cmdMeasure() Command {
	var asJSON bool
	return Command{
		Name:    "measure",
		Summary: "steps, tokens, cost, wall",
		Usage:   "<run> [--json]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "one JSON object")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 1 {
				message(stderr, "", 0, 0, "tego measure: exactly one run id or run directory", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			return runMeasure(ctx, fs.Arg(0), asJSON, stdout, stderr)
		},
	}
}

// runMeasure resolves the run, opens it read-only — never taking the lock, so a live run can be
// measured — and renders one report.
func runMeasure(ctx context.Context, ref string, asJSON bool, stdout, stderr io.Writer) int {
	mc := &machineOnce{stderr: stderr}
	dir, err := resolveRunDir(ref, true, mc)
	if err != nil {
		return runRefFailed(stderr, "measure", err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			message(stderr, "", 0, 0, fmt.Sprintf("tego measure: no run record at %s", dir), codeIO)
			return identity.ExitError
		}
		message(stderr, "", 0, 0, "tego measure: "+err.Error(), codeIO)
		return identity.ExitError
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	defer func() { warnNewer(stderr, "measure", dir, r.SkippedNewer()) }()
	if err := needRunRecord(r, dir); err != nil {
		message(stderr, "", 0, 0, "tego measure: "+err.Error(), readCode(err))
		return identity.ExitError
	}

	rep, err := measure.ComputeAt(ctx, r, measurePrices("measure", mc, stderr), liveMonoNS(r))
	if err != nil {
		return readFailed(stderr, "measure", err) // §7: a corrupt ledger is tego's own error, not a finding
	}
	warnAnomalies(stderr, "measure", dir, rep.Anomalies())
	write := rep.Table
	if asJSON {
		write = rep.JSON
	}
	if err := write(stdout); err != nil {
		message(stderr, "", 0, 0, "tego measure: "+err.Error(), codeIO)
		return identity.ExitError
	}
	return identity.ExitOK
}

// measurePrices is the machine config's price table (E15, R32), loaded the first time a response is priced: a run
// with no metered model response (capture off, or no model call) never reads the table, so its report prints no
// price warning (every `tego receipt` said "no price table" though nothing was there to price). Every failure
// is one warning line and no prices: a cost estimate must never stop a report being printed, and a table this binary
// refused reads as "$0.00 est. (N unpriced)" rather than a plausible wrong number. cmd names the command on those
// lines (measure, receipt: both price from this one table, so they print one cost).
func measurePrices(cmd string, mc *machineOnce, stderr io.Writer) measure.Prices {
	return &lazyPrices{load: func() measure.Prices { return loadPrices(cmd, mc, stderr) }}
}

// lazyPrices loads its table on the first Cost call, once; a load that failed (nil) prices nothing, which is what a
// nil Prices does.
type lazyPrices struct {
	once  sync.Once
	load  func() measure.Prices
	table measure.Prices
}

// Cost prices u with the table, loading it on the first call.
func (l *lazyPrices) Cost(u ledger.TokenUsage) (float64, bool) {
	l.once.Do(func() { l.table = l.load() })
	if l.table == nil {
		return 0, false
	}
	return l.table.Cost(u)
}

// loadPrices loads the price table now, warning once on stderr when it cannot.
func loadPrices(cmd string, mc *machineOnce, stderr io.Writer) measure.Prices {
	m, err := mc.load()
	if err != nil {
		message(stderr, "", 0, 0, "tego "+cmd+": machine config: "+err.Error(), codeIO)
		return nil
	}
	table, warn := limits.FromMachine(m)
	if warn != nil {
		message(stderr, "", 0, 0, "tego "+cmd+": "+warn.Message, codeNotFound)
		return nil // a nil *PriceTable in an interface is not a nil interface; hand back a real nil
	}
	return table
}

// liveMonoNS is the clock reading R21 measures an unfinished run's wall time against: the same
// monotonic clock the ledger stamps events with. A run that has ended ignores it, and so does a
// reading older than the run's last event (a ledger from an earlier boot), so this is only ever
// consulted where it is meaningful.
func liveMonoNS(r *ledger.Reader) uint64 {
	state, err := r.State()
	if err != nil || state != ledger.StateRunning {
		return 0
	}
	return ledger.SystemClock{}.Mono()
}
