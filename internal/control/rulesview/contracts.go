// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
)

// ContractRun is one rules file runs in a ledger snapshot named (run_start's contract_source): the Rules page's
// chooser of contracts. Only a file a run recorded is listed; the dashboard never offers a path of its own.
type ContractRun struct {
	// Path is the rules file's absolute path as the runs recorded it.
	Path string `json:"path"`
	// Gone: nothing is at Path now (the file, or a folder on its way, was removed or renamed since its runs). Its runs
	// still show the rules they ran, from their own copies.
	Gone bool `json:"gone,omitempty"`
	// Why disables changes when the location cannot be checked. Resolved is checked only in the helper.
	Why      string `json:"why,omitempty"`
	Resolved string `json:"-"`
	// Agent is the agent name of the newest run of it.
	Agent string `json:"agent"`
	// Newest is the newest run of it and NewestStart that run's start.
	Newest      string    `json:"newest"`
	NewestStart time.Time `json:"newest_start"`
	// Runs is how many runs of the snapshot named it; Live how many of them are running.
	Runs int `json:"runs"`
	Live int `json:"live"`
}

// ContractsFromRuns is the distinct rules files the snapshot's runs named, one per path as the runs recorded it (the
// page joins two spellings of one file by their ref, and an old link's ref is of the spelling), the file of the newest
// run first, each marked Gone when nothing is at its path now. A run that named none (an older ledger, a contract
// given on standard input) is left out. Distinct paths are checked together in one bounded helper exchange.
// An unavailable location remains listed with its Why and cannot be changed.
func ContractsFromRuns(s *ledgerview.Snapshot) []ContractRun {
	return ContractsFromRunsContext(context.Background(), s)
}

// ContractsFromRunsContext checks recorded locations using the page request context.
func ContractsFromRunsContext(ctx context.Context, s *ledgerview.Snapshot) []ContractRun {
	if s == nil {
		return nil
	}
	var out []ContractRun
	at := map[string]int{}
	for _, r := range s.Runs { // newest start first
		if r.Contract == "" || !filepath.IsAbs(r.Contract) {
			continue
		}
		path := filepath.Clean(r.Contract)
		i, ok := at[path]
		if !ok {
			i = len(out)
			at[path] = i
			out = append(out, ContractRun{Path: path, Agent: r.Agent, Newest: r.ID, NewestStart: r.Start})
		}
		out[i].Runs++
		if r.Live {
			out[i].Live++
		}
	}
	var checked []ContractRun
	locations := make([]string, len(out))
	for i, r := range out {
		locations[i] = r.Path
	}
	if err := pathcheck.Call(pathcheck.WithLocations(ctx, locations...), "control.locations", out, &checked); err != nil {
		for i := range out {
			out[i].Why = err.Error()
			out[i].Resolved = out[i].Path
		}
		return out
	}
	return checked
}

func missingLocation(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}
