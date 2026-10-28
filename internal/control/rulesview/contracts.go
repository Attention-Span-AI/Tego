// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"path/filepath"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// ContractRun is one rules file runs in a ledger snapshot named (run_start's contract_source): the Rules page's
// chooser of contracts. Only a file a run recorded is listed; the dashboard never offers a path of its own.
type ContractRun struct {
	// Path is the rules file's absolute path as the runs recorded it.
	Path string `json:"path"`
	// Agent is the agent name of the newest run of it.
	Agent string `json:"agent"`
	// Newest is the newest run of it and NewestStart that run's start.
	Newest      string    `json:"newest"`
	NewestStart time.Time `json:"newest_start"`
	// Runs is how many runs of the snapshot named it; Live how many of them are running.
	Runs int `json:"runs"`
	Live int `json:"live"`
}

// ContractsFromRuns is the distinct rules files the snapshot's runs named, the file of the newest run first. A run
// that named none (an older ledger, a contract given on standard input) is left out.
func ContractsFromRuns(s *ledgerview.Snapshot) []ContractRun {
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
	return out
}
