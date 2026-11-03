// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// ContractRun is one rules file runs in a ledger snapshot named (run_start's contract_source): the Rules page's
// chooser of contracts. Only a file a run recorded is listed; the dashboard never offers a path of its own.
type ContractRun struct {
	// Path is the rules file's absolute path as the runs recorded it.
	Path string `json:"path"`
	// Gone: nothing is at Path now (the file, or a folder on its way, was removed or renamed since its runs). Its runs
	// still show the rules they ran, from their own copies.
	Gone bool `json:"gone,omitempty"`
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
// given on standard input) is left out. Each path is looked at once, so a call costs one system call per distinct
// path, not per run.
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
	for i := range out {
		_, err := os.Lstat(out[i].Path)
		// ENOTDIR: a folder on the way is a file now. Any other error (a folder this user may not search) says
		// nothing about whether the file is there.
		out[i].Gone = errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
	}
	return out
}
