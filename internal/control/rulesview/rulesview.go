// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/nextrun"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Options is what a compile needs beside the run: the machine config tego compiles against (nil: the contract is
// shown and not compiled) and the chain anchor `tego run` guards.
type Options struct {
	Machine *config.Machine
	Anchor  string
	// Profiles resolves the extends of a run's rules file when InForce checks that file against the run (the
	// machine's profiles, as tego resolves them). Nil resolves none: a rules file that extends a profile is then
	// not checked, and its positions come from the run's copy.
	Profiles agent.ProfileSource
	// Run is the run as the dashboard's read model holds it (ledgerview's cache), when the caller has it: InForce then
	// takes the lines read, the end, the hits per rule (ledgerview.RuleHits, a refusal counted once as Logs counts
	// it) and the programs' folders from it and reads only the run_start line of the ledger, instead of reading the
	// whole ledger on every view. Nil, or another run, reads the ledger once (scanRun).
	Run *ledgerview.Run
}

// Contract is one run's contract and what it compiles to.
type Contract struct {
	Run string
	// Path is the copy's path; Text its bytes (empty when the run left none).
	Path string
	Text string
	// Missing is a run that left no contract.yaml (it ended before writing one).
	Missing bool
	// Hash is run_start's contract_hash; HashMatches is the copy's sha256 being it.
	Hash        string
	HashMatches bool
	Tier        string
	Cwd         string
	// Table is agent.PrintRuleTable's text, empty when the contract did not compile.
	Table string
	// Diagnostics is each load or compile diagnostic, as `tego compile` writes them.
	Diagnostics string
	// Err is why the contract was not compiled, empty when it was.
	Err string
	// Compiled is the rule table the contract compiles to, nil when it did not; drift reads it.
	Compiled *agent.RuleTable
}

// sealed resolves every extends name to an empty profile: the copy already holds what each profile contributed
// (internal/cli's sealedProfiles, the same reasoning).
type sealed struct{}

// Resolve implements agent.ProfileSource.
func (sealed) Resolve(name string) (string, []byte, error) {
	return "(merged into contract.yaml: " + name + ")", []byte("{}\n"), nil
}

// Load reads the contract of run under the ledger root root and compiles it.
func Load(ctx context.Context, root, run string, o Options) Contract {
	c := Contract{Run: run}
	if !ledger.IsRunID(run) {
		c.Err = "not a run id"
		return c
	}
	dir := filepath.Join(root, run)
	start, err := runStart(dir)
	if err != nil {
		c.Err = "run_start: " + err.Error()
	}
	loadCopy(ctx, &c, dir, start, o, nil, func(path string) string { return execDirs(dir, path) })
	return c
}

// loadCopy fills c from the run's copy in dir and compiles it as the run compiled it (start is its run_start).
// alt, when not nil, is compiled in the copy's place: the run's own rules file loaded to the run's contract_hash,
// whose positions name the real files (InForce). moreDirs is the directories of the programs the run exec'd that
// are not on path, read only when a compile with the dashboard's PATH fails.
func loadCopy(ctx context.Context, c *Contract, dir string, start record.RunStartPayload, o Options, alt *agent.Contract,
	moreDirs func(path string) string) {
	c.Path = filepath.Join(dir, ledger.ContractFile)
	c.Hash, c.Tier, c.Cwd = start.ContractHash, start.Tier, start.Cwd
	data, _, err := readNoFollow(c.Path)
	if errors.Is(err, os.ErrNotExist) {
		c.Missing, c.Err = true, "the run left no contract.yaml"
		return
	}
	if err != nil {
		c.Err = err.Error()
		return
	}
	c.Text = string(data)
	sum := sha256.Sum256(data)
	c.HashMatches = c.Hash != "" && hex.EncodeToString(sum[:]) == c.Hash
	profiles := &agent.ProfileChain{}
	if c.HashMatches {
		profiles = profiles.WithBuiltin(sealed{}).WithDir(sealed{})
	}
	if o.Machine == nil {
		c.Err = "the machine config could not be read, so the contract is not compiled"
		return
	}
	var diag bytes.Buffer
	contract := alt
	if contract == nil {
		// The copy's bytes are compiled at the path the run compiled them from, as the run did: the copy itself
		// sits under the ledger root, and compiled there it reads as a contract beside tego's own records, which
		// then are not read-denied (a false ledger-readable warning and a table without that deny).
		var ds []agent.Diagnostic
		contract, ds, err = agent.LoadBytes(placeOf(c.Path, start), data, profiles)
		_ = agent.WriteDiagnostics(&diag, ds)
		if err != nil {
			c.Diagnostics, c.Err = diag.String(), "the contract does not load: "+err.Error()
			return
		}
	}
	opts := []agent.CompileOption{agent.WithContext(ctx), agent.WithClock(time.Now), agent.Offline(), agent.WithOwnBinaries("")}
	if o.Machine.Home != "" {
		opts = append(opts, agent.WithHome(o.Machine.Home))
	}
	if o.Anchor != "" {
		opts = append(opts, agent.WithChainAnchor(o.Anchor))
	}
	if c.Cwd != "" {
		opts = append(opts, agent.WithCwd(c.Cwd))
	}
	if start.RunCommandGrant != "" {
		opts = append(opts, agent.WithRunCommand(start.RunCommandGrant))
	}
	if t, err := backend.ParseTier(c.Tier); err == nil && t != "" {
		opts = append(opts, agent.WithTiers(t))
	}
	// The run's own PATH is not recorded and the dashboard's differs (a service's PATH lacks ~/.local/bin), so a
	// command the contract names by basename is "not on the PATH" here though the run found it. Compile with the
	// dashboard's PATH first; only when that fails, add the directories of the programs the run did exec.
	path := os.Getenv("PATH")
	rt, ds, err := agent.Compile(contract, o.Machine, append(opts, agent.WithPATH(path))...)
	if err != nil && moreDirs != nil {
		if more := moreDirs(path); more != "" {
			rt, ds, err = agent.Compile(contract, o.Machine, append(opts, agent.WithPATH(path+":"+more))...)
		}
	}
	_ = agent.WriteDiagnostics(&diag, ds)
	c.Diagnostics = diag.String()
	if err != nil {
		c.Err = "the contract does not compile here today: " + err.Error()
		return
	}
	var table bytes.Buffer
	if err := agent.PrintRuleTable(&table, rt); err != nil {
		c.Err = "print: " + err.Error()
		return
	}
	c.Table, c.Compiled = table.String(), rt
}

// placeOf is the path the copy at copyPath is compiled at: the rules file the run named (contract_source), else the
// copy's own path.
func placeOf(copyPath string, start record.RunStartPayload) string {
	if src := start.ContractSource; src != nil && filepath.IsAbs(src.Path) {
		return src.Path
	}
	return copyPath
}

// execDirs is the directories (not already on path) of the programs the run in dir exec'd, ":"-joined: where its
// own PATH found them. It reads at most 5000 exec lines.
func execDirs(dir, path string) string { return nextrun.ExecDirs(dir, path) }

// RunStart is the run_start payload of run under the ledger root root: the machine page reads what the newest run
// recorded about this machine's tiers.
func RunStart(root, run string) (record.RunStartPayload, error) {
	if !ledger.IsRunID(run) {
		return record.RunStartPayload{}, errors.New("not a run id")
	}
	return runStart(filepath.Join(root, run))
}

// runStart is the run's first line's payload; a ledger with no run_start yet is a zero payload.
func runStart(dir string) (record.RunStartPayload, error) {
	var p record.RunStartPayload
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return p, err
	}
	defer func() { _ = r.Close() }()
	for e, err := range r.Iter() {
		if err != nil {
			return p, err
		}
		if e.Kind != record.KindRunStart {
			return p, nil
		}
		return p, e.DecodePayload(&p)
	}
	return p, nil
}

// readCopy reads contract.yaml without following a link, as a regular file, under the loader's size cap.
func readCopy(path string) ([]byte, error) {
	data, _, err := readNoFollow(path)
	return data, err
}

// readNoFollow reads the file at path without following a link at its last name, as a regular file, under the
// loader's size cap, and returns what fstat said of the descriptor it read (its mtime is the file's last change).
func readNoFollow(path string) ([]byte, os.FileInfo, error) {
	f, err := os.OpenFile(filepath.Clean(path), agent.OpenFlags|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }() // opened read-only
	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s: %w", path, agent.ErrNotAFile)
	}
	data, err := io.ReadAll(io.LimitReader(f, agent.MaxContractSize+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > agent.MaxContractSize {
		return nil, nil, fmt.Errorf("%s: %w", path, agent.ErrTooLarge)
	}
	return data, st, nil
}
