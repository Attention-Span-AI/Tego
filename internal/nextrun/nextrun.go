// SPDX-License-Identifier: Apache-2.0

package nextrun

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/profilesrc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Context is what a contract is compiled for: the run it will next govern, as the newest run of it recorded. A rule
// write is refused when Compile refuses the new text in this context, so it must be the context tego compiles in, or
// a write path refuses what tego runs or writes what tego then refuses.
type Context struct {
	// Contract is the contract file's absolute path: where relative profile and fs entries are placed from.
	Contract string
	// Cwd is the run's working directory (run_start.cwd), which relative entries are read from; empty, the contract's
	// folder.
	Cwd string
	// Tier is the tier the run ran at (run_start.tier): an auto contract resolves to it, not to the highest tier the
	// compiling binary could build, which the run did not get (F3).
	Tier string
	// Tiers is what an auto contract resolves among when Tier is empty or the text pins a tier other than Tier (a free
	// edit that changes the tier): `tego rule` passes the tiers its build has; the dashboard, which links no backend,
	// passes none, so auto resolves to the machine ceiling.
	Tiers []backend.Tier
	// RunCommandGrant is the exec rule tego run's command line added for the run (run_start.run_command_grant).
	RunCommandGrant string
	// PATH is the compiling process's PATH, which exec basenames are found on first.
	PATH string
	// ExecDirs are the directories, ":"-joined, of the programs the run exec'd: the PATH the run found them on, which
	// a service-started dashboard's own PATH lacks (F17). They are added only when PATH alone does not compile. Empty,
	// they are read from RunDir's ledger then, and only then.
	ExecDirs string
	// RunDir is the run directory ExecDirs is read from when empty; "" reads none.
	RunDir string
	// Home is the invoking user's home ("" leaves the compiler's default).
	Home string
	// Anchor is the chain anchor file the compile refuses the agent ("" for none known).
	Anchor string
	// RuntimeDirs are the bases under which the invoking user's runs keep their private directories (R10a): both
	// write paths pass config.RuntimeDirBases, the list the launcher checks.
	RuntimeDirs []string
	// Exe is the running tego binary, which R10 keeps out of every write entry with what PATH finds
	// (agent.WithOwnBinaries); "" where it cannot be named, as in tego-control, which runs from a sealed copy.
	Exe string
}

// Compile loads text as the contract at cc.Contract through the machine's profile sources and compiles it in cc,
// first on cc.PATH and, when that fails, on cc.PATH plus the run's exec directories. The error's text is the compile's
// error diagnostics, as tego compile prints them.
func Compile(ctx context.Context, m *config.Machine, cc Context, text []byte) (*agent.RuleTable, error) {
	if m == nil {
		return nil, errors.New("no machine config to compile against")
	}
	c, ds, err := agent.LoadBytes(cc.Contract, text, profilesrc.Chain(m))
	if err != nil {
		return nil, DiagError(ds, err)
	}
	// Offline: a host name is resolved at run start (E18), as `tego compile --offline` defers it. Neither write path
	// does DNS on a check, so a box without a resolver can still change a contract that names hosts, and both give a
	// mistyped host the same verdict: it fails the next run's start.
	opts := []agent.CompileOption{agent.WithContext(ctx), agent.WithClock(time.Now), agent.Offline(), agent.WithOwnBinaries(cc.Exe)}
	if len(cc.RuntimeDirs) > 0 {
		opts = append(opts, agent.WithRuntimeDir(cc.RuntimeDirs...))
	}
	cwd := cc.Cwd
	if cwd == "" {
		cwd = filepath.Dir(cc.Contract)
	}
	opts = append(opts, agent.WithCwd(cwd))
	if cc.Home != "" {
		opts = append(opts, agent.WithHome(cc.Home))
	}
	if cc.Anchor != "" {
		opts = append(opts, agent.WithChainAnchor(cc.Anchor))
	}
	if cc.RunCommandGrant != "" {
		opts = append(opts, agent.WithRunCommand(cc.RunCommandGrant))
	}
	if t := runTier(cc.Tier, c.Tier); t != "" {
		opts = append(opts, agent.WithTiers(t))
	} else if len(cc.Tiers) > 0 {
		opts = append(opts, agent.WithTiers(cc.Tiers...))
	}
	rt, ds, err := agent.Compile(c, m, append(opts, agent.WithPATH(cc.PATH))...)
	if err != nil {
		more := cc.ExecDirs
		if more == "" && cc.RunDir != "" {
			more = ExecDirs(cc.RunDir, cc.PATH)
		}
		if more != "" {
			rt, ds, err = agent.Compile(c, m, append(opts, agent.WithPATH(joinPath(cc.PATH, more)))...)
		}
	}
	if err != nil {
		return nil, DiagError(ds, err)
	}
	return rt, nil
}

// runTier is the run's tier when the text keeps the tier the run got: auto (no pin) or a pin of that same tier. A text
// that pins another tier (only a free edit does) is compiled as tego would compile it, not as if this machine built
// only the run's tier, so the preview's table and Reach are the next run's.
func runTier(run string, pin agent.TierPin) backend.Tier {
	t, err := backend.ParseTier(run)
	if err != nil {
		return ""
	}
	if p := backend.Tier(pin); p != "" && p != backend.TierAuto && p != t {
		return ""
	}
	return t
}

func joinPath(a, b string) string {
	if a == "" {
		return b
	}
	return a + ":" + b
}

// ExecDirs is the directories (not already on path) of the programs the run in the run directory dir exec'd,
// ":"-joined: where the run's own PATH found them. It reads at most the first 5000 exec lines.
func ExecDirs(dir, path string) string {
	const maxExecScan = 5000
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return ""
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	seen := map[string]bool{}
	for _, d := range strings.Split(path, ":") {
		seen[d] = true
	}
	var out []string
	n := 0
	for e, err := range r.Iter() {
		if err != nil || n >= maxExecScan {
			break
		}
		if e.Kind != record.KindExec {
			continue
		}
		n++
		var p record.ExecPayload
		if e.DecodePayload(&p) != nil || !filepath.IsAbs(p.Path) {
			continue
		}
		if d := filepath.Dir(p.Path); !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return strings.Join(out, ":")
}

// DiagError is err with the compile's error diagnostics as its text, as tego compile prints them.
func DiagError(ds []agent.Diagnostic, err error) error {
	var errs []agent.Diagnostic
	for _, d := range ds {
		if d.IsError() {
			errs = append(errs, d)
		}
	}
	if len(errs) == 0 {
		return err
	}
	var b bytes.Buffer
	_ = agent.WriteDiagnostics(&b, errs) // a bytes.Buffer write does not fail
	return errors.New(strings.TrimSpace(b.String()))
}
