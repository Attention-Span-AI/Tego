// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/learn"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdLearn) }

// cmdLearn is `tego learn <run> [--out <file>] [--workspace <dir>]` (C9, E65): read a finished run's ledger, an
// observe-only run of `tego watch` for instance, and print, or with --out write, a boundary contract PROPOSED from
// what the run did: the directories it wrote under the workspace, the programs it started, the addresses it
// connected to. It proposes, a person reviews and the contract is theirs: a dangerous endpoint (a D-Bus bus, an
// agent socket, the container daemon) is only reported, never allowed, and fs.deny_read is never touched. Like
// events and measure it reads the record alone and never takes the run's lock, so a run still going can be learned
// from, and its proposal is the run so far.
func cmdLearn() Command {
	var (
		out       string
		workspace string
	)
	return Command{
		Name:    "learn",
		Summary: "propose a contract from what a finished run did",
		Usage:   "<run> [--out <file>] [--workspace <dir>]",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&out, "out", "", "write the proposal to this new file (mode 0600, never replacing one) instead of printing it")
			fs.StringVar(&workspace, "workspace", "", "the directory writes may be allowed under (default: the run's working directory)")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 1 {
				message(stderr, "", 0, 0, "tego learn: exactly one run id or run directory", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			ws := workspace
			if ws != "" {
				abs, err := filepath.Abs(ws)
				if err != nil {
					message(stderr, "", 0, 0, "tego learn: --workspace: "+err.Error(), codeUsage)
					return identity.ExitUsage // R25: usage error
				}
				// The ledger names paths the kernel's way, every link resolved, so the workspace is compared in that
				// form. One that does not resolve here (a run read on another machine) is kept as given.
				if real, err := filepath.EvalSymlinks(abs); err == nil {
					abs = real
				}
				if ws = abs; ws == "/" {
					message(stderr, "", 0, 0, "tego learn: --workspace / is every directory: name the directory the agent works in", codeUsage)
					return identity.ExitUsage // R25: usage error
				}
			}
			return runLearn(ctx, fs.Arg(0), ws, out, stdout, stderr)
		},
	}
}

// runLearn resolves the run, reads its record without the lock and renders one proposal.
func runLearn(ctx context.Context, ref, workspace, out string, stdout, stderr io.Writer) int {
	mc := &machineOnce{stderr: stderr}
	dir, err := resolveRunDir("learn", ref, true, mc)
	if err != nil {
		return runRefFailed(stderr, "learn", err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			message(stderr, "", 0, 0, fmt.Sprintf("tego learn: no run record at %s", dir), codeIO)
			return identity.ExitError
		}
		message(stderr, "", 0, 0, "tego learn: "+err.Error(), codeIO)
		return identity.ExitError
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	defer func() { warnNewer(stderr, "learn", dir, r.SkippedNewer()) }()
	if err := needRunRecord(r, dir); err != nil {
		message(stderr, "", 0, 0, "tego learn: "+err.Error(), readCode(err))
		return identity.ExitError
	}

	l := learn.New(learn.Options{Workspace: workspace, StateDirs: learnStateDirs(r.Dir(), mc)})
	for e, err := range r.Iter() {
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			err = l.Add(e)
		}
		if err != nil {
			return readFailed(stderr, "learn", err) // a corrupt ledger is tego's own error, not a finding
		}
	}
	p, err := l.Proposal()
	if err != nil {
		message(stderr, "", 0, 0, "tego learn: "+err.Error(), codeUsage)
		return identity.ExitUsage // R25: usage error: the workspace the run or the flag names cannot be used
	}
	text := p.Contract()
	if out == "" {
		if _, err := io.WriteString(stdout, text); err != nil {
			message(stderr, "", 0, 0, "tego learn: "+err.Error(), codeIO)
			return identity.ExitError
		}
	} else if code := writeProposal(out, text, p, stderr); code != identity.ExitOK {
		return code
	}
	for _, w := range p.Warnings() {
		fmt.Fprintf(stderr, "tego learn: warning: %s\n", w)
	}
	if n := len(p.Left); n > 0 {
		fmt.Fprintf(stderr, "tego learn: %d kinds of action the run took are left out of the proposal; its header and its \"observed, not allowed\" comments say which and why\n", n)
	}
	return identity.ExitOK
}

// learnStateDirs are tego's own directories for run dir: the run's record, the ledger root it lies in, the chain
// anchor's directory (~/.tego) and the host state directory, each as written and with its symlinks followed. A
// proposal never writes any of them, since tego refuses a contract that lets the agent.
func learnStateDirs(runDir string, mc *machineOnce) []string {
	dirs := []string{runDir, "/run/tego"}
	if m, err := mc.load(); err == nil && m != nil {
		if root, err := ledgerRootOf(m); err == nil {
			dirs = append(dirs, root)
		}
		if a, err := anchorPath(m); err == nil {
			dirs = append(dirs, filepath.Dir(a))
		}
	}
	for _, d := range slices.Clone(dirs) {
		if real, err := filepath.EvalSymlinks(d); err == nil && real != d {
			dirs = append(dirs, real)
		}
	}
	return dirs
}

// writeProposal creates the new file out with the proposal, mode 0600. An existing file, a link included, is
// refused and left as it is: the proposal is something to review beside the contract in use, never over it.
func writeProposal(out, text string, p *learn.Proposal, stderr io.Writer) int {
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		code := codeIO
		exit := identity.ExitError
		if errors.Is(err, fs.ErrExist) {
			code, exit = codeExists, identity.ExitFinding // R25: a finding, as init's refusal of a foreign file is
		}
		message(stderr, out, 0, 0, "tego learn: "+err.Error()+": nothing was written; give --out a new file", code)
		return exit
	}
	_, err = io.WriteString(f, text)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(out)
		message(stderr, out, 0, 0, "tego learn: write: "+err.Error(), codeIO)
		return identity.ExitError
	}
	if abs, err := filepath.Abs(out); err == nil {
		warnWritable(stderr, abs, p)
	}
	fmt.Fprintf(stderr, "tego learn: wrote %s (mode 0600): a proposal for you to review; check it with tego compile %s\n", out, out)
	return identity.ExitOK
}

// warnWritable says so when the file just written lies inside one of its own fs.write entries: tego refuses to run
// a contract the agent could rewrite, so the proposal has to be kept elsewhere.
func warnWritable(stderr io.Writer, abs string, p *learn.Proposal) {
	dir := filepath.Dir(abs)
	for _, w := range p.WriteDirs() {
		if w = strings.TrimSuffix(w, "/"); w != "" && (dir == w || strings.HasPrefix(dir, w+"/")) {
			message(stderr, abs, 0, 0, fmt.Sprintf("tego learn: this file lies inside its own fs.write entry %q, which tego refuses to run: keep the contract outside the workspace", w), agent.CodeContradiction)
			return
		}
	}
}
