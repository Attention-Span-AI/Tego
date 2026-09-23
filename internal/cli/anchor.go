// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"strings"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// anchorPath resolves the chain anchor every command that writes or checks one uses: the invoking
// user's ~/.tego/chain.log, or beside the ledger root for an account with no home
// (tegoruntime.AnchorPath). It is a variable so this package's tests can point it into their own
// temporary directory, and so can a binary built with the tegotesthooks tag (anchor_testhook.go),
// for the tests that drive tego as a subprocess. Nothing in a product build reassigns it, and no
// environment variable can: the capability-bearing launcher must not let one choose where it
// appends (identity-config.md R21).
var anchorPath = tegoruntime.AnchorPath

// executable is os.Executable, a variable so a test can name the binary R10 protects.
var executable = os.Executable

// runningBinary is the running tego's file, "" when it cannot be named or is a package's test binary: go test's runs
// are this package's own contracts against a binary in the build's temporary directory, which is nothing a later run
// starts.
func runningBinary() string {
	exe, err := executable()
	if err != nil || strings.HasSuffix(exe, ".test") {
		return ""
	}
	return exe
}

// anchorCompileOptions names the run's chain anchor to the compiler, which R10 keeps out of every
// write entry (agent-contract.md R10). An anchor that cannot be resolved names nothing: `run` refuses
// that case on its own, and the compiler then guards ~/.tego/chain.log under its home, which is
// where the anchor of every account with a home is.
//
// It names the invoking user's runtime directories too, under which every run keeps its private directory
// (agent.WithRuntimeDir, agent-contract.md R10a): an entry over tego's runtime parent, or inside another run's
// directory, is refused. They are the launcher's (tegoruntime.RuntimeDirBases): the user's logind directory,
// /run/user/<uid>, whatever the environment says, so plain sudo, cron or an ssh session without the variable still
// protects where the same user's other runs keep theirs, and $XDG_RUNTIME_DIR when it names another. Each can only
// add refusals, never remove one, so an environment that names another directory weakens nothing the run relies on.
//
// It names the running binary as well, which R10 keeps out of every write entry with what the PATH finds
// (agent.WithOwnBinaries). A binary that cannot name itself leaves the PATH, and `tego run` is then no less confined.
func anchorCompileOptions(m *config.Machine) []agent.CompileOption {
	opts := []agent.CompileOption{agent.WithRuntimeDir(tegoruntime.RuntimeDirBases()...), agent.WithOwnBinaries(runningBinary())}
	p, err := anchorPath(m)
	if err != nil {
		return opts
	}
	return append(opts, agent.WithChainAnchor(p))
}

// sweepOptions are the options every orphan sweep a command runs shares: the same chain anchor a
// launcher uses, so a run ended by `run`, `stop` or `gc` is anchored where one that ended normally
// would have been — for a run another account owns on a shared ledger root, that account's anchor
// (tegoruntime.WithSweepAnchor). A home that cannot be resolved leaves the ledger's default in place
// and is logged: a sweep never fails the command that runs it (R20), and the run it ends is still
// recorded.
func sweepOptions(m *config.Machine, opts ...tegoruntime.SweepOption) []tegoruntime.SweepOption {
	p, err := anchorPath(m)
	if err != nil {
		logOwn("sweep: chain anchor: " + err.Error())
		return opts
	}
	return append(opts, tegoruntime.WithSweepAnchor(p))
}
