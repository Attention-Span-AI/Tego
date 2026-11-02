// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"

	"github.com/attention-span-ai/tego/internal/nextrun"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// CheckContext is what a contract is compiled for: the run it will next govern, as the newest run of it recorded.
// A write is refused when the compiler refuses the new text in this context, so
// it must be the context tego compiles in, or the dashboard refuses what tego runs (F2, F3, F17) or writes what tego
// then refuses.
type CheckContext struct {
	// Contract is the contract file's absolute path: where relative profile and fs entries are placed from.
	Contract string
	// Cwd is the run's working directory (run_start.cwd), which relative entries are read from.
	Cwd string
	// Tier is the tier the run ran at (run_start.tier): an auto contract resolves to it, not to this machine's
	// highest tier, which the dashboard cannot know (it links no backend) and the run did not get (F3).
	Tier string
	// RunCommandGrant is the exec rule tego run's command line added for the run (run_start.run_command_grant).
	RunCommandGrant string
	// ExecDirs are the directories, ":"-joined, of the programs the run exec'd: the PATH the run found them on,
	// which a service-started dashboard's own PATH lacks (F17). They are added only when the dashboard's PATH
	// alone does not compile. Empty, they are read from the run's ledger then, and only then.
	ExecDirs string
	// runDir is the run directory ExecDirs is read from when empty.
	runDir string
}

// errNoCompiler is every write's refusal when the dashboard has no machine config to compile against.
var errNoCompiler = errors.New("this dashboard was started without the machine config, so it cannot compile a contract and writes none")

// check is the compiler a change is planned with: nil when text compiles in cc.
func (s *Service) check(ctx context.Context, cc CheckContext) func([]byte) error {
	return func(text []byte) error {
		_, err := s.compile(ctx, cc, text)
		return err
	}
}

// relaxes is rule.EditRequest.Relaxes: the compiled count of built-in deny_read entries the text's fs.ask_read
// entries relax, which sees through a symlink the lexical model cannot.
func (s *Service) relaxes(ctx context.Context, cc CheckContext) func([]byte) (int, error) {
	return func(text []byte) (int, error) {
		rt, err := s.compile(ctx, cc, text)
		if err != nil {
			return 0, err
		}
		if rt == nil {
			return 0, nil
		}
		return len(rt.AskReadRelaxes), nil
	}
}

// compile compiles text as tego compiles the next run of the contract (internal/nextrun, the compile `tego rule` calls
// too): the run's tier, its run command grant, the invoking user's home, chain anchor and runtime directories, the
// dashboard's PATH and, when that fails, the run's exec directories as well. A test replaces the whole step with
// Service.Compile. The table is nil when Service.Compile answered.
func (s *Service) compile(ctx context.Context, cc CheckContext, text []byte) (*agent.RuleTable, error) {
	if s.Compile != nil {
		return nil, s.Compile(ctx, cc, text)
	}
	if s.Check != nil {
		return nil, s.Check(cc.Contract, cc.Cwd, text)
	}
	if s.Machine == nil {
		return nil, errNoCompiler
	}
	return nextrun.Compile(ctx, s.Machine, s.nextrunContext(cc), text)
}

// nextrunContext is cc as nextrun.Compile takes it, with what the dashboard knows of the machine filled in. Tiers stays
// empty: tego-control links no backend, so an auto contract whose run tier is unknown resolves to the machine ceiling.
// The runtime directories are config.RuntimeDirBases, the list `tego rule` compiles with and the launcher checks
// (agent-contract.md R10a), not a copy of it: tego-control may not link internal/runtime.
func (s *Service) nextrunContext(cc CheckContext) nextrun.Context {
	return nextrun.Context{Contract: cc.Contract, Cwd: cc.Cwd, Tier: cc.Tier, RunCommandGrant: cc.RunCommandGrant,
		PATH: s.path(), ExecDirs: cc.ExecDirs, RunDir: cc.runDir, Home: s.Machine.Home, Anchor: s.Anchor,
		RuntimeDirs: config.RuntimeDirBases()}
}
