// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/learn"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The rules that choose the next step (Next.Rule), checked in this order; the first that applies gives it. No score
// and no model. A person may run any command at any time: the rules only say which one comes next.
const (
	// RuleCheckNotKnown: the check step is not known (check.json could not be read and no check was made now).
	RuleCheckNotKnown = "check-not-known"
	// RuleCheckTodo: no check of this boot and this build.
	RuleCheckTodo = "check-todo"
	// RuleCheckOutside: no place checked can enforce, and the check that decided it was made from a shell that starts
	// no run only because it is outside the user manager's cgroup (Check.Cause): open a shell inside it.
	RuleCheckOutside = "check-outside"
	// RuleCheckNoManager: no place checked can enforce, and the check that decided it found no user manager running for
	// the user (Check.Cause CauseNoUserManager): an administrator starts one that runs without a login (Inputs.Linger).
	RuleCheckNoManager = "check-no-manager"
	// RuleCheckNoManagerName: as RuleCheckNoManager, but systemd refuses the user's name (Inputs.ManagerRefused), so it
	// starts no user manager for it, linger or not: the step says so and names no command (acceptance 3, 2026-11-11:
	// the user 4242 on Ubuntu 24.04, where the linger command came back after it ran).
	RuleCheckNoManagerName = "check-no-manager-name"
	// RuleCheckBlocked: no place checked can enforce, for another cause; tego doctor names the fix.
	RuleCheckBlocked = "check-blocked"
	// RuleRecordUnreadable: the record under the ledger root, or a registry, could not be read, or the recorded run
	// could not be checked.
	RuleRecordUnreadable = "record-unreadable"
	// RuleEnforceUnverified: the newest ended run under a contract does not check out.
	RuleEnforceUnverified = "enforce-unverified"
	// RuleEnforceDone: a run under a contract ended and checks out; every step is done.
	RuleEnforceDone = "enforce-done"
	// RuleEnforceWaiting: a run under a contract is still going and none has ended.
	RuleEnforceWaiting = "enforce-waiting"
	// RuleContractDone: a contract compiles and no run under one has ended.
	RuleContractDone = "contract-done"
	// RuleContractBlocked: the registries hold contracts and none compiles.
	RuleContractBlocked = "contract-blocked"
	// RuleRecordUnverified: the newest ended recorded run's record does not check out, and no contract compiles yet.
	RuleRecordUnverified = "record-unverified"
	// RuleRecordDone: a recorded run ended, its record checks out, and no contract compiles yet.
	RuleRecordDone = "record-done"
	// RuleRecordWaiting: a recording is still going.
	RuleRecordWaiting = "record-waiting"
	// RuleRecordTodo: nothing is recorded yet.
	RuleRecordTodo = "record-todo"
	// RuleHereOutside: the next step starts a run (StartsRun), the invoker's own place starts none, and a shell in the
	// user manager's cgroup would (its check is ready, or the invoker's place fails only for being outside it): open
	// that shell first, never the command that exits 125 from here. It stands in for record-todo and contract-done.
	RuleHereOutside = "here-outside"
	// RuleHereRootOnly: the next step starts a run, the invoker's own place starts none for another cause, and only
	// root's check is ready, which holds a run started with sudo and none started as the person: see why here cannot.
	RuleHereRootOnly = "here-root-only"
	// RuleHereElsewhere: the next step starts a run, the invoker's own place starts none for another cause, and the
	// check that is ready is another place's that is neither the user manager's nor root's: see why not here.
	RuleHereElsewhere = "here-elsewhere"
)

// RunCommands are the tego commands that start a run, which tier 1 places in the user manager's cgroup: each refuses
// from a shell outside it with exit 125 (cgroup.ErrBesideSubtree from FS.CanPlace, or tier landlock missing doctor's
// D3, which asks the same; tego test through the runs it starts). StartsRun reads a next step's command with them.
var RunCommands = []string{"run", "watch", "test"}

// StartsRun reports whether command, a next step's command line, starts a run: tego and one of RunCommands, after an
// optional "cd <folder> && ". A command written to run as root (sudo) is not one: a root run is placed anywhere.
func StartsRun(command string) bool {
	if strings.HasPrefix(command, "cd ") {
		if i := strings.LastIndex(command, " && "); i >= 0 {
			command = command[i+len(" && "):]
		}
	}
	f := strings.Fields(command)
	return len(f) >= 2 && f[0] == "tego" && slices.Contains(RunCommands, f[1])
}

// NoManagerText is the sentence of the step that starts the user's manager without a login (RuleCheckNoManager), and
// of tego doctor's next: line in the same case. It fits 80 columns after "next: ".
const NoManagerText = "no user manager runs for you; with sudo, start one that needs no login:"

// NoManagerNameText is the sentence of RuleCheckNoManagerName's step, which names no command (tego doctor's next: line
// in the same case points at its own fix: line instead). It fits 80 columns after "next: ".
const NoManagerNameText = "systemd runs no user manager for this account's name; see step 2."

// scopeText is the sentence of the step that opens a shell in the user manager's cgroup: tego setup there names the
// next command from a place that can run it. It fits 80 columns after "next: ".
const scopeText = "open a shell in your user manager's cgroup, then run tego setup there:"

// ScopeAsText is scopeText for a person who started tego setup as another user through sudo or su (As.ScopeAs): the
// command, typed in that person's own shell, opens a shell as the user tego ran as, in that user's manager (step 2's
// fact names the user). It fits 80 columns after "next: ".
const ScopeAsText = "from your own shell, open a shell as this user; run tego setup in it:"

// The parts of a command only the person knows (written in angle brackets, as the next: lines write them; ADR 0142 (3)).
const (
	startPlaceholder = "<the command you start it with>"
	namePlaceholder  = "<name>"
)

// next is the first rule that applies.
func (f *facts) next() Next {
	st := func(id string) string { return f.steps[id].State }
	switch {
	case st(StepCheck) == NotKnown:
		return Next{Step: StepCheck, Rule: RuleCheckNotKnown, Text: "check this machine again; it stores a new check:",
			Command: "tego setup"}
	case st(StepCheck) == Todo:
		return Next{Step: StepCheck, Rule: RuleCheckTodo, Text: "check this machine:", Command: "tego setup"}
	case st(StepCheck) == Blocked && f.blocked != nil && f.blocked.Cause == CauseOutsideUserManager:
		return f.openScope(StepCheck, RuleCheckOutside)
	case st(StepCheck) == Blocked && f.blocked != nil && f.blocked.Cause == CauseNoUserManager:
		if f.in.ManagerRefused != "" {
			return Next{Step: StepCheck, Rule: RuleCheckNoManagerName, Text: NoManagerNameText}
		}
		if f.in.Linger != "" {
			return Next{Step: StepCheck, Rule: RuleCheckNoManager, Text: NoManagerText, Command: f.in.Linger, NeedsRoot: true}
		}
		return Next{Step: StepCheck, Rule: RuleCheckNoManager,
			Text: "no user manager runs for you; tego doctor names how to start one:", Command: "tego doctor"}
	case st(StepCheck) == Blocked:
		return Next{Step: StepCheck, Rule: RuleCheckBlocked,
			Text: "no place checked can enforce; tego doctor names the one fix:", Command: "tego doctor"}
	case st(StepFind) == NotKnown || st(StepRecord) == NotKnown || st(StepContract) == NotKnown:
		return Next{Rule: RuleRecordUnreadable, Text: "Tego could not read its record or a registry; see the not known lines."}
	case st(StepEnforce) == Blocked:
		run := f.steps[StepEnforce].Run
		return Next{Step: StepEnforce, Rule: RuleEnforceUnverified, Text: "a run's record does not check out; see where it breaks:",
			Command: "tego events " + f.runs.short(run) + " --verify"}
	case st(StepEnforce) == Done:
		return Next{Rule: RuleEnforceDone, Text: "every step is done; see what the last enforced run did:",
			Command: "tego receipt " + f.runs.short(f.steps[StepEnforce].Run)}
	case st(StepEnforce) == Waiting:
		return Next{Step: StepEnforce, Rule: RuleEnforceWaiting, Text: "a run under a contract is still going; follow it:",
			Command: "tego status " + f.runs.short(f.steps[StepEnforce].Run)}
	case st(StepContract) == Done:
		return f.fromHere(f.runUnder())
	case st(StepContract) == Blocked:
		arg, placeholder := contractArg(f.contracts.all[0])
		return Next{Step: StepContract, Rule: RuleContractBlocked, Text: "fix what the compile says, then check it again:",
			Command: "tego compile " + arg, Placeholder: placeholder}
	case st(StepRecord) == Blocked:
		return Next{Step: StepRecord, Rule: RuleRecordUnverified, Text: "a recorded run's record does not check out; see where:",
			Command: "tego events " + f.runs.short(f.steps[StepRecord].Run) + " --verify"}
	case st(StepRecord) == Done:
		return f.learnFrom()
	case st(StepRecord) == Waiting:
		return Next{Step: StepRecord, Rule: RuleRecordWaiting,
			Text:    "a recording is still going; let it do a normal job, then stop it. See it:",
			Command: "tego status " + f.runs.short(f.steps[StepRecord].Run)}
	}
	return f.fromHere(Next{Step: StepRecord, Rule: RuleRecordTodo,
		Text: "record your own agent. From its folder, start it as you always do:", Command: "tego watch -- " + startPlaceholder,
		Placeholder: true})
}

// openScope is the step that opens a shell in the user manager's cgroup (OpenScope's command, as the invoker's As
// carries it, else DefaultScope), with tego setup to run in it; where no command opens one from the invoker's shell
// (As.ScopeMissing), the sentence alone, and the check step's fact says why. Its command never starts a run.
func (f *facts) openScope(step, rule string) Next {
	n := Next{Step: step, Rule: rule, Text: scopeText, Command: DefaultScope}
	if as := f.in.As; as != nil && as.Scope != "" {
		n.Command = as.Scope
		if as.ScopeAs != "" {
			n.Text = ScopeAsText
		}
	} else if as != nil && as.ScopeMissing != "" && as.Where == WhereShell {
		n.Text, n.Command = "systemd-run cannot open a shell in your user manager's cgroup here.", ""
	}
	return n
}

// fromHere is n, the step after a ready check, as the invoker's place can take it: when n starts a run (StartsRun) and
// the invoker's own check says no tier runs from it, the run would only exit 125 there (acceptance B, 2026-11-11). Then
// the step opens a shell in the user manager's cgroup when that place's check is ready or the invoker's place fails
// only for being outside it; else, when only root's check is ready, it says that check holds a run started with sudo,
// never one started as the person (F9), and names tego doctor, which says why this shell cannot; and when the ready
// check is another place's, it says so, naming no place step 2 does not, and names tego doctor too.
func (f *facts) fromHere(n Next) Next {
	if !f.hereCannot || f.ready == nil || !StartsRun(n.Command) {
		return n
	}
	if f.ready.Where == WhereUserManager || (f.here != nil && f.here.Cause == CauseOutsideUserManager) {
		return f.openScope(n.Step, RuleHereOutside)
	}
	if f.ready.Where == WhereRoot {
		return Next{Step: n.Step, Rule: RuleHereRootOnly, Text: "only root's check is ready, for runs started with sudo; see why not here:",
			Command: "tego doctor"}
	}
	// Another place's check (step 2 names it): the words never name root when no root check exists (the review's S3).
	return Next{Step: n.Step, Rule: RuleHereElsewhere, Text: "only another place's check is ready (step 2); see why not here:",
		Command: "tego doctor"}
}

// runUnder is the step after a contract that compiles: run the agent under it, from the folder of the recorded run
// the contract is named after when that link holds (the newest observe run whose folder's base name is the contract's
// name, the name learn's next: line proposes, has ended and its record checks out against the chain anchor), else
// from the agent's own folder. From a shell whose own check found no tier, while another place's check is ready, fromHere
// puts the step that opens a shell where it runs in its place, since tego run from here would only fail.
func (f *facts) runUnder() Next {
	c, _ := f.preferred()
	arg, placeholder := contractArg(c)
	n := Next{Step: StepEnforce, Rule: RuleContractDone, Text: "from your agent's folder, run it under its contract:",
		Command: "tego run " + arg, Placeholder: placeholder}
	if r := f.runs.newest(func(r *run) bool { return r.observe() && filepath.Base(r.start.Cwd) == c.name }); r != nil &&
		r.state == ledger.StateEnded && f.verify(r).v == ledger.Verified {
		if dir, ok := folderWord(r.start.Cwd); ok && folderHere(r.start.Cwd) {
			n.Text, n.Command = "run your agent under its contract:", "cd "+dir+" && "+n.Command
			f.steps[StepContract].Link += "; the next step runs it from the folder of run " + f.runs.short(r.id) +
				", whose base name is the agent's name and whose record checks out"
		}
	}
	return n
}

// learnFrom is the step after a recorded run whose record checks out (the record step's run): make a contract of it,
// named after its folder when that name is free.
func (f *facts) learnFrom() Next {
	id := f.steps[StepRecord].Run
	r := f.runs.newest(func(r *run) bool { return r.id == id })
	name := f.freeName(r.start.Cwd)
	n := Next{Step: StepContract, Rule: RuleRecordDone, Text: "make a contract from what it did, and read it before you use it:",
		Command: "tego learn " + f.runs.short(r.id) + " --save " + name, Placeholder: name == namePlaceholder}
	ctx, cancel := context.WithTimeout(f.ctx, suggestBudget)
	defer cancel()
	if SuggestHosts(ctx, r.dir) {
		// tego watch's next: line decides the same way (acceptance B, 2026-11-11).
		n.Text, n.Command, n.Placeholder = learnNameText, n.Command+" --allow-host "+hostPlaceholder, true
	}
	return n
}

// learnNameText is the sentence of the learn step that names --allow-host, tego watch's own.
const learnNameText = "make a contract from what it did, with the host name of its addresses:"

// suggestBudget bounds the learn step's read of the recorded run (SuggestHosts), which the dashboard's Overview makes
// on each load: tego watch bounds the same read by its summary budget, 5 s. Past it the step is the plain form, which
// learn accepts for any run it can read and which names no host (the review's S4). A variable so a test can run out.
var suggestBudget = 5 * time.Second

// hostPlaceholder is the host name only the person knows: the record holds addresses, never the name looked up.
const hostPlaceholder = "<host>"

// SuggestHosts reports whether the learn step for the run recorded in dir names --allow-host <host>: learn's proposal
// from its record (learn.Proposal.SuggestHosts) still allows addresses by address, and the leak rule found no
// destination the run's secrets may have gone to, so a host the person names is never one learn withheld. tego watch
// and tego learn ask the same of the same record, so the three next: lines agree. A record it cannot read reports
// false: the plain form, which learn accepts for any run it can read.
func SuggestHosts(ctx context.Context, dir string) bool {
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return false
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	l := learn.New(learn.Options{})
	for e, err := range r.Iter() {
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			err = l.Add(e)
		}
		if err != nil {
			return false
		}
	}
	p, err := l.Proposal()
	return err == nil && p.SuggestHosts()
}

// freeName is the name a next step proposes to save a contract of a run that worked in dir under: the folder's base
// name when learn --save takes it (an agent name that does not start with "-") and the registries resolve it to
// nothing from the guide's folder and from dir; else namePlaceholder.
func (f *facts) freeName(dir string) string {
	name := filepath.Base(dir)
	if dir == "" || !registry.IsName(name) || strings.HasPrefix(name, "-") || f.contracts == nil {
		return namePlaceholder
	}
	p := f.contracts.places
	for _, d := range []string{p.Dir, dir} {
		p.Dir = d
		if _, err := p.Resolve(name); !notFound(err) {
			return namePlaceholder
		}
	}
	return name
}

// notFound reports whether err is a registry's answer that it holds no agent of the name.
func notFound(err error) bool {
	var re *registry.Error
	return errors.As(err, &re) && re.Code == registry.CodeNotFound
}

// contractArg is how a next step names contract c: its name, which tego run, tego compile and the dashboard resolve
// in the registries; its file's path when the name starts with "-", which a command would read as a flag; or
// namePlaceholder when that path does not print as itself.
func contractArg(c *contract) (string, bool) {
	if !strings.HasPrefix(c.name, "-") {
		return c.name, false
	}
	if w, ok := folderWord(c.path); ok {
		return w, false
	}
	return namePlaceholder, true
}

// folderWord is dir as one word of a command line (shellword.Quote), and false when it is not an absolute path or
// holds a character that does not print as itself: a next step never names a folder a person could misread.
func folderWord(dir string) (string, bool) {
	if !filepath.IsAbs(dir) || !plain(dir) {
		return "", false
	}
	return shellword.Quote(dir), true
}

// folderHere reports whether dir is a folder on this machine now: a next step never sends a person to one that is
// gone, or to the folder of a record made elsewhere.
func folderHere(dir string) bool {
	fi, err := os.Stat(dir)
	return err == nil && fi.IsDir()
}

// tierWords is a tier as a newcomer reads it beside its key (doctor.TierWords' words).
func tierWords(t string) string {
	switch backend.Tier(t) {
	case backend.TierLandlock:
		return "tier 1 (landlock)"
	case backend.TierCgroup:
		return "tier 2 (cgroup)"
	case backend.TierBPFLSM:
		return "tier 3 (bpflsm)"
	case backend.TierObserve, backend.TierAuto:
	}
	return "tier " + tierKey(t)
}

// tierKey is a recorded tier, printable.
func tierKey(t string) string { return record.Printable(t) }

// pathWords is a recorded path, printable.
func pathWords(p string) string { return record.Printable(p) }

// joinAnd joins sentences with "and".
func joinAnd(s []string) string { return strings.Join(s, " and ") }

// registrySource is where the contract step looked: the user registry's agents folder and the project folder.
func registrySource(p registry.Places) string {
	var at []string
	if p.User != "" {
		at = append(at, filepath.Join(p.User, registry.AgentsDir))
	}
	if p.Dir != "" {
		at = append(at, p.Dir)
	}
	if len(at) == 0 {
		return "no registry"
	}
	return strings.Join(at, " and ")
}
