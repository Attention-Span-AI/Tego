// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/internal/check/inforce"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/profilesrc"
	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/internal/setup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

// "Set up a new agent" (rules design RD-SETUP-NEW): the dashboard composes a new contract from the presets
// (internal/setup, the code `tego init --preset` writes through) or from a finished run's least-privilege proposal
// (`tego learn`), compiles it as `tego compile --offline` would in the project folder, and writes <dir>/agent.yaml
// with rulefile.Create: never over a file, through the same guards and journal a change goes through. The project
// folder is the one value a request names as a path, so it is checked before anything reads under it: an existing
// directory, this user's, not writable by others unless sticky, and not under the ledger root or tego's home. The
// folders the contract needs are made beneath the checked folder opened with no symlink followed (setup.Create), so a
// link swapped into its path after the check is refused, never followed out of it. The new contract joins the
// bounded set Contracts lists (its journal line names it), so the Rules page offers it and a later change can edit it
// before any run of it.
//
// A draft from a run may instead be saved as the user registry's entry <name> (NewReq.Registry): registry.Save writes
// it, the writer `tego learn --save` writes through, with the same refusals (a name taken from the run's folder, a
// file inside the draft's own write entries, a draft that does not compile, a file already there) and the same 0700
// folder and 0600 file. That entry is in no change record: the Rules page lists it from its first run.

// NewFile is the file "Set up a new agent" writes in the project folder: what `tego init` writes and `tego run`
// finds.
const NewFile = setup.ContractFile

// NewReq is the "Set up a new agent" form.
type NewReq struct {
	// Dir is the project folder as typed: an absolute path, or ~/ for the invoking user's home.
	Dir string
	// Name is the agent id ([a-z0-9-]{1,40}); empty, it is made from the folder's name.
	Name string
	// Presets, Writes, Hosts and Command are setup.Options': the presets the contract extends (no-secrets, no-prod,
	// repo-only-writes), the folders it may write besides those the project's markers imply, the hosts it may reach
	// (host, host:port or @group), and the agent's command line (empty writes a short demo command).
	Presets []string
	Writes  []string
	Hosts   []string
	Command string
	// Pass are the variables the agent needs (env.pass) and AskRead the paths a person decides each read of
	// (fs.ask_read); the agent's own needs are added for a claude or codex command (setup.Options.AgentNeeds).
	Pass, AskRead []string
	// FromRun, when set, makes the draft that run's least-privilege proposal (rulesview.Learn) in place of the
	// presets, with Name as its name: what the run did, and no more.
	FromRun string
	// Registry saves a FromRun draft as the user registry's entry Name (<registry>/agents/<Name>.yaml) through
	// registry.Save, the writer `tego learn --save` writes through, in place of Dir/agent.yaml: `tego run <Name>`
	// typed in Dir, and the tego-agent@<Name> unit, find it there. Dir is then the folder the agent runs in.
	Registry bool
	// Reads makes the draft record each read it refuses, at tier landlock too (reason: {reads: on}). A FromRun draft
	// is then what `tego learn --reads on` writes, learn's own rendering of the proposal (rulesview.Learned.TextReads);
	// a draft from presets gets the same block from setup (setup.Options.Reads).
	Reads bool
	// Withhold are the destinations the run FromRun leaked secrets to (the dashboard's verdict of it, never a field a
	// person types): the draft leaves every one of them out of net.allow (rulesview.Withhold, QA PW-1).
	Withhold []string
	// LiveMode is how the agent's rules change while it runs (ADR 0125): "" or "locked" (the default) writes no live:
	// section; "adjustable" writes one whose fence lists FenceRead (paths it may be allowed to read), FenceNet
	// (destinations) and FenceExec (programs), each entry refused until a person lifts or grants it.
	LiveMode                       string
	FenceRead, FenceNet, FenceExec []string
}

// The values of NewReq.LiveMode (agent.LiveLocked, agent.LiveAdjustable).
const (
	NewLiveLocked     = string(agent.LiveLocked)
	NewLiveAdjustable = string(agent.LiveAdjustable)
)

// NewGroup is one group of the draft's rules in plain sentences (internal/check/inforce's groups).
type NewGroup struct {
	ID, Title, Lede, Default string
	Rules                    []NewRule
}

// NewRule is one rule of a NewGroup: its sentence and effect word (allow, ask, deny, limit, note), and a note the
// page shows beside it ("" for none).
type NewRule struct {
	Sentence, Effect string
	Note             string
}

// AddressNote is what a draft from a run says beside each network entry that is an address: a watched run's record
// holds the address it connected to, never the name it looked up, and the next run may pick another address of the
// same name (learn.AddressWarning says it for the whole file).
const AddressNote = "Tego saw an address, not a name; the next run may reach another address of this site. Write the host name."

// NewPlan is what the form shows: the composed contract, its rules in sentences, what compile said, and what stops
// Create, if anything. A mistake in the form is a Problem, never an error, so the form is shown again with it.
type NewPlan struct {
	// Dir is the project folder with its symlinks resolved, "" when it is not one Create may write in; File is
	// Dir/agent.yaml.
	Dir, File string
	// Name is the agent id the contract carries.
	Name string
	// Presets are the presets the contract extends; FromRun the run whose proposal it is, and Withheld the
	// destinations its proposal left out because the run leaked secrets there (NewReq.Withhold).
	Presets  []string
	FromRun  string
	Withheld []string
	// Command is the command line typed, which the contract's command: holds (setup.Options.Command).
	Command string
	// Text is the contract as Create writes it; Base its sha256, which Create's request carries back so that the
	// file written is the one previewed.
	Text []byte
	Base string
	// Groups are the draft's rules, every profile it extends laid in, as sentences; ViewNote says what they rest on.
	Groups   []NewGroup
	ViewNote string
	// Diagnostics are what compile said, one line each ("error: …", "warning: …"); OK is that no field has a
	// problem and compile found no error, so Create may write.
	Diagnostics []string
	OK          bool
	// Problems are the form's mistakes, each a sentence with its fix.
	Problems []string
	// MakeDirs are the folders Create makes first (relative to Dir when inside it); Ignore the .gitignore lines the
	// generated folders want; Notes what each preset promises and what is left to add.
	MakeDirs, Ignore, Notes []string
	// Grants is, by preset, what the command's agent was given past the preset's promise (setup.Result.Grants).
	Grants map[string][]string
	// Protection says what the draft does to the protection of the whole policy, "" for nothing worth a banner.
	Protection string
	// Exists is set when Dir already holds agent.yaml: Create is refused, and the Rules page opens it.
	Exists bool
	// Registry is set when File is the user registry's entry Name (NewReq.Registry), which tego run <Name> finds from
	// Dir; Reads when the draft records each read it refuses (NewReq.Reads).
	Registry, Reads bool
	// writeDirs are a FromRun draft's fs.write directories, which a registry entry may not lie inside.
	writeDirs []string
}

// Created is a new contract written.
type Created struct {
	// ID is the journal line of the write, "" when it was written but not journaled (ErrJournal).
	ID string
	// Ref is the contract's ref in the bounded set; Path its file, Dir its project folder.
	Ref, Path, Dir string
	Name           string
	Command        string
	// Made are the folders made for it, relative to Dir when inside it; Ignore the .gitignore lines they want.
	Made, Ignore []string
	// Registry is set when Path is the user registry's entry Name, which no change record holds: tego run <Name>
	// typed in Dir finds it.
	Registry bool
}

// PlanNew composes and checks the contract req asks for and writes nothing. Its error is the service's own failure
// (no machine config to compile against is a Problem, as every mistake in req is).
func (s *Service) PlanNew(ctx context.Context, req NewReq) (*NewPlan, error) {
	p, _, _ := s.planNew(ctx, req)
	return p, nil
}

// CreateNew writes the contract PlanNew shows for req into its project folder, when the plan has no problem, compiles,
// and still is the text base names (ErrStale otherwise: the folder's markers or a preset changed what is composed).
// It makes the plan's folders beneath the checked project folder, refusing a symbolic link on the way (setup.Create),
// compiles again with them in place (setup.Apply), writes agent.yaml with rulefile.Create (ErrRefused when a file is
// there) and removes the folders it made when anything after them fails (setup.Remove: only while empty, never
// through a link).
// A write that lands but is not journaled returns the Created and an error wrapping rulefile.ErrJournal.
func (s *Service) CreateNew(ctx context.Context, req NewReq, base string) (*Created, error) {
	p, res, env := s.planNew(ctx, req)
	switch {
	case len(p.Problems) > 0:
		return nil, fmt.Errorf("%w: %s", ErrRefused, strings.Join(p.Problems, " "))
	case !p.OK:
		return nil, fmt.Errorf("%w: the contract does not compile, so nothing was written: %s", ErrRefused, strings.Join(p.Diagnostics, "; "))
	case base == "" || base != p.Base:
		return nil, fmt.Errorf("%w: the contract composed now is not the one previewed; look at the preview again", ErrStale)
	}
	if p.Registry {
		return s.saveNew(ctx, p, env)
	}
	cr, ok := s.writer().(Creator)
	if !ok {
		return nil, fmt.Errorf("%w: this dashboard's writer cannot write a new contract", ErrRefused)
	}
	var made []string
	var err error
	if env == nil { // a test compiler (Service.Compile): no second compile to make
		made, err = setup.Create(res, p.Dir)
	} else {
		var ds []agent.Diagnostic
		var compiled bool
		made, ds, compiled, err = setup.Apply(res, p.Dir, *env)
		if err == nil && !compiled {
			return nil, fmt.Errorf("%w: with its folders in place the contract does not compile, so nothing was written: %s",
				ErrRefused, strings.Join(diagLines(ds, true), "; "))
		}
	}
	if err != nil {
		setup.Remove(made, p.Dir)
		return nil, fmt.Errorf("%w: %v", ErrRefused, err)
	}
	summary := "set up agent " + p.Name
	switch {
	case p.FromRun != "":
		summary += " from run " + p.FromRun + "'s least privilege"
	case len(p.Presets) > 0:
		summary += " with " + strings.Join(p.Presets, ", ")
	}
	e, err := cr.Create(ctx, p.File, p.Text, rulefile.Change{Via: Via, Run: p.FromRun, Summary: summary})
	if err != nil && !errors.Is(err, rulefile.ErrJournal) {
		setup.Remove(made, p.Dir)
		return nil, fmt.Errorf("%w: %v", ErrRefused, err)
	}
	out := &Created{Path: p.File, Dir: p.Dir, Name: p.Name, Command: p.Command, Made: made, Ignore: p.Ignore}
	if e != nil {
		out.Path, out.Ref = e.Contract, refOf(e.Contract)
		if err == nil {
			out.ID = e.ID
		}
	}
	return out, err
}

// DescribeNew is the plan of a contract of the bounded set that no run ran yet (Contracts' Runs is 0): its text, its
// rules in sentences and what compile says, for the Rules page to show before its first run.
func (s *Service) DescribeNew(ctx context.Context, ref string) (*NewPlan, error) {
	c, err := s.contract(ref)
	if err != nil {
		return nil, err
	}
	if c.Runs > 0 {
		return nil, fmt.Errorf("%w: %s has runs; the Rules page shows their rules", ErrNoContract, ref)
	}
	f, err := s.readContract(c)
	if err != nil {
		return nil, err
	}
	p := &NewPlan{Dir: filepath.Dir(f.Path), File: f.Path, Name: c.Agent, Text: f.Text, Base: f.SHA256}
	switch env := s.newEnv(); {
	case s.Compile != nil || s.Check != nil:
		p.Diagnostics, p.OK = s.seamCheck(ctx, p.File, p.Dir, f.Text)
	case env != nil:
		ds, ok := setup.Check(f.Text, p.Dir, *env)
		p.Diagnostics, p.OK = diagLines(ds, false), ok
	default:
		p.Problems = append(p.Problems, errNoCompiler.Error())
	}
	s.sentences(p)
	return p, nil
}

// What Ask before reading does to a whole policy. A read waits for a person only at tier landlock, so the draft pins
// it, on a machine that could run stronger. Adjustable cannot run there, and at tier cgroup or bpflsm these reads are
// refused without asking: that fails closed, but the field does not do what it says.
const (
	askReadBasic      = "Ask before reading runs this whole contract at Basic protection: only there can a read wait for you"
	askReadAdjustable = "Adjustable runs at Strong or Strongest, where a read cannot wait: these reads are refused without asking you"
)

// planNew is PlanNew with what CreateNew needs besides: the setup result and the compile environment (nil when a test
// compiler stands in, or there is no machine config).
func (s *Service) planNew(ctx context.Context, req NewReq) (*NewPlan, *setup.Result, *setup.CheckEnv) {
	p := &NewPlan{FromRun: strings.TrimSpace(req.FromRun), Command: strings.TrimSpace(req.Command)}
	dir, problem := s.projectDir(req.Dir)
	if problem != "" {
		p.Problems = append(p.Problems, problem)
		return p, nil, nil
	}
	p.Dir, p.File = dir, filepath.Join(dir, NewFile)
	name, problem := newName(req.Name, dir)
	if problem != "" {
		p.Problems = append(p.Problems, problem)
	}
	p.Name = name
	p.Registry, p.Reads = req.Registry && p.FromRun != "", req.Reads
	var st unix.Stat_t
	if p.Registry {
		// The file is the registry's entry, and what Save would refuse is a problem now, before the preview.
		sv := s.registrySave(p, nil)
		path, err := sv.Check()
		if path != "" {
			p.File = path
		}
		if err != nil && problem == "" {
			p.Problems = append(p.Problems, saveProblem(err, name))
		}
	} else if unix.Lstat(p.File, &st) == nil {
		p.Exists = true
		p.Problems = append(p.Problems, fmt.Sprintf("%s already holds %s, and a new agent's rules are never written over a "+
			"file: open it on the Rules page, or pick another folder.", dir, NewFile))
	}
	env := s.newEnv()
	seam := s.Compile != nil || s.Check != nil
	if env == nil && !seam {
		p.Problems = append(p.Problems, errNoCompiler.Error())
	}
	var res *setup.Result
	if p.FromRun != "" {
		res = s.fromRun(ctx, p, req.Withhold)
	} else {
		res = s.fromPresets(ctx, p, req, env, seam)
	}
	if res == nil {
		return p, nil, nil
	}
	switch strings.TrimSpace(req.LiveMode) {
	case "", NewLiveLocked: // Locked: the contract exactly as it always was
	case NewLiveAdjustable:
		s.adjustable(ctx, p, req, res, env, seam)
	default:
		p.Problems = append(p.Problems, fmt.Sprintf("%q is not a live mode: pick Locked or Adjustable (live both ways).", req.LiveMode))
	}
	p.Text, p.Base = res.Contract, rulefile.Sum(res.Contract)
	p.Presets, p.Ignore, p.Notes, p.Grants = res.Presets, res.Ignore, res.Notes, res.Grants
	if p.FromRun == "" && len(nonEmpty(req.AskRead)) > 0 {
		// compose.go pins tier: landlock for these reads, the one tier that can hold one; Adjustable needs another.
		p.Protection = askReadBasic
		if strings.TrimSpace(req.LiveMode) == NewLiveAdjustable {
			p.Protection = askReadAdjustable
		}
	}
	for _, d := range res.MakeDirs {
		if rel, err := filepath.Rel(dir, d); err == nil && filepath.IsLocal(rel) {
			d = filepath.ToSlash(rel) + "/"
		}
		p.MakeDirs = append(p.MakeDirs, d)
	}
	s.sentences(p)
	p.OK = p.OK && len(p.Problems) == 0
	if !seam {
		return p, res, env
	}
	return p, res, nil
}

// liveHeader opens the live: section an Adjustable draft gets, as `tego init --live-mode adjustable` writes it.
const liveHeader = `
# How this agent's rules change while it runs (docs/user/live-modes.md):
#   locked:     file, program and network rules are fixed when the run starts; tighten while it runs, loosen from the next run.
#   adjustable: the kernel enforces a wider fence; Tego's live layer enforces the rules inside it, so you can
#               loosen and tighten while it runs. Weaker if Tego fails; needs tier cgroup or bpflsm (root).
`

// liveSection is the live: section of an Adjustable draft: mode adjustable and the fence the form listed.
type liveSection struct {
	Live struct {
		Mode  string `yaml:"mode"`
		Fence struct {
			Read []string `yaml:"read,omitempty"`
			Net  []string `yaml:"net,omitempty"`
			Exec []string `yaml:"exec,omitempty"`
		} `yaml:"fence,omitempty"`
	} `yaml:"live"`
}

// adjustable makes res's contract Adjustable (ADR 0125): its live: section appended, with the fence req lists, and a
// tier: landlock line, which Adjustable is refused at, made tier: cgroup with a note that it needs root. The draft is
// compiled again, so compile's verdict on the fence is the one the page shows and Create keeps.
func (s *Service) adjustable(ctx context.Context, p *NewPlan, req NewReq, res *setup.Result, env *setup.CheckEnv, seam bool) {
	text := string(res.Contract)
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, "live:") {
			p.Problems = append(p.Problems, "The draft already has a live: section, so Adjustable cannot add one: pick Locked, and change its live: section on the Change rules page.")
			return
		}
	}
	var sec liveSection
	sec.Live.Mode = NewLiveAdjustable
	sec.Live.Fence.Read, sec.Live.Fence.Net, sec.Live.Fence.Exec = nonEmpty(req.FenceRead), nonEmpty(req.FenceNet), nonEmpty(req.FenceExec)
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2) // as tego init writes it
	err := enc.Encode(&sec)
	if cerr := enc.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		p.Problems = append(p.Problems, sentence("the live section could not be written: "+err.Error()))
		return
	}
	lines := strings.SplitAfter(text, "\n")
	pinned := false
	for i, l := range lines {
		if rest, ok := strings.CutPrefix(l, "tier: landlock"); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\n' || rest[0] == '#') {
			lines[i], pinned = "tier: cgroup"+rest, true
		}
	}
	text = strings.Join(lines, "")
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	res.Contract = []byte(text + liveHeader + b.String())
	if pinned {
		res.Notes = append(res.Notes, "  tier: cgroup is written in place of tier: landlock: Adjustable needs tier cgroup or bpflsm, which need root")
	} else {
		res.Notes = append(res.Notes, "  Adjustable needs tier cgroup or bpflsm, which need root: a run that lands at tier landlock is refused")
	}
	switch {
	case seam:
		p.Diagnostics, p.OK = s.seamCheck(ctx, p.File, p.Dir, res.Contract)
	case env != nil:
		ds, ok := setup.Check(res.Contract, p.Dir, *env)
		p.Diagnostics, p.OK = diagLines(ds, false), ok
	}
}

// fromPresets composes the presets' contract (setup.Draft, the code `tego init --preset` writes through) and sets the
// plan's diagnostics; nil when the form's presets, folders or hosts are a mistake (a Problem).
func (s *Service) fromPresets(ctx context.Context, p *NewPlan, req NewReq, env *setup.CheckEnv, seam bool) *setup.Result {
	o := setup.Options{Presets: req.Presets, Writes: nonEmpty(req.Writes), Hosts: nonEmpty(req.Hosts), Command: p.Command,
		Name: p.Name, Dir: p.Dir, Home: s.home(), Pass: nonEmpty(req.Pass), AskRead: nonEmpty(req.AskRead), AgentNeeds: true, Reads: p.Reads}
	if p.Name == "" {
		o.Name = "agent" // composed for the preview anyway; the name's own Problem stops Create
	}
	if len(nonEmpty(o.Presets)) == 0 {
		p.Problems = append(p.Problems, "Pick at least one preset: no-secrets, no-prod or repo-only-writes.")
		return nil
	}
	var res *setup.Result
	var err error
	switch {
	case seam:
		if res, err = setup.Compose(o); err == nil {
			p.Diagnostics, p.OK = s.seamCheck(ctx, p.File, p.Dir, res.Contract)
		}
	case env != nil:
		if res, err = setup.Draft(o, *env); err == nil {
			p.Diagnostics, p.OK = diagLines(res.Diagnostics, false), res.OK
		}
	default:
		res, err = setup.Compose(o)
	}
	if err != nil {
		p.Problems = append(p.Problems, sentence(err.Error()))
		return nil
	}
	return res
}

// fromRun makes the plan's draft the least-privilege proposal of run p.FromRun, with the destinations in withhold left
// out of net.allow (the run leaked secrets there), renamed to p.Name, and compiles it in the project folder; nil when
// there is no proposal (a Problem).
func (s *Service) fromRun(ctx context.Context, p *NewPlan, withhold []string) *setup.Result {
	if !runID(p.FromRun) {
		p.Problems = append(p.Problems, fmt.Sprintf("%q is not a run id; pick a run from the list.", p.FromRun))
		return nil
	}
	l := rulesview.Learn(ctx, s.Ledger, s.Anchor, p.FromRun)
	if l.Err != "" {
		p.Problems = append(p.Problems, fmt.Sprintf("Run %s has no least-privilege proposal: %s.", p.FromRun, strings.TrimSuffix(l.Err, ".")))
		return nil
	}
	draft := l.Text
	if p.Reads {
		draft = l.TextReads
	}
	proposal, held := rulesview.Withhold(draft, withhold)
	p.Withheld = held
	if w := rulesview.AddressWarning(proposal); w != "" {
		p.Notes = append(p.Notes, "  "+w)
	}
	text := []byte(proposal)
	if p.Name != "" {
		text = renamed(text, p.Name)
	}
	if !l.Ended {
		p.Notes = append(p.Notes, "  run "+p.FromRun+" has not ended: the proposal is what it did so far, and it suggests no limits")
	}
	if l.Left > 0 {
		p.Notes = append(p.Notes, fmt.Sprintf("  %d things the run did are left out (the file's comments name them): a write outside the project, a dangerous socket", l.Left))
	}
	if len(held) > 0 {
		p.Notes = append(p.Notes, "  run "+p.FromRun+" leaked secrets to "+strings.Join(held, ", ")+": that address is left out of the proposal")
	}
	p.writeDirs = l.WriteDirs
	if p.Registry && len(p.Problems) == 0 {
		// The write entries are known now: Save's check again, with them.
		if _, err := s.registrySave(p, text).Check(); err != nil {
			p.Problems = append(p.Problems, saveProblem(err, p.Name))
		}
	}
	switch env := s.newEnv(); {
	case s.Compile != nil || s.Check != nil:
		p.Diagnostics, p.OK = s.seamCheck(ctx, p.File, p.Dir, text)
	case env != nil:
		ds, ok := setup.CheckFile(text, p.File, p.Dir, *env)
		p.Diagnostics, p.OK = diagLines(ds, false), ok
	}
	return &setup.Result{Contract: text, Notes: p.Notes} // planNew sets p.Notes from the result
}

// registrySave is the registry.Save of p's draft text: the user registry of the machine config, the name looked up
// from p.Dir, where tego run <name> is typed next, tego's own directories (the ledger root, the profiles directory,
// the chain anchor's directory) refused as a registry's place, and p's write entries. Its Compile is the preview's
// compile with the entry's path as the contract's file.
func (s *Service) registrySave(p *NewPlan, text []byte) registry.Save {
	uid, _ := config.InvokingUID()
	places := registry.Places{Dir: p.Dir, UID: uid, Own: []string{s.Ledger}}
	if s.Machine != nil {
		places.User = s.Machine.Registry.Value
		places.Own = append(places.Own, s.Machine.LedgerRoot.Value, s.Machine.Profiles.Value)
	}
	if s.Anchor != "" {
		places.Own = append(places.Own, filepath.Dir(s.Anchor))
	}
	return registry.Save{Places: places, From: []string{p.Dir}, Name: p.Name, Text: text, Writes: p.writeDirs}
}

// saveNew is CreateNew of a plan saved in the user registry (NewReq.Registry): registry.Save writes it, the writer
// `tego learn --save` writes through, after compiling it once more as the entry it will be. A refusal is ErrRefused
// with the sentence saveProblem says; the entry is in no change record.
func (s *Service) saveNew(ctx context.Context, p *NewPlan, env *setup.CheckEnv) (*Created, error) {
	sv := s.registrySave(p, p.Text)
	sv.Compile = func(path string, text []byte) error {
		if env == nil { // a test compiler (Service.Compile)
			if ds, ok := s.seamCheck(ctx, path, p.Dir, text); !ok {
				return errors.New(strings.Join(ds, "; "))
			}
			return nil
		}
		if ds, ok := setup.CheckFile(text, path, p.Dir, *env); !ok {
			return errors.New(strings.Join(diagLines(ds, true), "; "))
		}
		return nil
	}
	path, err := sv.Write()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrRefused, saveProblem(err, p.Name))
	}
	return &Created{Path: path, Dir: p.Dir, Name: p.Name, Command: p.Command, Registry: true}, nil
}

// saveProblem is a refused registry.Save as the form's sentence with its fix, in the words `tego learn --save` uses.
func saveProblem(err error, name string) string {
	var se *registry.SaveError
	if !errors.As(err, &se) {
		return "Tego could not save it: " + strings.TrimSuffix(err.Error(), ".") + "."
	}
	switch se.Step {
	case registry.SaveName:
		return "The agent name " + strings.TrimSuffix(se.Err.Error(), ".") + "."
	case registry.SaveNoRegistry:
		return "The machine config names no user registry (registry: in its file), so there is nowhere tego run " + name +
			" finds a contract: save it in the project folder instead."
	case registry.SaveTaken:
		if se.Entry != nil {
			return fmt.Sprintf("The agent name %q is already the contract %s: give another name.", name, se.Entry.Path)
		}
		var re *registry.Error
		if errors.As(se.Err, &re) && re.Code == registry.CodeAmbiguous {
			return fmt.Sprintf("The agent name %q is taken in %s: %s. Give another name.", name, se.Dir, strings.TrimSuffix(se.Err.Error(), "."))
		}
		return fmt.Sprintf("The registry cannot say whether the agent name %q is free in %s: %s. Nothing was saved.", name, se.Dir,
			strings.TrimSuffix(se.Err.Error(), "."))
	case registry.SaveInsideWrite:
		return fmt.Sprintf("%s would lie inside the contract's own write entry %s, and tego refuses to run a contract its agent "+
			"could rewrite: save it in the project folder instead.", se.Path, se.Write)
	case registry.SaveNoCompile:
		return "The contract does not compile here, so nothing was saved: " + strings.TrimSuffix(se.Err.Error(), ".") + "."
	case registry.SaveExists:
		return se.Path + " is there already, and a contract is never written over a file: give another name."
	case registry.SaveUnusable:
		return fmt.Sprintf("tego run %s in %s would refuse the file (%s), so nothing was saved.", name, se.Dir, strings.TrimSuffix(se.Err.Error(), "."))
	case registry.SaveIO:
		what := se.Op
		if what == "mkdir" {
			what = "make the folder"
		}
		return "Tego could not " + what + " " + se.Path + ": " + strings.TrimSuffix(se.Err.Error(), ".") + "."
	}
	return "Tego could not save it: " + strings.TrimSuffix(se.Error(), ".") + "."
}

// newEnv is the machine a new contract is compiled against, as nextrun compiles the next run of a contract and
// `tego compile --offline` compiles one (setup.Check adds Offline and the project folder as the cwd): the machine
// config and its profile sources, the dashboard's PATH, the invoking user's home, the chain anchor and runtime
// directories. No tiers are passed: tego-control links no backend, so an auto contract resolves to the machine
// ceiling. nil without a machine config.
func (s *Service) newEnv() *setup.CheckEnv {
	if s.Machine == nil {
		return nil
	}
	opts := []agent.CompileOption{agent.WithPATH(s.path()), agent.WithClock(time.Now), agent.WithRuntimeDir(config.RuntimeDirBases()...), agent.WithOwnBinaries("")}
	if s.Machine.Home != "" {
		opts = append(opts, agent.WithHome(s.Machine.Home))
	}
	if s.Anchor != "" {
		opts = append(opts, agent.WithChainAnchor(s.Anchor))
	}
	return &setup.CheckEnv{Machine: s.Machine, Profiles: profilesrc.Chain(s.Machine), Options: opts}
}

// seamCheck is the test compiler's verdict on text as the contract file in dir.
func (s *Service) seamCheck(ctx context.Context, file, dir string, text []byte) ([]string, bool) {
	if _, err := s.compile(ctx, CheckContext{Contract: file, Cwd: dir}, text); err != nil {
		return []string{"error: " + err.Error()}, false
	}
	return nil, true
}

// sentences fills p.Groups from p.Text: the merged contract (every profile it extends laid in, as `tego compile
// --merged` prints it) read by inforce.Declared, so a preset's rules are said too. A draft makes no enforcement
// claim: the run's tier decides that.
func (s *Service) sentences(p *NewPlan) {
	if len(p.Text) == 0 {
		return
	}
	text := p.Text
	var profiles agent.ProfileSource
	if s.Machine != nil {
		profiles = profilesrc.Chain(s.Machine)
	} else {
		profiles = profilesrc.Chain(nil)
	}
	p.ViewNote = "What the agent may do under this contract, every preset it extends laid in. A run's protection level decides how each rule is enforced."
	if c, _, err := agent.LoadBytes(p.File, p.Text, profiles); err == nil {
		if merged, err := c.Canonical(); err == nil {
			text = merged
		}
	} else {
		p.ViewNote = "Read from the file as written: its profiles could not be read, so a preset's own rules are not listed."
	}
	v, err := inforce.Declared(text, p.File)
	if err != nil {
		p.ViewNote = "The contract is not valid YAML, so no rules can be shown."
		return
	}
	builtIn := builtInSecretsOn(v)
	for _, g := range v.Groups {
		var extra []NewRule
		if g.ID == inforce.GroupNeverRead && builtIn {
			extra = builtInSecretRules()
		}
		if g.ID == inforce.GroupLive || len(g.Rules) == 0 && len(extra) == 0 && g.Default == "" {
			continue
		}
		ng := NewGroup{ID: g.ID, Title: g.Title, Lede: g.Lede, Default: g.Default, Rules: extra}
		for _, r := range g.Rules {
			nr := NewRule{Sentence: r.Sentence, Effect: string(r.Effect)}
			if p.FromRun != "" && r.Key == "net.allow" && addressEntry(r.Entry) {
				nr.Note = AddressNote
			}
			ng.Rules = append(ng.Rules, nr)
		}
		p.Groups = append(p.Groups, ng)
	}
}

// addressEntry is whether a net.allow entry names an address and a port, not a host: tcp://, udp:// or no scheme.
func addressEntry(entry string) bool {
	for _, scheme := range []string{"tcp://", "udp://"} {
		entry = strings.TrimPrefix(entry, scheme)
	}
	_, err := netip.ParseAddrPort(entry)
	return err == nil
}

// builtInSecretsOn is whether the view's contract keeps the built-in secret list (it does not say deny_read: []).
func builtInSecretsOn(v inforce.View) bool {
	for _, g := range v.Groups {
		if g.ID != inforce.GroupAlwaysOn {
			continue
		}
		for _, r := range g.Rules {
			if r.Key == "built-in.deny_read" {
				return true
			}
		}
	}
	return false
}

// builtInSecretRules are the built-in secret list (agent.BuiltInDenyRead and the .env scan) as Never reads rows, one
// per family the list's own table gives each row (agent.BuiltInDenyReadFamily). No contract line writes them, so
// inforce lists them only as one Always on row at the foot of the page; no-secrets' file half is exactly this list,
// and a draft that names it should show it where a reader looks for refusals.
func builtInSecretRules() []NewRule {
	var ssh, logins, browsers []string
	for _, p := range agent.BuiltInDenyRead() {
		// Every row has one of these families (TestBuiltInDenyReadFamilies), and a new family is a case to add here
		// (the exhaustive linter, TestBuiltInSecretRulesFollowFamilies).
		switch agent.BuiltInDenyReadFamily(p) {
		case agent.SecretSSHKeys:
			ssh = append(ssh, "~/"+p)
		case agent.SecretLogins:
			logins = append(logins, "~/"+p)
		case agent.SecretBrowsers:
			browsers = append(browsers, p)
		}
	}
	var out []NewRule
	if len(ssh) > 0 {
		out = append(out, NewRule{Sentence: "Never reads your SSH keys (" + strings.Join(ssh, ", ") + "), built in", Effect: string(inforce.EffectDeny)})
	}
	if len(logins) > 0 {
		out = append(out, NewRule{Sentence: "Never reads cloud, registry and git logins (" + strings.Join(logins, ", ") + "), built in", Effect: string(inforce.EffectDeny)})
	}
	if len(browsers) > 0 {
		out = append(out, NewRule{Sentence: "Never reads browser profiles (Firefox, Chrome, Chromium, Brave, Edge, Vivaldi, Opera), built in", Effect: string(inforce.EffectDeny)})
	}
	return append(out, NewRule{Sentence: "Never reads .env files in the project folder, built in", Effect: string(inforce.EffectDeny)})
}

// projectDir checks the typed project folder and returns it with its symlinks resolved: an absolute path (or ~/ for
// the invoking user's home), an existing directory, this user's, not writable by others unless sticky, and not the
// ledger root, tego's home or under either. Each refusal is a sentence with its fix. setup.Create opens the path it
// returns again with no symlink followed, so a link swapped into that path after this check is refused, never
// followed out of the project; a real folder renamed into the path after the check is used, since neither these
// checks nor the descriptor that made them are carried to Create.
func (s *Service) projectDir(typed string) (dir, problem string) {
	typed = strings.TrimSpace(typed)
	switch {
	case typed == "":
		return "", "Type the project folder: the folder the agent works in, where agent.yaml is written."
	case len(typed) > 4096 || strings.ContainsRune(typed, 0):
		return "", "That is not a folder path."
	case typed == "~" || strings.HasPrefix(typed, "~/"):
		h := s.home()
		if h == "" {
			return "", "This dashboard does not know your home folder: type the full path."
		}
		typed = filepath.Join(h, strings.TrimPrefix(strings.TrimPrefix(typed, "~"), "/"))
	case !filepath.IsAbs(typed):
		return "", fmt.Sprintf("Type the full path of the project folder (it starts with / or ~/), not %q.", typed)
	}
	dir, err := filepath.EvalSymlinks(filepath.Clean(typed))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Sprintf("%s does not exist. Set up an agent in a project folder that exists: create it first.", typed)
		}
		return "", fmt.Sprintf("%s cannot be read: %v.", typed, err)
	}
	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		return "", fmt.Sprintf("%s cannot be read: %v.", dir, err)
	}
	switch euid := uint32(os.Geteuid()); {
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		return "", fmt.Sprintf("%s is not a folder.", dir)
	case st.Uid != euid:
		return "", fmt.Sprintf("%s is owned by uid %d, not by you (uid %d): set up an agent in a folder of your own.", dir, st.Uid, euid)
	case st.Mode&0o002 != 0 && st.Mode&unix.S_ISVTX == 0:
		return "", fmt.Sprintf("%s is writable by every user, so another user could swap the rules file: chmod o-w %s, or pick another folder.", dir, dir)
	}
	g := s.guard()
	refuse := append([]string{g.LedgerRoot}, g.Refuse...)
	if h := s.home(); h != "" {
		refuse = append(refuse, filepath.Join(h, ".tego"))
	}
	for _, r := range refuse {
		if r == "" {
			continue
		}
		rr := r
		if e, err := filepath.EvalSymlinks(r); err == nil {
			rr = e
		}
		if within(dir, rr) {
			return "", fmt.Sprintf("%s is tego's own folder (the ledger root or tego's home, %s) or inside it: an agent's rules never live there. Pick the project folder.", dir, r)
		}
	}
	return dir, ""
}

// home is the invoking user's home: the service's, else the machine config's.
func (s *Service) home() string {
	if s.Home != "" {
		return s.Home
	}
	if s.Machine != nil {
		return s.Machine.Home
	}
	return ""
}

// within is whether p is dir or inside it.
func within(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// newName is the typed agent id, or one made from the folder's name when none is typed; problem says why it is not
// one.
func newName(typed, dir string) (name, problem string) {
	typed = strings.TrimSpace(typed)
	if typed == "" {
		var b strings.Builder
		for _, r := range strings.ToLower(filepath.Base(dir)) {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
				b.WriteRune(r)
			case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
				b.WriteByte('-')
			}
		}
		typed = strings.Trim(b.String(), "-")
		if len(typed) > 40 {
			typed = strings.Trim(typed[:40], "-")
		}
		if typed == "" {
			typed = "agent"
		}
	}
	if _, err := identity.ParseAgentID(typed); err != nil {
		return "", fmt.Sprintf("The agent name %q is not an agent id: use 1 to 40 lowercase letters, digits and dashes.", typed)
	}
	return typed, ""
}

// renamed is text with its top-level name set to name, double-quoted: an agent id may be all digits or a word YAML
// reads as a bool or a null, and name is a string (R3), as tego init writes it. The key is found in the YAML tree, not
// by a line's text, so a name: in a comment or inside another value is never the one set. Its old value alone is
// replaced in the text where the result reads as text did with only the name changed, so the rest of its line (a
// comment) and every other byte stay; otherwise (a name over several lines) the tree is written out with the name set,
// comments and order kept. Text that is not one YAML mapping, or has no top-level name, comes back as it was: compile
// says what is wrong with it.
func renamed(text []byte, name string) []byte {
	var doc yaml.Node
	if yaml.Unmarshal(text, &doc) != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return text
	}
	var v *yaml.Node
	for top, i := doc.Content[0], 0; i+1 < len(top.Content); i += 2 {
		if k := top.Content[i]; k.Kind == yaml.ScalarNode && k.Value == "name" {
			v = top.Content[i+1]
			break
		}
	}
	if v == nil {
		return text
	}
	lines := strings.SplitAfter(string(text), "\n")
	if from, to, ok := scalarSpan(lines, v); ok {
		l := lines[v.Line-1]
		lines[v.Line-1] = l[:from] + strconv.Quote(name) + l[to:]
		if out := []byte(strings.Join(lines, "")); onlyRenamed(text, out, name) {
			return out
		}
	}
	*v = yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Style: yaml.DoubleQuotedStyle, Value: name, Anchor: v.Anchor,
		HeadComment: v.HeadComment, LineComment: v.LineComment, FootComment: v.FootComment}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2) // as tego init writes it
	if enc.Encode(&doc) != nil || enc.Close() != nil {
		return text
	}
	return b.Bytes()
}

// scalarSpan is where the one-line scalar n is written: the byte offsets, in its line, of its source, which reads
// alone as n and is followed by nothing but blanks and n's own comment. ok is false for any other n: a block scalar,
// one with an anchor, or one that goes on over the next lines.
func scalarSpan(lines []string, n *yaml.Node) (from, to int, ok bool) {
	if n.Kind != yaml.ScalarNode || n.Anchor != "" || n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 || n.Line < 1 || n.Line > len(lines) {
		return 0, 0, false
	}
	l := lines[n.Line-1]
	if from = byteAt(l, n.Column-1); from < 0 {
		return 0, 0, false
	}
	to = len(strings.TrimRight(l, " \t\r\n"))
	if c := n.LineComment; c != "" {
		if !strings.HasSuffix(l[:to], c) {
			return 0, 0, false
		}
		to = len(strings.TrimRight(l[:to-len(c)], " \t"))
	}
	if to <= from || !readsAlone(l[from:to], n) {
		return 0, 0, false
	}
	return from, to, true
}

// readsAlone says src, as a mapping value on its own, is the scalar n: its value, tag and style, and no comment.
func readsAlone(src string, n *yaml.Node) bool {
	var doc yaml.Node
	if yaml.Unmarshal([]byte("k: "+src+"\n"), &doc) != nil || len(doc.Content) != 1 || len(doc.Content[0].Content) != 2 {
		return false
	}
	m := doc.Content[0].Content[1]
	return m.Kind == yaml.ScalarNode && m.Value == n.Value && m.Tag == n.Tag && m.Style == n.Style && m.Anchor == "" && m.LineComment == ""
}

// onlyRenamed says out reads as text does with its top-level name set to name, and differs from it in nothing else.
func onlyRenamed(text, out []byte, name string) bool {
	var was, now map[string]any
	if config.GuardYAML(func() error { return yaml.Unmarshal(text, &was) }) != nil || yaml.Unmarshal(out, &now) != nil || was == nil {
		return false
	}
	was["name"] = name
	return reflect.DeepEqual(was, now)
}

// byteAt is the byte offset of rune col (0-based) of s, -1 past its end: yaml.v3 counts columns in runes.
func byteAt(s string, col int) int {
	for off := range s {
		if col == 0 {
			return off
		}
		col--
	}
	return -1
}

// diagLines is ds as one line each, "error: …" or "warning: …", the errors alone with errorsOnly.
func diagLines(ds []agent.Diagnostic, errorsOnly bool) []string {
	var out []string
	for _, d := range ds {
		if errorsOnly && !d.IsError() {
			continue
		}
		line := d.Severity + ": "
		if d.Line > 0 {
			line += fmt.Sprintf("%s:%d: ", filepath.Base(d.File), d.Line)
		}
		line += d.Message
		if d.Code != "" {
			line += " [" + d.Code + "]"
		}
		if d.Fix != "" {
			line += " (fix: " + d.Fix + ")"
		}
		out = append(out, line)
	}
	return out
}

// nonEmpty is xs without its blank items, each trimmed.
func nonEmpty(xs []string) []string {
	var out []string
	for _, x := range xs {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// sentence is msg with a capital first letter and a closing full stop, as the form shows a problem.
func sentence(msg string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return msg
	}
	msg = strings.ToUpper(msg[:1]) + msg[1:]
	if !strings.HasSuffix(msg, ".") {
		msg += "."
	}
	return msg
}

// Preset is one preset the form offers: its name and, in one sentence, what it promises.
type Preset struct {
	Name, Promise string
}

// Presets is every preset, in catalog order, for the form's checkboxes.
func Presets() []Preset {
	var out []Preset
	for _, p := range presets.List() {
		out = append(out, Preset{Name: p.Name, Promise: p.Promise})
	}
	return out
}
