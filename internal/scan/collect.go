// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/attention-span-ai/tego/internal/grouptrust"
	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"github.com/attention-span-ai/tego/internal/scan/result"
)

type callerAccountReaderKey struct{}

// namedProgramKey carries Options.NamedProgram, bound to the caller's home, to the process reads.
type namedProgramKey struct{}

// Options supplies explicit source locations; collection never discovers HOME
// or a default source when a fixture path is absent.
type Options struct {
	// ReadCallerPasswd is a per-call fixture collector. Nil uses root-owned system placement;
	// no environment variable or command-line flag overrides that production policy.
	ReadCallerPasswd                                  func(string) ([]byte, error)
	ProcRoot, Passwd, Boot, Directory, Path, Version  string
	Caller                                            Caller
	Rows                                              []catalog.Row
	Check, AllMine, Advanced, AllowUnreadablePrograms bool
	// NamedProgram says whether pid, a process of the recipient whose program file cannot be read, is one a proof the
	// caller holds names as a Tego process that is not an agent (the dashboard: it is non-dumpable because it holds
	// secrets, and holds a lock the proof reads, internal/runlock). It receives the caller's home and is asked only
	// about such processes, in basic scope. A process it names is not counted among the unreadable programs, as a
	// readable process that matches nothing is not listed; any other unreadable program stays counted. Nil names none.
	NamedProgram func(home string, pid int) bool
	// OnProcRead is an optional audit of attempted proc content reads. It receives
	// paths only, before allow-list checks; no input bytes or argv reach it.
	OnProcRead func(string)
	// BeforeRecipient must permanently drop every thread to uid/gid. Advanced
	// closes its fixed-source descriptors before calling it; nil fails closed.
	BeforeRecipient func(uid, gid uint32) error
	// ResolveDirectory obtains the working folder only after BeforeRecipient.
	// Fixtures may instead supply Directory directly.
	ResolveDirectory func() (string, error)
	// SystemUnitRoots supplies the two fixed machine user-unit directories.
	SystemUnitRoots []string
	// Advanced roots are explicit; missing fixture fields never fall back to host files.
	AdvancedSystemUnitRoots []string
	Cron                    CronRoots
}

// Outcome includes the local-passwd destination separately from untrusted JSON.
type Outcome struct {
	Snapshot result.Snapshot
	Home     string
	GID      uint32
}

// Collect is the bounded basic or initial-root advanced scan. It performs no writes and starts no process.
func Collect(ctx context.Context, o Options) Outcome {
	processes := readProcesses
	if o.Advanced {
		processes = func(ctx context.Context, fs procAccess, root string, uid uint32, rows []catalog.Row) processSnapshot {
			return readProcessesMode(ctx, fs, root, uid, rows, true)
		}
	}
	return collect(ctx, o, processes)
}

func collect(ctx context.Context, o Options, processes func(context.Context, procAccess, string, uint32, []catalog.Row) processSnapshot) Outcome {
	return collectWithIdentity(ctx, o, processes, func(ctx context.Context, fs procAccess, root, passwd, boot string, c Caller, advanced bool) (callerIdentity, string) {
		if !advanced {
			return identifyCaller(ctx, fs, root, passwd, boot, c)
		}
		return identifyCallerMode(ctx, fs, root, passwd, boot, c, true)
	})
}

func collectWithIdentity(ctx context.Context, o Options, processes func(context.Context, procAccess, string, uint32, []catalog.Row) processSnapshot, identify func(context.Context, procAccess, string, string, string, Caller, bool) (callerIdentity, string)) Outcome {
	if o.ReadCallerPasswd != nil {
		ctx = context.WithValue(ctx, callerAccountReaderKey{}, o.ReadCallerPasswd)
	}
	duration := 2 * time.Second
	if o.Advanced {
		duration = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	s := result.New(time.Now(), o.Caller.UID, o.Version)
	s.OtherListed = o.AllMine
	if o.Check {
		s.Check = "unknown"
	}
	if o.Advanced {
		s = result.NewAdvanced(time.Now(), o.Caller.UID, o.Caller.Recipient, o.Version)
		s.OtherListed = o.AllMine
		if o.Check {
			s.Check = "unknown"
		}
	}
	if plainPath(o.Directory) {
		s.Project = result.Path(o.Directory)
	}
	for _, r := range o.Rows {
		origin := "catalog"
		if r.ID[:min(5, len(r.ID))] == "user-" {
			origin = "user"
		}
		name, _ := catalog.ObservedName(r.ID)
		s.Rules = append(s.Rules, result.Rule{ID: r.ID, Name: name, Origin: origin})
	}
	fail := func(reason string) Outcome {
		// Before identity resolution there is no recipient destination.
		s.As.Recipient = o.Caller.UID
		s.AddFailure("meta", reason)
		s.Exclusions = append(s.Exclusions, "scan-not-performed")
		s.Finished = time.Now().UTC()
		return Outcome{Snapshot: s}
	}
	if o.Advanced && (!o.Caller.InitialRoot || o.Caller.UID != 0 || o.Caller.EUID != 0) {
		return fail("privilege")
	}
	fs, err := openProc(o.ProcRoot)
	if err != nil {
		return fail("io")
	}
	defer fs.close()
	fs.observe = o.OnProcRead
	// The 8 MiB process allocation includes caller checks. Record and metadata
	// allocations keep basic below 198 MiB of input and advanced below 224 MiB
	// (ADR 0145). These are input bounds, not a process RSS promise.
	budget := &budgetProc{procAccess: fs, remaining: processInputBudget}
	identity, reason := identify(ctx, budget, o.ProcRoot, o.Passwd, o.Boot, o.Caller, o.Advanced)
	if reason != "" {
		out := fail(reason)
		for _, source := range identity.Sources {
			if source.AccountRepair != "" {
				last := &out.Snapshot.Sources[len(out.Snapshot.Sources)-1]
				last.Locator = result.Path(source.Path)
				last.AccountRepair = source.AccountRepair
			}
		}
		return out
	}
	if ctx.Value(collectionPolicyKey{}) == nil {
		ctx = context.WithValue(ctx, collectionPolicyKey{}, &discoveryPolicy{load: func() grouptrust.Policy { return grouptrust.System(int(o.Caller.UID)) }})
	}
	s.Boot = result.Path(identity.Boot)
	if identity.OuterNamespace || identity.NamespaceUnknown {
		s.Exclusions = append(s.Exclusions, "outer-pid-namespace")
	}
	if o.NamedProgram != nil && !o.Advanced {
		ctx = context.WithValue(ctx, namedProgramKey{}, func(pid int) bool { return o.NamedProgram(identity.Home, pid) })
	}
	a := processes(ctx, budget, o.ProcRoot, identity.Recipient, o.Rows)
	content := &contentBudget{remaining: 6 << 20}
	if o.Advanced {
		content = &contentBudget{remaining: 32 << 20, fileLimit: 8192, units: &unitWorkBudget{entries: 16384, perDirectory: 8192, maxDirectories: 4096}}
	}
	unitPaths := []string{filepath.Join(identity.Home, ".config/systemd/user")}
	if len(o.SystemUnitRoots) > 0 {
		unitPaths = append(unitPaths, o.SystemUnitRoots[0])
	}
	unitPaths = append(unitPaths, filepath.Join(identity.Home, ".local/share/systemd/user"))
	if len(o.SystemUnitRoots) > 1 {
		unitPaths = append(unitPaths, o.SystemUnitRoots[1])
	}
	e := unitSnapshot{}
	system := unitSnapshot{}
	cron := cronSnapshot{}
	if o.Advanced {
		e, system = collectAdvancedUnits(ctx, identity.Accounts, o.SystemUnitRoots, o.AdvancedSystemUnitRoots, content)
		cron = collectCron(ctx, o.Cron, identity.Accounts, content)

	}
	// No root-opened descriptor crosses into the recipient phase. Fixed account
	// unit paths are the only home paths that advanced collection may read here.
	fs.close()
	dropFailed := false
	if o.Advanced {
		dropFailed = o.BeforeRecipient == nil
		if !dropFailed {
			dropFailed = o.BeforeRecipient(identity.Recipient, identity.GID) != nil
		}
	}
	m, f, d := metadataSnapshot{}, projectSnapshot{}, mcpSnapshot{}
	var directoryErr error
	if !dropFailed {
		if o.ResolveDirectory != nil {
			o.Directory, directoryErr = o.ResolveDirectory()
			if directoryErr != nil {
				o.Directory = ""
			}
		}
		if plainPath(o.Directory) {
			s.Project = result.Path(o.Directory)
		}
		m = collectMetadata(ctx, identity.Home, o.Directory, o.Path, identity.Recipient, o.Rows)
		f = collectProject(ctx, o.Directory, identity.Recipient, identity.GID)
		d = collectMCP(ctx, identity.Home, o.Directory, identity.Recipient, content)
		if !o.Advanced {
			e = collectUnits(ctx, unitPaths, o.Caller.UID, content)
		}
	}
	s.Status = "ok"
	s.Counts.Exited = a.Exited
	s.Counts.KernelThreads = a.KernelThreads
	// One encoded result budget covers all collectors, with space reserved for
	// unknown-remainder rows and save diagnostics. Evidence never outlives sources.
	retained := 0
	limited := map[string]bool{}
	addSource := func(kind string, p processSource) string {
		if limited[kind] {
			return ""
		}
		v := result.Source{ID: fmt.Sprintf("source-%d", len(s.Sources)+1), Kind: kind, Locator: result.Path(p.Path), State: p.State, Reason: p.Reason, WritableGroup: p.WritableGroup, GroupEvidence: p.GroupEvidence, AccountRepair: p.AccountRepair, Read: p.Read, NotRead: p.NotRead}
		if v.Locator != nil && !plainPath(*v.Locator) {
			v.Locator = nil
			v.WritableGroup = nil
			v.GroupEvidence = ""
			v.AccountRepair = ""
			v.State = "not-read"
			v.Reason = "unsupported"
			v.NotRead = 1
			v.Read = 0
		}
		b, _ := json.Marshal(v)
		if len(s.Sources) >= 2020 || retained+len(b) > 430<<10 {
			limited[kind] = true
			s.Sources = append(s.Sources, result.Source{ID: v.ID, Kind: kind, State: "not-read", Reason: "limit", NotRead: 1})
			s.Limits = appendUnique(s.Limits, "source-limit")
			s.Status = "partial"
			return ""
		}
		retained += len(b)
		s.Sources = append(s.Sources, v)
		if v.State == "not-read" || v.State == "partial" || v.State == "unreadable-program" {
			s.Status = "partial"
		}
		return v.ID
	}
	sourceIDs := map[string]string{}
	if directoryErr != nil {
		addSource("meta", procSource("", directoryErr, false))
	}
	if o.Directory != "" && !plainPath(o.Directory) {
		addSource("meta", processSource{State: "not-read", Reason: "unsupported", NotRead: 1})
	}
	for _, p := range identity.Sources {
		addSource("meta", p)
	}
	unreadableIndex := 0
	for _, p := range a.Sources {
		id := addSource("A", p)
		if p.State == "unreadable-program" {
			if id != "" && unreadableIndex < len(a.UnreadablePIDs) {
				s.UnreadableProgramPIDs = append(s.UnreadableProgramPIDs, a.UnreadablePIDs[unreadableIndex])
			}
			unreadableIndex++
		}
		if p.State == "read" {
			sourceIDs["A:"+p.Path] = id
		}
	}
	s.Counts.UnreadablePrograms = len(s.UnreadableProgramPIDs)
	for _, p := range m.Sources {
		id := addSource(p.Kind, p.processSource)
		if p.State == "read" {
			sourceIDs[p.Kind+":"+p.Path] = id
		}
	}
	for _, p := range f.Sources {
		id := addSource("F", p)
		if p.State == "read" {
			sourceIDs["F:"+p.Path] = id
		}
	}

	for _, group := range []struct {
		kind    string
		sources []processSource
	}{{"D", d.Sources}, {"E", e.Sources}, {"system", system.Sources}, {"cron", cron.Sources}} {
		for _, p := range group.sources {
			id := addSource(group.kind, p)
			if p.State == "read" {
				sourceIDs[group.kind+":"+p.Path] = id
			}
		}
	}

	itemBytes := 0
	addItem := func(i result.Item) bool {
		b, _ := json.Marshal(i)
		if len(s.Items) >= 512 || itemBytes+len(b) > 450<<10 {
			s.Limits = appendUnique(s.Limits, "item-limit")
			s.Status = "partial"
			return false
		}
		itemBytes += len(b)
		i.ID = fmt.Sprintf("item-%d", len(s.Items)+1)
		s.Items = append(s.Items, i)
		return true
	}
	otherRule := false
	for _, p := range a.Processes {
		id := sourceIDs["A:"+p.SourcePath]
		if id == "" {
			a.Unknown = true
			continue
		}
		kind, name, rid, fact := "process", p.Name, p.RuleID, string(p.Fact)
		if p.Other {
			s.Counts.Other++
			if !o.AllMine {
				continue
			}
			kind, name, rid, fact = "other_program", "other-interpreter", "other-interpreter", "interpreter"
			if !otherRule {
				s.Rules = append(s.Rules, result.Rule{ID: rid, Name: name, Origin: "catalog"})
				otherRule = true
			}
		}
		detail := result.Process{PID: p.PID, PPID: p.PPID, UID: p.UID, Start: strconv.FormatUint(p.Start, 10), Exe: result.Path(p.Exe), Cwd: result.Path(p.Cwd), Membership: p.Membership, RunID: result.Path(p.RunID)}
		if !p.Other && p.ContainerID != "" {
			detail.Container = rawContainer(p.ContainerRuntime, p.ContainerID)
		}
		caveats := []string{"name-collision"}
		if p.Other {
			caveats = []string{}
		}
		if p.Membership == "unknown" {
			caveats = append(caveats, "membership-unknown")
		}
		if s.Boot == nil {
			caveats = append(caveats, "identity-unknown")
			a.Unknown = true
		}
		if len(rid) >= 5 && rid[:5] == "user-" {
			caveats = append(caveats, "user-rule")
		}
		evidence := []result.Evidence{{RuleID: rid, SourceID: id, Fact: fact}}
		if detail.Container != nil {
			caveats = append(caveats, "container-hint")
		}
		if p.Membership == "in-run" || detail.Container != nil {
			evidence = append(evidence, result.Evidence{RuleID: rid, SourceID: id, Fact: "cgroup"})
		}
		if !addItem(result.Item{Kind: kind, Name: name, Evidence: evidence, Detail: result.Detail(detail), Caveats: caveats}) {
			a.Unknown = true
			continue
		}
		if !p.Other {
			s.Counts.Running++
			switch p.Membership {
			case "in-run":
				s.Counts.InRun++
			case "outside-run":
				s.Counts.Outside++
			default:
				s.Counts.Unknown++
			}
		}
	}
	for _, group := range []struct {
		kind, source, fact string
		files              []fileObservation
	}{{"program", "B", "path", m.Programs}, {"settings", "C", "settings-path", m.Settings}} {
		for _, f := range group.files {
			id := sourceIDs[group.source+":"+f.Path]
			if id == "" {
				continue
			}
			caveats := []string{"name-collision"}
			if group.kind == "settings" {
				caveats = []string{"settings-only"}
			}
			mt := f.Mtime
			if addItem(result.Item{Kind: group.kind, Name: f.Name, Evidence: []result.Evidence{{RuleID: f.RuleID, SourceID: id, Fact: group.fact}}, Detail: result.Detail(result.File{Path: result.Path(f.Path), Target: result.Path(f.Target), Mtime: &mt, Type: f.FileType}), Caveats: caveats}) {
				if group.kind == "program" {
					s.Counts.Installed++
				} else {
					s.Counts.Settings++
				}
			}
		}
	}
	for _, d := range catalog.Dependencies() {
		s.Rules = append(s.Rules, result.Rule{ID: d.ID, Name: d.Name, Origin: "catalog"})
	}
	for _, m := range projectMarkers {
		s.Rules = append(s.Rules, result.Rule{ID: m.id, Name: m.name, Origin: "catalog"})
	}

	for _, p := range f.Items {
		id := sourceIDs["F:"+p.Path]
		if id == "" {
			continue
		}
		fact := "dependency"
		if p.Dependency == nil {
			fact = "path"
		}
		if addItem(result.Item{Kind: "project", Name: p.Name, Evidence: []result.Evidence{{RuleID: p.ID, SourceID: id, Fact: fact}}, Detail: result.Detail(result.Project{Path: result.Path(p.Path), Dependency: p.Dependency}), Caveats: []string{"declaration-only"}}) {
			s.Counts.Project++
		}
	}
	for _, code := range f.Limits {
		s.Limits = appendUnique(s.Limits, code)
	}

	for _, client := range []string{"claude", "codex", "gemini"} {
		s.Rules = append(s.Rules, result.Rule{ID: "mcp-" + client, Name: client, Origin: "catalog"})
	}
	for _, r := range catalog.Rows() {
		if len(r.Programs) > 0 {
			name, _ := catalog.ObservedName(r.ID)
			s.Rules = append(s.Rules, result.Rule{ID: "unit-" + name, Name: name, Origin: "catalog"})
		}
	}

	for _, p := range d.Items {
		if id := sourceIDs["D:"+p.Path]; id != "" {
			if addItem(result.Item{Kind: "mcp_server", Name: p.Client, Evidence: []result.Evidence{{RuleID: p.RuleID, SourceID: id, Fact: "mcp-key"}}, Detail: result.Detail(mcpDetail(p)), Caveats: []string{"configured-only"}}) {
				s.Counts.MCP++
			}
		}
	}
	for _, p := range append(e.Items, system.Items...) {
		sourceKind := "E"
		if p.System {
			sourceKind = "system"
		}
		if id := sourceIDs[sourceKind+":"+p.Path]; id != "" {
			name, _ := catalog.ObservedName(p.Exec.Program)
			rid := "unit-" + name
			uid := o.Caller.UID
			detail := result.Unit{Path: result.Path(p.Path), UID: &uid, Program: result.Path(p.Exec.Program), Name: p.Name, Arguments: p.Exec.Arguments, Specifiers: p.Exec.Specifiers, Triggers: result.Path(p.Trigger), Enablement: p.Enablement}
			if o.Advanced {
				detail.UID = p.UID
			}
			kind, fact := "user_unit", "exec-start"
			if p.System {
				kind = "system_unit"
			}
			if p.Trigger != "" {
				kind, fact = "timer", "timer-unit"
			}
			if addItem(result.Item{Kind: kind, Name: name, Evidence: []result.Evidence{{RuleID: rid, SourceID: id, Fact: fact}}, Detail: result.Detail(detail), Caveats: []string{"configured-only", "name-collision"}}) {
				if p.System {
					s.Counts.SystemUnits++
				} else {
					s.Counts.Units++
				}
			}
		}
	}
	for _, name := range []string{"claude", "codex", "opencode", "gemini"} {
		if o.Advanced {
			s.Rules = append(s.Rules, result.Rule{ID: "cron-" + name, Name: name, Origin: "catalog"})
		}
	}
	for _, p := range cron.Items {
		id := sourceIDs["cron:"+p.Path]
		if id == "" {
			continue
		}
		name, _ := catalog.ObservedName(p.Program)
		if addItem(result.Item{Kind: "cron", Name: name, Evidence: []result.Evidence{{RuleID: "cron-" + name, SourceID: id, Fact: "cron-command"}}, Detail: result.Detail(result.Cron{Path: result.Path(p.Path), UID: p.UID, Program: result.Path(p.Program)}), Caveats: []string{"configured-only", "name-collision"}}) {
			s.Counts.Cron++
		}
	}
	if content.remaining <= 0 {
		s.Limits = appendUnique(s.Limits, "byte-limit")
	}
	if content.files >= content.maxFiles() {
		s.Limits = appendUnique(s.Limits, "file-limit")
	}
	for _, p := range s.Sources {
		if (p.Kind == "D" || p.Kind == "E" || p.Kind == "system" || p.Kind == "cron") && p.Reason == "limit" {
			s.Limits = appendUnique(s.Limits, "parse-limit")
		}
	}

	for _, code := range m.Limits {
		s.Limits = appendUnique(s.Limits, code)
	}
	if a.ByteLimited || budget.limited {
		s.Limits = appendUnique(s.Limits, "byte-limit")
	}
	if a.Limited {
		s.Limits = appendUnique(s.Limits, "source-limit")
	}
	if ctx.Err() != nil {
		// A accounts for its own interrupted reads. Later B-through-F deadlines cannot
		// turn a finished process check into unknown.
		s.Status = "partial"
		s.Limits = appendUnique(s.Limits, "deadline")
	}
	if o.Check {
		switch {
		case !a.Usable:
			s.Check = "unknown"
		case s.Counts.Outside > 0:
			s.Check = "outside-observed"
		case a.Unknown || limited["A"] || identity.OuterNamespace || identity.NamespaceUnknown || s.Boot == nil || s.Counts.Unknown > 0:
			s.Check = "unknown"
		case len(a.UnreadablePIDs) > 0 && !o.AllowUnreadablePrograms:
			s.Check = "unreadable-observed"
		case len(a.UnreadablePIDs) > 0:
			s.Check = "none-observed-allow-unreadable"
		default:
			s.Check = "none-observed"
		}
	}
	if !a.Usable {
		s.Status = "failed"
	}
	if dropFailed {
		s.AddFailure("result", "privilege")
	}
	s.Finished = time.Now().UTC()
	return Outcome{Snapshot: s, Home: identity.Home, GID: identity.GID}
}

func appendUnique(a []string, s string) []string {
	for _, v := range a {
		if v == s {
			return a
		}
	}
	return append(a, s)
}

func rawContainer(runtime, id string) *json.RawMessage {
	b := result.Detail(result.Container{Runtime: runtime, ID: id})
	return &b
}
