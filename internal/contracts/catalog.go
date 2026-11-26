// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/contractsrc"
	"github.com/attention-span-ai/tego/internal/ledger/runstart"
	"github.com/attention-span-ai/tego/internal/profilesrc"
	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Schema names the versioned list format under spec/contracts/v1.
const Schema = "tego.contracts.v1"

// Footer states the discovery boundary on every list, including an empty one.
const Footer = "These are the contracts Tego found in these registries and runs. Files outside them may be missing. Contracts in folders Tego has never seen are not included. Other users' contracts are not included without root. No other homes are searched."

// ContextNote describes the check, without claiming a launch or backend probe.
const ContextNote = "Checked offline with today's files and machine config. DNS is deferred; the contract's program is not executed and no backend is probed. PATH is the current caller's, not a recorded run's. Hash equality compares merged contract text, not enforcement or comments."

// Root is a discovery source, including one that could not be read.
type Root struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	State   string `json:"state"`
	Problem string `json:"problem,omitempty"`
}

// Diagnostic is a load, compile or discovery finding in the compiler's words.
type Diagnostic struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column,omitempty"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

// LastRun is what the newest record says, not a reconstruction of enforcement.
type LastRun struct {
	ID           string    `json:"id"`
	At           time.Time `json:"at"`
	Tier         string    `json:"tier"`
	ContractHash string    `json:"contract_hash,omitempty"`
	SameContract string    `json:"same_contract"` // yes, no, unknown, not-enforced
}

// Entry is one contract file, whether or not it compiles today.
type Entry struct {
	Name         string       `json:"name"`
	Path         string       `json:"path"`
	FoundIn      []string     `json:"found_in"`
	Aliases      []string     `json:"aliases,omitempty"`
	Cwd          string       `json:"cwd"`
	State        string       `json:"state"`
	Hash         string       `json:"contract_hash,omitempty"`
	Ambiguous    bool         `json:"ambiguous"`
	LastRun      *LastRun     `json:"last_run"`
	Diagnostics  []Diagnostic `json:"diagnostics"`
	table        *agent.RuleTable
	description  *Show
	data         []byte
	readErr      error
	expected     string
	owner        *int
	unknownOwner bool
}

// Catalog is the list response. Incomplete means discovery or a context was
// uncertain; a broken contract alone is a finding, not incomplete discovery.
type Catalog struct {
	// General is observation only; its problems never change standalone exit codes.
	General    *contractsrc.General `json:"general,omitempty"`
	Schema     string               `json:"schema"`
	Contracts  []Entry              `json:"contracts"`
	Roots      []Root               `json:"roots"`
	Issues     []Diagnostic         `json:"issues"`
	Incomplete bool                 `json:"incomplete"`
	Context    string               `json:"context"`
	Footer     string               `json:"footer"`
	machine    *config.Machine
}

// Options supplies today's compile context. Snapshot, when non-nil, is the
// caller's existing ledger view. The catalog never modifies it or Machine.
type Options struct {
	// General is an optional read-only source snapshot supplied by the view caller.
	General        *contractsrc.General
	Machine        *config.Machine
	Places         registry.Places
	Snapshot       *runstart.Snapshot
	PATH           string
	Tiers          []backend.Tier
	CompileContext CompileContext
	// KeepTableFor retains compiled state only for this name or path. Lists
	// release each table after checking, instead of keeping every expansion.
	KeepTableFor string
}

// Discover joins registry entries to contract sources and project roots known
// from runs in the selected ledger. Historical paths are never cleaned into a
// different kernel walk. A malformed source remains a visible finding.
func Discover(ctx context.Context, o Options) Catalog {
	ctx, closeSession := WithHelperSession(ctx)
	defer closeSession()
	return discover(ctx, o)
}

func discover(ctx context.Context, o Options) Catalog {
	c := Catalog{Schema: Schema, Contracts: []Entry{}, Roots: []Root{}, Issues: []Diagnostic{},
		Context: ContextNote, Footer: Footer, machine: o.Machine}
	if c.machine == nil {
		c.machine = config.Builtin()
	}
	if err := ctx.Err(); err != nil {
		c.issue("", "interrupted", err.Error())
		return c
	}
	if o.General != nil && o.General.State != "absent" {
		c.General = o.General
	}
	snap := o.Snapshot
	rootProblem := ""
	if snap == nil {
		var problems []error
		snap, problems = runstart.Load(ctx, c.machine.LedgerRoot.Value)
		for _, err := range problems {
			c.issue(c.machine.LedgerRoot.Value, "ledger-unreadable", err.Error())
			var pe *os.PathError
			if errors.As(err, &pe) && pe.Path == c.machine.LedgerRoot.Value {
				rootProblem = err.Error()
			}
		}
	}
	if err := ctx.Err(); err != nil {
		c.issue("", "interrupted", err.Error())
		return c
	}
	state := "present"
	fi, err := os.Stat(c.machine.LedgerRoot.Value)
	switch {
	case errors.Is(err, os.ErrNotExist):
		state = "absent"
	case err != nil:
		state, rootProblem = "unreadable", err.Error()
	case !fi.IsDir():
		state, rootProblem = "unreadable", "the ledger root is not a directory"
	case rootProblem != "":
		state = "unreadable"
	}
	if state == "unreadable" {
		c.Incomplete = true
	}
	c.Roots = append(c.Roots, Root{Kind: "ledger", Path: c.machine.LedgerRoot.Value, State: state, Problem: rootProblem})
	byPath := map[string]int{}
	roots := map[string]bool{}
	catalogCut := false
	retainedBytes := 0
	var checkedRegistry []listedEntry
	add := func(e Entry) {
		if i, ok := byPath[e.Path]; ok {
			if e.Path != c.Contracts[i].Path && !slices.Contains(c.Contracts[i].Aliases, e.Path) {
				c.Contracts[i].Aliases = append(c.Contracts[i].Aliases, e.Path)
			}
			for _, source := range e.FoundIn {
				if !slices.Contains(c.Contracts[i].FoundIn, source) {
					c.Contracts[i].FoundIn = append(c.Contracts[i].FoundIn, source)
				}
			}
			return
		}
		if len(c.Contracts) >= registry.MaxCatalogEntries {
			if !catalogCut {
				c.issue("", "catalog-bound", fmt.Sprintf("catalog exceeds %d contracts; some contracts are missing", registry.MaxCatalogEntries))
				catalogCut = true
			}
			return
		}
		if retainedBytes+len(e.data) > registry.MaxCatalogBytes {
			e.data = nil
			e.readErr = fmt.Errorf("catalog source bytes exceed %d; this contract was not checked", registry.MaxCatalogBytes)
			c.issue(e.Path, "catalog-byte-bound", e.readErr.Error())
		} else {
			retainedBytes += len(e.data)
		}
		byPath[e.Path] = len(c.Contracts)
		c.Contracts = append(c.Contracts, e)
	}
	project := func(dir string, user bool) {
		key := dir
		if roots[key] || catalogCut || ctx.Err() != nil {
			return
		}
		roots[key] = true
		p := o.Places
		p.Dir = dir
		if !user {
			p.User = ""
		}
		listed, projectErr := requestCheck(ctx, checkRequest{Operation: "registry", Places: p})
		es, rs := listed.Entries, listed.Roots
		if projectErr != nil {
			c.issue(dir, "registry-interrupted", projectErr.Error())
			c.Roots = append(c.Roots, Root{Kind: "registry", Path: dir, State: "unreadable", Problem: projectErr.Error()})
		}
		for _, r := range rs {
			root := Root{Kind: r.Kind, Path: r.Path, State: r.State}
			if r.Err != "" && r.State != "absent" {
				root.Problem = r.Err
				c.Incomplete = true
			}
			c.Roots = append(c.Roots, root)
		}
		for _, e := range es {
			if e.Err.Bound {
				c.issue(e.Path, "catalog-byte-bound", e.Err.Message)
			}
			alias := false
			for _, prior := range checkedRegistry {
				if e.Name == prior.Name && e.sameFile(prior) {
					if i, ok := byPath[prior.Path]; ok {
						byPath[e.Path] = i
						alias = true
						break
					}
				}
			}
			add(Entry{Name: e.Name, Path: e.Path, Cwd: dir, FoundIn: []string{e.Registry},
				Diagnostics: []Diagnostic{}, data: e.Data, readErr: e.Err.error(), expected: e.Name})
			if !alias {
				identity := e
				identity.Data = nil
				checkedRegistry = append(checkedRegistry, identity)
			}
		}
	}
	project(o.Places.Dir, true)
	if snap != nil {
		if snap.RunsCut || snap.Partial {
			c.issue(snap.Root, "ledger-incomplete", "the ledger view is bounded or incomplete; some contracts or newer runs may be missing")
		}
		// Do not depend on the caller ordering its snapshot.
		runs := slices.Clone(snap.Runs)
		slices.SortFunc(runs, func(a, b *runstart.Run) int {
			if n := b.Start.Compare(a.Start); n != 0 {
				return n
			}
			return strings.Compare(b.ID, a.ID)
		})
		for _, r := range runs {
			if ctx.Err() != nil {
				break
			}
			if r.Bad > 0 {
				c.issue(snap.Root, "record-invalid", fmt.Sprintf("run %s has %d unreadable record lines", r.ID, r.Bad))
			}
			if r.UIDKnown && o.Places.UID != 0 && r.UID != o.Places.UID {
				c.issue(snap.Root, "other-owner", fmt.Sprintf("run %s belongs to uid %d; its sources were not opened", r.ID, r.UID))
				continue
			}
			if r.Cwd != "" {
				if safePath(r.Cwd) {
					before := len(c.Contracts)
					project(r.Cwd, false)
					for i := before; i < len(c.Contracts); i++ {
						owner := r.UID
						c.Contracts[i].owner = &owner
						c.Contracts[i].unknownOwner = !r.UIDKnown
					}
				} else {
					c.issue(r.Cwd, "record-path", "recorded project root is not a plain absolute path; it was not opened")
				}
			}
			if r.Contract == "" {
				continue
			}
			if _, ok := byPath[r.Contract]; !ok {
				owner := r.UID
				add(Entry{Name: recordedName(r.Agent), Path: r.Contract, Cwd: r.Cwd, FoundIn: []string{"run"}, Diagnostics: []Diagnostic{}, owner: &owner, unknownOwner: !r.UIDKnown})
			}
			i, exists := byPath[r.Contract]
			if !exists {
				continue
			}
			e := &c.Contracts[i]
			if !slices.Contains(e.FoundIn, "run") {
				e.FoundIn = append(e.FoundIn, "run")
			}
			if e.LastRun == nil {
				e.Cwd = r.Cwd
				e.LastRun = lastRun(r.ID, r.Start, r.Tier, r.ContractHash)
			}
		}
	}
	c.checkEntries(ctx, o)
	names := map[string]int{}
	for _, e := range c.Contracts {
		names[e.Name]++
	}
	for i := range c.Contracts {
		c.Contracts[i].Ambiguous = names[c.Contracts[i].Name] > 1
	}
	slices.SortFunc(c.Contracts, func(a, b Entry) int {
		if n := strings.Compare(a.Name, b.Name); n != 0 {
			return n
		}
		return strings.Compare(a.Path, b.Path)
	})
	if ctx.Err() != nil {
		c.issue("", "interrupted", ctx.Err().Error())
	}
	return c
}

func (c *Catalog) checkEntries(ctx context.Context, o Options) {
	kept := -1
	duplicateTable := false
	for i := range c.Contracts {
		if err := ctx.Err(); err != nil {
			c.Contracts[i].interrupted(err)
			c.Incomplete = true
		} else {
			c.check(ctx, &c.Contracts[i], o)
		}
		if c.Contracts[i].table != nil || c.Contracts[i].description != nil {
			if kept >= 0 {
				c.Contracts[kept].table = nil
				c.Contracts[kept].description = nil
				duplicateTable = true
			}
			if duplicateTable {
				c.Contracts[i].table = nil
				c.Contracts[i].description = nil
			} else {
				kept = i
			}
		}
		c.Contracts[i].data = nil
		c.Contracts[i].readErr = nil
	}
}

// safePath rejects ambiguous historical spellings rather than cleaning a link/..
// into a different file. Explicit paths are placed by the CLI before this layer.
func safePath(path string) bool {
	return filepath.IsAbs(path) && !strings.ContainsRune(path, 0) && filepath.Clean(path) == path
}

func (c *Catalog) issue(file, code, msg string) {
	c.Incomplete = true
	c.Issues = append(c.Issues, Diagnostic{File: file, Code: code, Message: msg, Severity: agent.SeverityError})
}

// A reply owns its state. A timed-out helper cannot mutate the returned catalog.
func (c *Catalog) check(ctx context.Context, e *Entry, o Options) {
	r, err := requestCheck(ctx, checkRequest{Operation: "source", Entry: *e, Data: e.data,
		ReadError: packError(e.readErr), Expected: e.expected, Owner: e.owner, UnknownOwner: e.unknownOwner,
		machine: c.machine, Places: o.Places, PATH: o.PATH, Tiers: o.Tiers,
		CompileContext: o.CompileContext, KeepTableFor: o.KeepTableFor})
	if err != nil {
		e.interrupted(err)
		c.Incomplete = true
		return
	}
	*e = r.Entry
	e.description = r.Show
	c.Incomplete = c.Incomplete || r.Incomplete
}

func (c *Catalog) checkSource(ctx context.Context, e *Entry, o Options, read sourceReader) {
	// A check of a local location is given the local bound, and is interrupted in the disk's words (location.go).
	bound := CheckTimeout
	if localCheck(ctx) {
		bound = localCap()
	}
	ctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	defer func() {
		if err := ctx.Err(); err != nil {
			if localCheck(ctx) && errors.Is(err, context.DeadlineExceeded) {
				err = &unavailableError{err: err, fault: faultDisk}
			}
			e.interrupted(err)
			c.Incomplete = true
		}
	}()
	if ctx.Err() != nil {
		return
	}
	e.State = "invalid"
	if e.Name == "" {
		e.Name = strings.TrimSuffix(filepath.Base(e.Path), ".yaml")
	}
	if e.LastRun != nil && e.LastRun.Tier == string(backend.TierObserve) {
		e.LastRun.SameContract = "not-enforced"
	}
	fail := func(code string, err error) {
		e.Diagnostics = append(e.Diagnostics, Diagnostic{File: e.Path, Code: code, Message: err.Error(), Severity: agent.SeverityError})
	}
	if !safePath(e.Path) {
		e.State = "unsafe"
		fail("source-path", errors.New("source is not a plain absolute path; it was not opened"))
		return
	}
	data, err := e.data, e.readErr
	if data == nil && err == nil {
		caller := CallerContext(ctx)
		g := rulefile.Guard{LedgerRoot: c.machine.LedgerRoot.Value, Refuse: append([]string{}, caller.GuardHomes...)}
		g.Refuse = append(g.Refuse, o.Places.Own...)
		data, err = read(ctx, e.Path, g)
	}
	if err != nil {
		if errors.Is(err, syscall.EIO) || errors.Is(err, syscall.ENOTCONN) {
			e.interrupted(err)
			c.Incomplete = true
			return
		}
		e.State = "unreadable"
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			e.State = "missing"
		}
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, config.ErrUntrusted) || errors.Is(err, rulefile.ErrGuard) {
			e.State = "unsafe"
		}
		fail("source-unreadable", err)
		return
	}
	if ctx.Err() != nil {
		return
	}
	contract, ds, err := agent.LoadBytes(e.Path, data, profilesrc.Chain(c.machine, *CallerContext(ctx)))
	e.addDiagnostics(ds)
	if err != nil {
		if !agent.HasErrors(ds) {
			fail(agent.CodeSchema, err)
		}
		return
	}
	if ctx.Err() != nil {
		return
	}
	e.Name = contract.Name
	canonical, err := contract.Canonical()
	if err != nil {
		fail(agent.CodeSchema, err)
		return
	}
	h := sha256.Sum256(canonical)
	e.Hash = hex.EncodeToString(h[:])
	if e.LastRun != nil {
		switch {
		case e.LastRun.Tier == string(backend.TierObserve):
			e.LastRun.SameContract = "not-enforced"
		case (e.LastRun.Tier == string(backend.TierLandlock) || e.LastRun.Tier == string(backend.TierCgroup) || e.LastRun.Tier == string(backend.TierBPFLSM)) && validHash(e.LastRun.ContractHash):
			e.LastRun.SameContract = "no"
			if e.Hash == e.LastRun.ContractHash {
				e.LastRun.SameContract = "yes"
			}
		}
	}
	if e.expected != "" && (!registry.IsName(e.expected) || contract.Name != e.expected) {
		fail(registry.CodeEntry, fmt.Errorf("registry entry %q holds name %q; rename the entry or correct its name field", e.expected, contract.Name))
		return
	}
	if ctx.Err() != nil {
		return
	}
	if !safePath(e.Cwd) {
		e.State = "incomplete"
		fail("compile-context", errors.New("no safe recorded or selected working directory; compilation is incomplete"))
		c.Incomplete = true
		return
	}
	if fi, err := statCwd(e.Cwd); err != nil || !fi.IsDir() {
		if errors.Is(err, syscall.EIO) || errors.Is(err, syscall.ENOTCONN) {
			e.interrupted(err)
			c.Incomplete = true
			return
		}
		e.State = "incomplete"
		fail("compile-context", fmt.Errorf("working directory %s is missing, unreadable or not a directory", e.Cwd))
		c.Incomplete = true
		return
	}
	if ctx.Err() != nil {
		return
	}
	if e.unknownOwner || (e.owner != nil && *e.owner != o.Places.UID) {
		e.State = "incomplete"
		fail("compile-context", errors.New("the recorded owner's home and machine context are not selected; compilation is incomplete"))
		c.Incomplete = true
		return
	}
	o.CompileContext.Caller = CallerContext(ctx)
	opts := o.CompileContext.options()
	opts = append(opts, agent.WithContext(ctx), agent.WithCwd(e.Cwd), agent.WithHome(c.machine.Home), agent.WithPATH(o.PATH), agent.Offline(), agent.WithResolver(noDNS{}))
	if len(o.Tiers) > 0 {
		opts = append(opts, agent.WithTiers(o.Tiers...))
	}
	rt, ds, err := agent.Compile(contract, c.machine, opts...)
	e.addDiagnostics(ds)
	if err != nil {
		if !agent.HasErrors(ds) {
			fail("compile", err)
		}
		return
	}
	e.State = "compiles"
	if o.KeepTableFor == e.Path || o.KeepTableFor == e.Name {
		e.table = rt
	}
}

// These operations run only inside a filesystem helper.
var catalogRegistry = registry.Places.CatalogContext
var statCwd = os.Stat

// CheckTimeout bounds the caller's wait for a contract check or registry scan.
// A worker blocked in the kernel may remain until its mount answers. 5 s, times raceScale in a race build.
const CheckTimeout = 5 * time.Second * raceScale

type sourceReader func(context.Context, string, rulefile.Guard) ([]byte, error)

func (e *Entry) interrupted(err error) {
	err = CheckUnavailable(err)
	e.State = "incomplete"
	e.table = nil
	e.description = nil
	e.Diagnostics = append(e.Diagnostics, Diagnostic{File: e.Path, Code: "check-interrupted", Message: err.Error(), Severity: agent.SeverityError})
}

func readSource(ctx context.Context, path string, g rulefile.Guard) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := rulefile.Read(path, g)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.Text, nil
}

func validHash(h string) bool { return len(h) == 64 && strings.Trim(h, "0123456789abcdef") == "" }

func (e *Entry) addDiagnostics(ds []agent.Diagnostic) {
	for _, d := range ds {
		e.Diagnostics = append(e.Diagnostics, Diagnostic{File: d.File, Line: d.Line, Column: d.Col, Code: d.Code, Message: d.Message, Severity: d.Severity})
	}
}

// ExitCode follows the CLI convention: unsafe/incomplete input 125, a contract
// finding or ambiguous name 1, otherwise 0. Missing registry roots are normal.
func (c Catalog) ExitCode() int {
	if c.Incomplete {
		return identity.ExitError
	}
	code := identity.ExitOK
	for _, e := range c.Contracts {
		if e.State == "unreadable" || e.State == "unsafe" || e.State == "incomplete" {
			return identity.ExitError
		}
		if e.State != "compiles" || e.Ambiguous {
			code = identity.ExitFinding
		}
	}
	return code
}

// Inspect checks an explicitly selected source without searching any other folder.
func Inspect(ctx context.Context, path string, o Options) Catalog {
	ctx, closeSession := WithHelperSession(ctx)
	defer closeSession()
	return inspect(ctx, path, o)
}

func inspect(ctx context.Context, path string, o Options) Catalog {
	m := o.Machine
	if m == nil {
		m = config.Builtin()
	}
	c := Catalog{Schema: Schema, Contracts: []Entry{{Path: path, Cwd: o.Places.Dir, FoundIn: []string{"explicit"}, Diagnostics: []Diagnostic{}}},
		Roots: []Root{}, Issues: []Diagnostic{}, Context: ContextNote, Footer: Footer, machine: m}
	o.KeepTableFor = path
	c.check(ctx, &c.Contracts[0], o)
	if err := ctx.Err(); err != nil {
		c.issue("", "interrupted", err.Error())
	}
	return c
}
