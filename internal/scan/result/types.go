// SPDX-License-Identifier: Apache-2.0

package result

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// MaxBytes bounds both encoded snapshots and untrusted saved input.
const MaxBytes = 1 << 20

// UnreadableProgramsWarning states the uncertainty behind unreadable counts.
const UnreadableProgramsWarning = "Tego cannot tell whether these are agents; any program can make itself unreadable."

// Snapshot is the tego.scan/1 wire object. All slices are present, even when empty.
type Snapshot struct {
	Schema                    string    `json:"schema"`
	Tego                      string    `json:"tego"`
	Catalog                   string    `json:"catalog"`
	Started                   time.Time `json:"started_at"`
	Finished                  time.Time `json:"finished_at"`
	Boot                      *string   `json:"boot_id"`
	Mode                      string    `json:"mode"`
	As                        Identity  `json:"as"`
	Project                   *string   `json:"project"`
	Status                    string    `json:"status"`
	Check                     string    `json:"check"`
	Counts                    Counts    `json:"counts"`
	UnreadableProgramPIDs     []int     `json:"unreadable_program_pids"`
	UnreadableProgramsWarning string    `json:"unreadable_programs_warning"`
	OtherListed               bool      `json:"other_listed"`
	Rules                     []Rule    `json:"rules"`
	Items                     []Item    `json:"items"`
	Sources                   []Source  `json:"sources"`
	Exclusions                []string  `json:"not_looked_at"`
	Limits                    []string  `json:"limits"`
}

// Identity describes the collector and recipient, never authentication of a cache.
type Identity struct {
	UID       uint32 `json:"uid"`
	Recipient uint32 `json:"recipient_uid"`
	Root      bool   `json:"root"`
}

// Counts keeps process findings separate from metadata and unknown-purpose programs.
type Counts struct {
	Running            int `json:"running"`
	InRun              int `json:"in_run"`
	Outside            int `json:"outside_run"`
	Unknown            int `json:"membership_unknown"`
	Installed          int `json:"installed"`
	Settings           int `json:"settings"`
	Project            int `json:"project"`
	MCP                int `json:"mcp_servers,omitempty"`
	Units              int `json:"user_units,omitempty"`
	SystemUnits        int `json:"system_units,omitempty"`
	Cron               int `json:"cron_entries,omitempty"`
	Other              int `json:"other"`
	Exited             int `json:"exited_during_scan"`
	KernelThreads      int `json:"kernel_threads"`
	UnreadablePrograms int `json:"unreadable_programs"`
}

// Rule contains only a closed catalog or numbered custom identifier.
type Rule struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Origin string `json:"origin"`
}

// Source accounts for each attempted input, including failed and deferred reads.
type Source struct {
	// WritableGroup names only the account group behind a mode refusal.
	WritableGroup *string `json:"writable_group,omitempty"`
	// GroupEvidence is a closed local-evidence refusal code for WritableGroup.
	GroupEvidence string `json:"group_evidence,omitempty"`
	// AccountRepair is bounded printable account-placement repair text.
	AccountRepair string  `json:"account_repair,omitempty"`
	ID            string  `json:"id"`
	Kind          string  `json:"kind"`
	Locator       *string `json:"locator"`
	State         string  `json:"state"`
	Read          int     `json:"read"`
	NotRead       int     `json:"not_read"`
	Reason        string  `json:"reason"`
}

// Evidence refers to a rule and an observed source, never a copied match token.
type Evidence struct {
	RuleID   string `json:"rule_id"`
	SourceID string `json:"source_id"`
	Fact     string `json:"fact"`
}

// Item carries one typed detail object. Decode rejects unsupported future kinds.
type Item struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Name     string          `json:"name"`
	Evidence []Evidence      `json:"evidence"`
	Detail   json.RawMessage `json:"detail"`
	Caveats  []string        `json:"caveats"`
}

// Process is a numeric process identity and typed paths. Membership is a cgroup fact.
// Cwd is never collected for accounts other than the advanced recipient.
type Process struct {
	PID        int              `json:"pid"`
	PPID       int              `json:"ppid"`
	UID        uint32           `json:"uid"`
	Start      string           `json:"start_ticks"`
	Exe        *string          `json:"exe"`
	Cwd        *string          `json:"cwd"`
	Membership string           `json:"membership"`
	RunID      *string          `json:"run_id"`
	Unit       *string          `json:"unit"`
	Container  *json.RawMessage `json:"container"`
}

// Container records a cgroup suggestion, never a runtime-confirmed container.
type Container struct {
	Runtime string `json:"runtime"`
	ID      string `json:"id"`
}

// File holds metadata only, with no file contents.
type File struct {
	Path   *string    `json:"path"`
	Target *string    `json:"target"`
	Mtime  *time.Time `json:"mtime"`
	Type   string     `json:"file_type"`
}

// Project holds only a typed manifest path and a closed dependency id.
type Project struct {
	Path       *string `json:"path"`
	Dependency *string `json:"dependency"`
}

// Config retains a server name, catalog program id and count, never launch input.
type Config struct {
	Path      *string `json:"path"`
	Client    string  `json:"client"`
	Scope     string  `json:"scope"`
	Transport string  `json:"transport"`
	Program   *string `json:"program"`
	Host      *string `json:"host"`
	Server    string  `json:"server"`
	Arguments int     `json:"arguments"`
}

// Unit records configured startup, never current process membership.
type Unit struct {
	Path       *string `json:"path"`
	UID        *uint32 `json:"uid"`
	Program    *string `json:"program"`
	Triggers   *string `json:"triggers"`
	Enablement *bool   `json:"enablement_link"`
	Name       string  `json:"unit"`
	Arguments  int     `json:"arguments"`
	Specifiers bool    `json:"specifiers_unexpanded"`
}

// Cron records configured startup, with no command, schedule or environment.
type Cron struct {
	Path    *string `json:"path"`
	UID     *uint32 `json:"uid"`
	Program *string `json:"program"`
}

// Cron returns checked configured-cron metadata.
func (i Item) Cron() Cron { var v Cron; _ = json.Unmarshal(i.Detail, &v); return v }

// Config returns checked configured-server metadata.
func (i Item) Config() Config { var v Config; _ = json.Unmarshal(i.Detail, &v); return v }

// Unit returns checked configured-unit metadata.
func (i Item) Unit() Unit { var v Unit; _ = json.Unmarshal(i.Detail, &v); return v }

// Project returns a checked declaration or metadata hint.
func (i Item) Project() Project { var p Project; _ = json.Unmarshal(i.Detail, &p); return p }

// Path returns null for unavailable metadata. Validation checks all nonempty paths.
func Path(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// CheckedPath admits a path only when the result contract can retain it. It is
// used for optional locators so invalid input cannot erase other observations.
func CheckedPath(s string) *string {
	p := Path(s)
	if !validPath(p) {
		return nil
	}
	return p
}

// Detail encodes one of the typed detail structures.
func Detail(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

// Process returns the checked process detail of a process item.
func (i Item) Process() Process { var p Process; _ = json.Unmarshal(i.Detail, &p); return p }

// File returns the checked file detail of a metadata item.
func (i Item) File() File { var f File; _ = json.Unmarshal(i.Detail, &f); return f }

// MembershipWords requires a live record check supplied by the CLI at this scan's
// finish time. Saved membership alone can never supply that check.
func MembershipWords(p Process, live map[string]bool) string {
	switch p.Membership {
	case "in-run":
		if p.RunID != nil {
			if live[*p.RunID] {
				return "in Tego run " + *p.RunID
			}
			return "in a cgroup named for run " + *p.RunID + "; could not be checked against the record"
		}
	case "outside-run":
		return "outside a Tego run"
	}
	return "run membership unknown"
}

// ExitCode implements ADR 0145's priority table; check mode never saves.
func (s Snapshot) ExitCode() int {
	if s.Status == "failed" {
		return identity.ExitError
	}
	switch s.Check {
	case "outside-observed":
		return identity.ExitFinding
	case "unknown":
		return identity.ExitError
	case "unreadable-observed":
		return identity.ExitScanUnreadable
	}
	return identity.ExitOK
}

// New returns a failure-safe empty object, with always-present exclusions.
func New(now time.Time, uid uint32, version string) Snapshot {
	return Snapshot{Schema: "tego.scan/1", Tego: version, Catalog: "c3", Started: now.UTC(), Finished: now.UTC(), Mode: "basic", As: Identity{UID: uid, Recipient: uid, Root: uid == 0}, Status: "failed", Check: "not-requested", Rules: []Rule{}, Items: []Item{}, Sources: []Source{}, UnreadableProgramPIDs: []int{}, UnreadableProgramsWarning: UnreadableProgramsWarning, Limits: []string{}, Exclusions: []string{"other-users", "other-user-settings", "system-units", "containers-unattributed", "unknown-formats", "unresolved-units", "project-parents", "project-children", "project-alternates", "project-includes", "unreadable-processes", "unknown-owners", "unknown-names", "libraries", "remote-agents", "between-scans", "environment", "memory", "source-code", "network"}}
}

// NewAdvanced retains the requested collector and recipient for refusal objects.
// A successful collection requires initial-namespace root before any source read.
func NewAdvanced(now time.Time, collector, recipient uint32, version string) Snapshot {
	s := New(now, collector, version)
	s.Catalog, s.Mode, s.As.Recipient = "c4", "advanced", recipient
	s.Exclusions = slices.DeleteFunc(s.Exclusions, func(code string) bool {
		return code == "other-users" || code == "system-units" || code == "containers-unattributed"
	})
	s.Exclusions = append(s.Exclusions, "unresolved-cron", "container-patterns", "nonlocal-homes")
	return s
}

// AddFailure appends a fixed diagnostic without keeping raw errors or input.
func (s *Snapshot) AddFailure(kind, reason string) {
	s.Status = "failed"
	if s.Check != "not-requested" {
		s.Check = "unknown"
	}
	s.Sources = append(s.Sources, Source{ID: fmt.Sprintf("source-%d", len(s.Sources)+1), Kind: kind, State: "not-read", NotRead: 1, Reason: reason})
}
