// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Diagnostic codes: the closed set every Load and Compile finding uses
// (spec/identity/RUN-IDENTITY.md "Messages"). Refusal reasons are
// record.Reason values and are never mixed with these.
const (
	CodeSchema             = "schema"
	CodeNotYetSupported    = "not-yet-supported"
	CodeExtendsNotFound    = "extends-not-found"
	CodeExtendsCycle       = "extends-cycle"
	CodeExtendsTooDeep     = "extends-too-deep"
	CodePathMissing        = "path-missing"
	CodeExecNotOnPath      = "exec-not-on-path"
	CodeHostUnresolvable   = "host-unresolvable"
	CodeLimitAboveMachine  = "limit-above-machine"
	CodeLimitBelowStart    = "limit-below-start"
	CodeContradiction      = "contradiction"
	CodeEnvRuntimeReserved = "env-runtime-reserved"
	CodeRedundantRule      = "redundant-rule"
	CodeMalformedELF       = "malformed-elf"
	CodeModelDirectBypass  = "model-direct-bypass"
	CodeExecWritable       = "exec-writable"
	CodeKernelFSWrite      = "kernel-fs-write"
	CodeDenyReadDisabled   = "deny-read-disabled"
	CodeMountWarning       = "mount"
	CodeUnenforced         = "unenforced"
	CodeProxyEnv           = "proxy-env"
	CodeIOUring            = "io-uring"
	CodeInterpreter        = "interpreter"
	CodeGlobNoMatch        = "glob-no-match"
	CodeLoaderRefused      = "loader-refused"
	CodeLandlockTopology   = "landlock-topology"
	CodeResolvedDenied     = "resolved-denied"
	CodeHostSockets        = "host-sockets"
	CodeLedgerReadable     = "ledger-readable"
	CodeExecMap            = "exec-map"
	// CodeExecRule is an exec command pattern the contract cannot hold (an error: syntax, bounds, shell operators, a
	// path in a deny or ask command word, a directory with words, an unquoted path with spaces, a deny or ask entry
	// matching the run's own command), or one it holds with a finding (a warning: $ or a backtick in a word, an
	// empty deny-list section, a deny entry matching an MCP server's command). ADR 0048 (9).
	CodeExecRule = "exec-rule"
	// CodeExecRuleCoverage warns where command rules cover less than they read as: deny-list mode (beside fs.write a
	// copy written to disk; with or without it a copy run from a memfd or a deleted file, and a program's file mapped
	// into a process), a constrained tool an implicit grant shadows, an allow entry naming options (required, not
	// whitelisted).
	CodeExecRuleCoverage = "exec-rule-coverage"
	// CodeStallReadsUnseen warns that limits.stall_after counts no read where the run lands at tier landlock under
	// record: summary or off, so an agent that only reads is ended as stalled (SEMANTICS §8).
	CodeStallReadsUnseen = "stall-reads-unseen"
	// CodeExecProc is an exec entry (command, mcp command, exec.allow) that is or leads through a /proc path, which
	// names a file relative to the process that opens it: /proc/self/exe resolves at compile to tego's own
	// executable (agent-contract.md R8a). An error.
	CodeExecProc = "exec-proc"
	// CodeProfileCannotLoosen warns at a profile's line that writes a value a stricter key marks loosening: only
	// the top-level contract may loosen it, so the profile's value is ignored (agent-contract R5, ADR 0065).
	CodeProfileCannotLoosen = "profile-cannot-loosen"
	// CodeHeldReads says a run's read opens are held (fs.reads, ADR 0069): which deny_read target inside a write
	// entry made them so, the cost per read open, and what held reads do not refuse.
	CodeHeldReads = "held-reads"
	// CodeExtendsConflict is a contract-wins key two parents of one extends list set to different values, which the
	// file naming the list does not set: an error at both parents' lines (agent-contract R5, ADR 0065 D4, ADR 0066).
	CodeExtendsConflict = "extends-conflict"
	// CodeShadowedBuiltin is a profiles-directory file under the reserved tego/ namespace that an extends name
	// would have read: names there resolve only to built-in profiles, so the file is never read, and the extends
	// is an error until the file is moved (ADR 0066 D2).
	CodeShadowedBuiltin = "shadowed-builtin"
	// CodeWallHardCap is the note on a contract that sets limits.wall and no stall_after: wall ends the run at that mark whatever the
	// agent or the person is doing, which an interactive session usually wants stall_after for (G7). Informational.
	CodeWallHardCap = "wall-hard-cap"
	// CodeRecordOff is the note on a contract whose own record: off, or a profile's it extends, is the run's record
	// mode: the ledger keeps the run's refusals and no exec or allowed action. What the author wrote, weakening no
	// rule, so it is informational: compile prints it, a run only under -v, and the run's end says record off.
	CodeRecordOff = "record-off"
	// CodeSecretEnv warns that a contract with no env.pass hands the agent the launcher's whole environment and that
	// it holds variables whose names look like credentials, naming them and never their values. A warning: no
	// variable is removed (SEMANTICS §9, ADR 0067).
	CodeSecretEnv = "secret-env"
	// CodePathShadow warns that a write entry covers a PATH directory searched before tego, where a file the agent puts
	// runs in tego's place the next time a person types its name (WithOwnBinaries). A warning: the directory is often
	// the project's own, an activated .venv/bin, and holds nothing of tego's.
	CodePathShadow = "path-shadow"

	// The live: section's findings (ADR 0125), all errors but CodeLiveFenceLocal.

	// CodeLiveMode is a live.mode other than locked or adjustable.
	CodeLiveMode = "live-mode"
	// CodeLiveLockedFence is a fence under live.mode: locked, which has none.
	CodeLiveLockedFence = "live-locked-fence"
	// CodeLiveInProfile is a live: key in a profile: only the top-level contract's counts.
	CodeLiveInProfile = "live-in-profile"
	// CodeLiveTier is Adjustable where the run is held at tier landlock, or in an --observe run (LiveTierCheck).
	CodeLiveTier = "live-tier"
	// CodeLiveTooMany is a fence of more than MaxLiveFence entries.
	CodeLiveTooMany = "live-too-many"
	// CodeLiveFenceAllowed is a fence entry the contract already allows.
	CodeLiveFenceAllowed = "live-fence-allowed"
	// CodeLiveFenceWrite is a read entry at, under or above an fs.write or fs.ask entry.
	CodeLiveFenceWrite = "live-fence-write"
	// CodeLiveFenceEntry is a fence entry Tego cannot hold race-free or that would reach its own state, a built-in
	// refusal or another deny_read entry, or one malformed for its kind.
	CodeLiveFenceEntry = "live-fence-entry"
	// CodeLiveReadsDirect is a read entry under fs.reads: direct; a read fence entry needs held reads.
	CodeLiveReadsDirect = "live-reads-direct"
	// CodeLiveFenceLocal warns at a loopback or link-local destination, or localhost.
	CodeLiveFenceLocal = "live-fence-local"
)

// Diagnostic severities.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
)

// Diagnostic is one Load or Compile finding, rendered as
// file:line[:col]: message [code]; Fix is printed by the CLI on the next line.
type Diagnostic struct {
	File     string
	Line     int
	Col      int
	Code     string
	Message  string
	Fix      string
	Severity string // error | warning
	// Tier is the tier the finding holds in, when it does not hold in every tier: a deny_read Landlock cannot
	// enforce, a setting tier landlock leaves without effect. "" is a finding about every tier. Compile
	// reports such a finding when the table can land at that tier (RuleTable.Reach), and `tego run`, which
	// learns its tier only after compiling, prints it once the run has that tier (ADR 0019). A finding that holds
	// in a few tiers, and in no other, names the first here and the rest in Tiers (ForTier reads them all).
	Tier backend.Tier

	// also are the tiers past Tier the finding holds in (only, Tiers).
	also []backend.Tier

	// note marks a warning that only says how a rule the contract wrote applies and enforces nothing less than the
	// contract wrote (Informational).
	note bool

	// overlap marks the R10 contradiction so firstError can wrap ErrContractOverlap.
	overlap bool
}

// Error renders file:line[:col]: message [code]; :col is omitted when Col is 0
// and file:line: is omitted when Line is 0 (a finding with no source position).
func (d Diagnostic) Error() string {
	s := ""
	switch {
	case d.Line > 0 && d.Col > 0:
		s = d.File + ":" + strconv.Itoa(d.Line) + ":" + strconv.Itoa(d.Col) + ": "
	case d.Line > 0:
		s = d.File + ":" + strconv.Itoa(d.Line) + ": "
	case d.File != "":
		s = d.File + ": "
	}
	return s + d.Message + " [" + d.Code + "]"
}

// Informational reports whether the diagnostic is a note and not a warning about the contract's own rules: it says how
// a rule applies (a path that is a mount point, the cost of held reads) or that a rule changes nothing (redundant),
// and no rule it names is enforced less than the contract wrote. `tego run` leaves such a note out of its start
// unless asked for every one (-v), and `tego compile` always prints it. An error is never informational.
func (d Diagnostic) Informational() bool {
	return !d.IsError() && (d.note || d.Code == CodeHeldReads || d.Code == CodeRedundantRule)
}

// IsError reports whether the diagnostic blocks the run.
func (d Diagnostic) IsError() bool { return d.Severity == SeverityError }

// Sentinel errors. The error chain is the Go-idiomatic channel; Diagnostic.Code
// is the machine-readable one.
var (
	// ErrInvalidContract wraps the first error diagnostic of Load or Compile.
	ErrInvalidContract = errors.New("invalid contract")
	// ErrProfileNotFound is wrapped when an extends: name cannot be resolved.
	ErrProfileNotFound = errors.New("profile not found")
	// ErrContractOverlap is wrapped when a write entry contains the run
	// directory or the contract file (R10), so the CLI can errors.Is it.
	ErrContractOverlap = errors.New("write entry contains the run directory or the contract file")
	// ErrTooLarge is wrapped when a contract or profile exceeds MaxContractSize.
	ErrTooLarge = errors.New("contract exceeds 1MiB")
	// ErrNotAFile is wrapped when a contract, profile or test table is neither a regular file nor a
	// pipe.
	ErrNotAFile = errors.New("not a regular file or a pipe")
)

// HasErrors reports whether any diagnostic is an error.
func HasErrors(ds []Diagnostic) bool {
	for _, d := range ds {
		if d.IsError() {
			return true
		}
	}
	return false
}

// SortDiagnostics orders diagnostics by file (the top-level contract first),
// line, column, code and message, so output is deterministic.
func SortDiagnostics(ds []Diagnostic, topFile string) {
	sort.SliceStable(ds, func(i, j int) bool {
		a, b := ds[i], ds[j]
		if (a.File == topFile) != (b.File == topFile) {
			return a.File == topFile
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Col != b.Col {
			return a.Col < b.Col
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Message < b.Message
	})
}

// WriteDiagnostics writes one line per diagnostic in Error() form, followed by
// an indented "fix: ..." line when a Fix is set. It is the shared renderer for
// the CLI and the golden tests; this package never prints on its own.
func WriteDiagnostics(w io.Writer, ds []Diagnostic) error {
	for _, d := range ds {
		if _, err := fmt.Fprintf(w, "%s: %s\n", d.Severity, record.Printable(d.Error())); err != nil {
			return err
		}
		if d.Fix != "" {
			if _, err := fmt.Fprintf(w, "  fix: %s\n", record.Printable(d.Fix)); err != nil {
				return err
			}
		}
	}
	return nil
}

// firstError returns ErrInvalidContract wrapping the first error diagnostic,
// or nil when every diagnostic is a warning.
func firstError(ds []Diagnostic) error {
	for _, d := range ds {
		if d.IsError() {
			if d.Code == CodeContradiction && d.overlap {
				return fmt.Errorf("%w: %w: %w", ErrInvalidContract, ErrContractOverlap, d)
			}
			if d.Code == CodeExtendsNotFound {
				return fmt.Errorf("%w: %w: %w", ErrInvalidContract, ErrProfileNotFound, d)
			}
			return fmt.Errorf("%w: %w", ErrInvalidContract, d)
		}
	}
	return nil
}

// diags collects diagnostics during Load and Compile.
type diags struct {
	list []Diagnostic
}

func (ds *diags) errorf(p Pos, code, format string, args ...any) *Diagnostic {
	return ds.at(p, code, SeverityError, fmt.Sprintf(format, args...))
}

func (ds *diags) warnf(p Pos, code, format string, args ...any) *Diagnostic {
	return ds.at(p, code, SeverityWarning, fmt.Sprintf(format, args...))
}

func (ds *diags) at(p Pos, code, sev, msg string) *Diagnostic {
	ds.list = append(ds.list, Diagnostic{File: p.File, Line: p.Line, Col: p.Col, Code: code, Message: msg, Severity: sev})
	return &ds.list[len(ds.list)-1]
}

// fix attaches a Fix line to the diagnostic just added.
func (d *Diagnostic) fix(format string, args ...any) *Diagnostic {
	d.Fix = fmt.Sprintf(format, args...)
	return d
}

// info marks the diagnostic just added as a note (Informational). It ends a chain.
func (d *Diagnostic) info() { d.note = true }

// only marks the diagnostic just added as holding in the tiers ts alone (Diagnostic.Tier, Tiers), at least one.
// It ends a chain.
func (d *Diagnostic) only(ts ...backend.Tier) {
	d.Tier, d.also = ts[0], slices.Clone(ts[1:])
}

// Tiers is every tier the finding holds in when it does not hold in every tier (Tier first), nil for a finding
// about every tier.
func (d Diagnostic) Tiers() []backend.Tier {
	if d.Tier == "" {
		return nil
	}
	return append([]backend.Tier{d.Tier}, d.also...)
}

// ForTier is the diagnostics a run at tier t is to see: every one about all tiers, and those that hold in t.
// An empty t keeps only the ones about all tiers, which is what `tego run` prints before it knows its tier.
func ForTier(ds []Diagnostic, t backend.Tier) []Diagnostic {
	var out []Diagnostic
	for _, d := range ds {
		if d.Tier == "" || d.Tier == t || (t != "" && slices.Contains(d.also, t)) {
			out = append(out, d)
		}
	}
	return out
}
