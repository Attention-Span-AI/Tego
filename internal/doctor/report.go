// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/attention-span-ai/tego/internal/platform/whereami"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// MinLandlockABI is the oldest Landlock ABI this project supports. ABI 1 (kernels 5.13-5.18)
// confines rename and link to a single directory and is explicitly unsupported
// (spec/backend/CAPABILITIES.md, docs/ARCHITECTURE.md §14).
const MinLandlockABI = 2

// Report is everything `tego doctor` learned: the nine probe results in R27's fixed order, the
// highest tier this machine can reach, what each tier above it is missing, and the capability matrix
// with this machine's own values in it.
type Report struct {
	// BusinessRules is separate from the kernel tier: a tier label proves no exclusive business route.
	BusinessRules BusinessRulesStatus `json:"business_rules"`

	// PendingWSL names containment proofs that this release has not completed on WSL.
	// It qualifies readiness, not the measured kernel capabilities or run admission.
	PendingWSL []string `json:"pending_wsl,omitempty"`

	// Results holds exactly nine entries, D1..D9 in order.
	Results []Result `json:"results"`
	// Tier is the highest tier this machine can reach at or below the machine config's ceiling;
	// "" when no tier can run.
	Tier backend.Tier `json:"tier"`
	// Missing lists, per tier above Tier, the probe answers that stand in the way.
	Missing map[backend.Tier][]string `json:"missing,omitempty"`
	// Matrix is the capability set of Tier: the CAPABILITIES.md column this machine actually gets,
	// with rows this kernel cannot deliver turned off (R27's "with this machine's values").
	Matrix backend.Set `json:"matrix"`
	// MatrixNotes says, per adjusted row, which measured value decided it.
	MatrixNotes map[backend.Capability]string `json:"matrix_notes,omitempty"`
	// Fix is the one line that makes the next tier up available, "" at the top tier.
	Fix string `json:"fix,omitempty"`
	// Require is the tier --require asked for, "" when it was not given.
	Require backend.Tier `json:"require,omitempty"`
	// Ceiling is the machine config's tier ceiling, "" when unbounded.
	Ceiling backend.Tier `json:"ceiling,omitempty"`
	// CeilingSource is the file:line that set Ceiling, "" when unbounded. A concrete machine tier is a
	// pin as well as a ceiling, so when it names a tier this machine cannot
	// provide the report is tier none, and the line that caused it is what the reader must edit
	// (not just "tier: none" with no file named).
	CeilingSource string `json:"ceiling_source,omitempty"`
	// Tiers is what this machine and this binary can provide, per tier, before the ceiling is
	// applied: the one tier derivation (derive.go), which `tego run` selects from. It is the value
	// Probe returns and enforce.Select consumes; Tier is what the ceiling then allows.
	Tiers backend.Probe `json:"tiers"`
	// OutsideUserManager is true when no tier runs from this process only because it runs beside its user manager's
	// cgroup (an SSH or console login's session scope): D3's placement refusal (cgroup.ErrBesideSubtree) is the one
	// thing tier landlock misses, and the ceiling allows tier landlock. A shell opened inside that cgroup
	// (systemd-run --user --scope) gets tier landlock. This report describes the original shell; run, watch and
	// test can try a user-scope handoff before runtime placement (ADR 0142 B3-1). `tego setup` stores this
	// predicate. Not in --json: doctor's JSON stays as scripts read it.
	OutsideUserManager bool `json:"-"`
	// ThroughUserScope records successful entry rehearsal and the remaining D3 checks, from the original shell.
	ThroughUserScope bool `json:"through_user_scope,omitempty"`
	// UserScopeFailure is why the CLI's rehearsal of entry into a user scope failed (WithUserScopeFailure), set only
	// with OutsideUserManager: tego could not open a user scope from this shell, so run, watch and test cannot either.
	// "" when no rehearsal was tried or it worked. Not in --json.
	UserScopeFailure string `json:"-"`
	// NoUserManager is true when no tier runs from this process only because no user manager runs for its user
	// (cgroup.ErrNoUserManager: user@<uid>.service has no cgroup, as for an account with a nologin shell reached
	// through su or sudo -u that has no linger), with the same conditions as OutsideUserManager. The delegation fix
	// changes nothing there; doctor and tego setup name cgroup.LingerCommand. Not in
	// --json.
	NoUserManager bool `json:"-"`

	// The raw state behind the results, for --json consumers and for tests.
	Kernel      string      `json:"kernel"`
	Root        bool        `json:"root"`
	LandlockABI int         `json:"landlock_abi"`
	LSM         LSMState    `json:"lsm"`
	Ptrace      PtraceState `json:"ptrace"`
	// Fanotify is what D8 measured, null when D8 did not run (unprivileged, or not needed by a run's reach):
	// its fields read false before, which --json readers took for a kernel that refuses them (R27).
	Fanotify *FanotifyState `json:"fanotify"`
	Programs []HookResult   `json:"programs,omitempty"`
	// Plane is the decision plane's mode probe (plane.go), null when it did not run
	// (unprivileged, or not needed by a run's reach). Its per-hook rows are in Programs, with plane set.
	Plane *PlaneState `json:"plane"`

	// whyNot is, per tier missing from Tiers, the missing list and the fix line for that tier on one
	// line (derive.go whyNot); WhyNot reads it.
	whyNot map[backend.Tier]string
	// cached names the run-probe cache entry D7's tier-2 rows and D8 were read from (runcache.go), nil when
	// they were probed or not needed; DiscardCache removes that entry.
	cached *cachedAnswer
	// cacheNote is runCache.refused as the run left it (CacheNote).
	cacheNote string
	// coordinationNote is why a run could not coordinate its probe with a concurrent one (CoordinationNote).
	coordinationNote string
	// rootStateVisible is live namespace authority, never accepted from JSON.
	rootStateVisible bool
}

// Run performs every probe of R27 in order and derives the tier, the gaps and the fix. It needs no
// privilege; root unlocks D6's functional half and the D7/D8 functional probes, which report
// "requires root to test" otherwise (§6 E18). It leaves nothing behind: no pin, no cgroup, no mark,
// no filtered thread (I7).
//
// The only error it returns is the context's: a probe that cannot answer answers with
// Result{OK:false} and a fix, because a missing capability is an answer, not a failure (§4).
func Run(ctx context.Context, m *config.Machine, require backend.Tier) (*Report, error) {
	uid, _ := config.InvokingUID()
	st := runProbes(ctx, uid, planePin(m), m.LimitCeilings())
	if ctx.Err() != nil {
		return nil, fmt.Errorf("doctor: %w", ctx.Err())
	}
	r := st.report(m, require)
	r.noteScope(ctx)
	r.addMountWarnings(uid)
	r.addWSLWarnings()
	return r, nil
}

// report derives the Report from what the probes learned: pure, so a test can hand it a described machine
// and get exactly what Run would print and `tego run` would select from on that machine.
func (st probeState) report(m *config.Machine, require backend.Tier) *Report {
	r := &Report{
		Results:          st.results,
		BusinessRules:    businessRulesStatus(),
		Kernel:           st.release,
		PendingWSL:       pendingWSLProofs(st.wslHeld),
		Root:             st.root,
		rootStateVisible: st.root && st.rootTierWhy == "",
		LandlockABI:      st.landlockABI,
		LSM:              st.lsm,
		Ptrace:           st.ptrace,
		Programs:         st.hooks,
		Plane:            st.plane,
		Require:          require,
		Ceiling:          ceiling(m),
		cached:           st.cached,
		cacheNote:        st.cacheNote,
	}
	r.coordinationNote = st.coordinationNote
	if r.Ceiling != "" {
		r.CeilingSource = m.Tier.Source.String()
	}
	if d8, ok := st.byID[CheckFanotify]; ok && !d8.Skipped {
		f := st.fanotify
		r.Fanotify = &f
	}
	r.Tiers = st.probe()
	r.OutsideUserManager = st.outsideUserManager(r.Ceiling)
	r.ThroughUserScope = st.byID[CheckCgroupV2].throughUserScope
	r.NoUserManager = st.noUserManager(r.Ceiling)
	// A concrete machine tier is both ceiling and pin, exactly as internal/runtime/enforce reads it,
	// and `tego run` selects from this same r.Tiers, so the tier
	// doctor reports is the tier a run of an auto contract gets under the same machine config; a
	// contract's own tier: pin or --tier can only ask for a tier listed here or be refused.
	tier, err := backend.Select(r.Ceiling, r.Ceiling, r.Tiers)
	if err == nil {
		r.Tier = tier
	}
	r.Matrix, r.MatrixNotes = st.machineMatrix(r.Tier)
	r.Missing = st.missing(r.Tier)
	r.Fix = st.fix(r.Tier)
	r.whyNot = st.whyNot()
	if r.pinUnavailable() {
		// The next tier up is not what stands in the way: the pin is. Its line is the one to edit, or the
		// pinned tier's own fix is what would make it run.
		r.Fix = fmt.Sprintf("set tier: auto, or a tier this machine provides, at %s", r.CeilingSource)
		if f := st.fixFor(r.Ceiling); f != "" {
			r.Fix += "; or make tier " + string(r.Ceiling) + " available: " + f
		}
	}
	return r
}

// pinUnavailable reports whether the machine config pins a tier this machine cannot provide, which is
// what leaves the report at tier none although a lower tier may run.
func (r *Report) pinUnavailable() bool {
	return r.Tier == "" && r.Ceiling != "" && !r.Tiers[r.Ceiling]
}

// RootStateVisible reports whether a live probe proved that root can interpret
// PID-indexed root-tier state. A report decoded from JSON carries no such
// authority. A private or unreadable PID namespace must not sweep other builds.
func (r *Report) RootStateVisible() bool { return r.rootStateVisible }

// available lists the tiers this machine provides, lowest first.
func (r *Report) available() []string {
	var out []string
	for _, t := range backend.Tiers() {
		if r.Tiers[t] {
			out = append(out, string(t))
		}
	}
	return out
}

// Probe reports which tiers this machine and this binary can provide, the value enforce.Select
// consumes to pick a run's backend; internal/cli's `run` builds its
// selection from it and nothing else. Each entry is the derivation's own answer for that tier (derive.go),
// never inferred from the reached tier or a rank ordering. The machine config's ceiling is deliberately
// not applied here — Select applies it, so one probe serves every run.
func (r *Report) Probe() backend.Probe {
	p := backend.Probe{}
	for _, t := range backend.Tiers() {
		if t == backend.TierObserve {
			continue
		}
		p[t] = r.Tiers[t]
	}
	return p
}

// WhyNot says why tier t is not in Probe: doctor's own "missing for" line for t and the fix line that
// makes t available, "" when t is available or the report does not know. Missing and Fix answer only for
// the tiers above the one reached and for the next tier up; a run refused a tier it asked for by name
// needs that tier's answer, whichever it is.
func (r *Report) WhyNot(t backend.Tier) string {
	if r.Tiers[t] {
		return ""
	}
	if why := r.whyNot[t]; why != "" {
		return why
	}
	if reasons := r.Missing[t]; len(reasons) > 0 {
		return fmt.Sprintf("missing for %s: %s", t, strings.Join(reasons, "; "))
	}
	return ""
}

// Select picks and constructs a run's backend from this report: enforce.Select over Probe, offered only
// tier `only` when it is not "" (`tego run --tier`), with every refusal carrying WhyNot for the tier that
// was refused. It is the one way `tego run` selects, so the tier a run gets is the tier this report
// derived and a refusal gives the reasons `tego doctor` prints for that tier, not a sentence
// of its own: `--tier cgroup` on a machine with tier landlock used to answer "no enforcement tier
// available on this machine", which was false and named neither the build nor root.
func (r *Report) Select(m *config.Machine, rt *agent.RuleTable, only backend.Tier) (enforce.Backend, []enforce.Diagnostic) {
	opts := []enforce.SelectOption{enforce.Explain(r.WhyNot)}
	if only != "" {
		opts = append(opts, enforce.Only(only))
	}
	// Tier cgroup's decision plane: the mode this report selected, which the
	// backend loads and pins, beside it the answer that lets a run adopting the build probe nothing (R21).
	if choice, err := r.PlaneFor(backend.TierCgroup); err == nil && choice.Mode != "" {
		opts = append(opts, enforce.Plane(enforce.PlaneSetup{Mode: choice.Mode, Build: choice.Build,
			ExecPins: choice.ExecPins, RecheckAdmission: r.planeAdmission(choice.Mode), PinAnswer: func(dir string) error { return PinPlaneAnswer(dir, choice) }}))
	}
	// Tier bpflsm's plane (R19): LSM mode, or doctor's reason and fix where it does not pass, which a
	// run pinned to tier bpflsm is refused with. It is never another mode.
	lsm, err := r.PlaneFor(backend.TierBPFLSM)
	setup := enforce.PlaneSetup{Mode: lsm.Mode, Build: lsm.Build, ExecPins: lsm.ExecPins}
	if err == nil {
		setup.PinAnswer = func(dir string) error { return PinPlaneAnswer(dir, lsm) }
		setup.RecheckAdmission = r.planeAdmission(lsm.Mode)
	}
	opts = append(opts, enforce.LSMPlane(setup, err))
	return enforce.Select(m, rt, r.Probe(), opts...)
}

// ExitCode is the process status `tego doctor` should exit with (R25): 211 when --require named a
// tier this machine cannot reach, 1 when no tier can run or WSL containment remains unproved, 0 otherwise. RUN-IDENTITY.md's
// exit table resolves the earlier 1/211 ambiguity in favour of 211 for the --require case.
func (r *Report) ExitCode() int {
	if r.Require != "" && (r.Tier == "" || !r.Require.AtOrBelow(r.Tier)) {
		return identity.ExitRequire
	}
	if r.Tier == "" || len(r.PendingWSL) != 0 {
		return identity.ExitFinding
	}
	return identity.ExitOK
}

// WriteText writes the human report: one line per probe, the summary line, then CAPABILITIES.md's table
// with this machine's values, the tier, what each tier above it is missing, and the one-line fix (R27).
// The summary comes before the table so that the answer is not below the table's rows; the tier line
// stays after the table, where scripts read it.
func (r *Report) WriteText(w io.Writer) error {
	var fold repeatFold
	if err := writeResults(w, r.Results, r.optionalOff, &fold); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\n%s\n", r.summary()); err != nil {
		return fmt.Errorf("doctor: write summary: %w", err)
	}
	for _, row := range r.PendingWSL {
		if _, err := fmt.Fprintf(w, "warning: WSL %s containment has not been proven; this build does not qualify WSL as ready\n", row); err != nil {
			return fmt.Errorf("doctor: write WSL warning: %w", err)
		}
	}
	if len(r.PendingWSL) != 0 {
		if _, err := fmt.Fprintln(w, "WSL_INTEROP is omitted from enforcing runs; launcher and socket containment still require guest proof"); err != nil {
			return fmt.Errorf("doctor: write WSL environment: %w", err)
		}
	}
	tier := r.Tier
	if tier == "" {
		tier = backend.TierObserve
	}
	if _, err := fmt.Fprintf(w, "\ncapability matrix for tier %s on this machine:\n", tier); err != nil {
		return fmt.Errorf("doctor: write matrix header: %w", err)
	}
	lines := r.Matrix.ReportFor(tier)
	for i := range lines {
		if note := r.MatrixNotes[lines[i].Capability]; note != "" {
			lines[i].Detail += " [this machine: " + note + "]"
		}
	}
	if err := backend.WriteReport(w, lines); err != nil {
		return fmt.Errorf("doctor: write matrix: %w", err)
	}
	if _, err := fmt.Fprintf(w, "\ntier: %s\n", r.tierText()); err != nil {
		return fmt.Errorf("doctor: write tier: %w", err)
	}
	if r.Ceiling != "" && r.Tier == r.Ceiling {
		if _, err := fmt.Fprintf(w, "ceiling: the machine config caps every run at %s (%s)\n", r.Ceiling, r.CeilingSource); err != nil {
			return fmt.Errorf("doctor: write ceiling: %w", err)
		}
	}
	for _, t := range backend.Tiers() {
		reasons, ok := r.Missing[t]
		if !ok {
			continue
		}
		if _, err := fmt.Fprintf(w, "missing for %s: %s\n", t, strings.Join(reasons, "; ")); err != nil {
			return fmt.Errorf("doctor: write missing: %w", err)
		}
	}
	if r.Fix != "" {
		if _, err := fmt.Fprintf(w, "fix: %s\n", fold.line(r.printedFix())); err != nil {
			return fmt.Errorf("doctor: write fix: %w", err)
		}
	}
	if r.Require != "" && r.ExitCode() == identity.ExitRequire {
		if _, err := fmt.Fprintf(w, "required tier %s is not available on this machine\n", r.Require); err != nil {
			return fmt.Errorf("doctor: write require: %w", err)
		}
	}
	if _, err := fmt.Fprintf(w, "\nbusiness rules: %s\n", r.BusinessRules.Reason); err != nil {
		return fmt.Errorf("doctor: write business rules: %w", err)
	}

	return nil
}

// Verdict is the line for a person who reads only the end of doctor's report, which `tego doctor` writes on stderr
// after it (doctor's stdout stays as scripts read it), and fix, what doctor printed to make the
// next tier up available, "" when the line says ready: the fix line, or the first failing check's own fix. Ready is
// doctor's exit 0. A report made as root is a root run's: a run the same person starts without sudo gets tier
// landlock at most, so its line says "a run started as root here", never "this shell".
func (r *Report) Verdict() (line, fix string) {
	who, can := "this shell", "this shell can"
	if r.Root {
		who, can = "a run started as root here", "a run started as root here can"
	}
	got := can + " only record"
	if r.Tier != "" {
		got = can + " enforce at " + TierWords(r.Tier)
	}
	// "Only record" holds only where D3 passed: a run that records is placed in the same cgroup, so where D3 fails
	// recording also needs placement. A CLI scope handoff does not change the shell this report checked.
	none := who + " can only record"
	switch {
	case r.OutsideUserManager && r.UserScopeFailure != "":
		none = who + " is outside your user manager's cgroup and tego could not open a user scope from it (" +
			r.UserScopeFailure + ")"
	case r.OutsideUserManager:
		none = who + " is outside your user manager's cgroup; run, watch and test can try a user scope"
	case r.NoUserManager:
		none = "no user manager runs for this user, so tego starts no run from " + who + ", not even tego watch"
	case r.placementFailed():
		none = "tego can start no run from " + who + ", not even tego watch"
	}
	if r.Tier == "" {
		got = none
	}
	switch r.ExitCode() {
	case identity.ExitOK:
		line = "Ready: " + got
		if !r.Root && r.Tier == backend.TierLandlock {
			line += ", no root needed"
		}
		if r.ThroughUserScope {
			line += "; " + ThroughScopeFact
		}
		return line + ".", ""
	case identity.ExitRequire:
		line = fmt.Sprintf("Not ready for %s, which --require asks for: %s.", TierWords(r.Require), got)
	default:
		line = "Not ready: " + none + "."
		if len(r.PendingWSL) != 0 {
			line = "Not ready: WSL containment checks remain unproven; a kernel tier alone does not qualify this machine."
		}
	}
	if len(r.PendingWSL) != 0 {
		return line, "WSL remains unqualified until its launcher, home-folder alias, Windows drive, and GUI and audio socket checks are proven"
	}
	fix = r.Fix
	for _, res := range r.Results {
		if fix == "" && !res.OK && !res.Skipped && res.Fix != "" {
			fix = res.Fix
		}
	}
	return line, fix
}

// TierWords is a tier as a newcomer reads it beside its key: "tier 1 (landlock)", "tier 2 (cgroup)", "tier 3
// (bpflsm)" (docs/site/tiers.md numbers them so).
func TierWords(t backend.Tier) string {
	switch t {
	case backend.TierLandlock:
		return "tier 1 (landlock)"
	case backend.TierCgroup:
		return "tier 2 (cgroup)"
	case backend.TierBPFLSM:
		return "tier 3 (bpflsm)"
	case backend.TierObserve, backend.TierAuto:
	}
	return "tier " + string(t)
}

// tierText is what the tier line says after "tier: ", and the summary after "tier ": the tier this machine gets,
// or none and why.
func (r *Report) tierText() string {
	switch {
	case r.pinUnavailable():
		text := fmt.Sprintf("none: the machine config pins tier %s at %s, which this machine cannot provide",
			r.Ceiling, r.CeilingSource)
		if avail := r.available(); len(avail) > 0 {
			text += " (available here: " + strings.Join(avail, ", ") + ")"
		}
		return text
	case r.Tier == "" && r.OutsideUserManager && r.UserScopeFailure != "":
		return "none in this shell (tego could not open a user scope from it)"
	case r.Tier == "" && r.OutsideUserManager:
		return "none in this shell (run commands can try a user scope)"
	case r.Tier == "" && r.NoUserManager:
		return "none (no user manager runs for this user, so tego starts no run from here)"
	case r.Tier == "" && r.placementFailed():
		return "none (tego can start no run from here)"
	case r.Tier == "":
		return "none (this machine can only record)"
	}
	return string(r.Tier)
}

// placementFailed reports whether D3 ran and failed: every run, one that only records included, is made in the
// cgroup D3 checks, so none starts from here.
func (r *Report) placementFailed() bool {
	for _, res := range r.Results {
		if res.ID == CheckCgroupV2 {
			return !res.OK && !res.Skipped
		}
	}
	return false
}

// printedFix is the one-line fix as WriteText prints it after the table. The container's cure of a failed cgroup check
// (whereami.ContainerCgroupCure) is long, and the cgroupv2 line above has already printed it, so here it is a pointer to
// that line, which keeps the cure to one appearance in a report. Any other fix, and the fix of a host, is printed
// as it is.
func (r *Report) printedFix() string {
	if !strings.Contains(r.Fix, whereami.ContainerCgroupCure) {
		return r.Fix
	}
	for _, res := range r.Results {
		if res.ID == CheckCgroupV2 && !res.OK && res.Fix == whereami.ContainerCgroupCure {
			return strings.ReplaceAll(r.Fix, whereami.ContainerCgroupCure, "what the cgroupv2 line above says the container needs")
		}
	}
	return r.Fix
}

// summary is the line WriteText prints between the probes and the matrix: the tier, a machine config that caps
// every run at it, and what each tier above it needs, by name. The tier line used to be the first answer a reader
// met, after the matrix's rows (R27 Output). The summary says nothing the lines after the matrix
// do not, and it never starts with "tier: ": test/vm's scripts read the tier line by that prefix.
func (r *Report) summary() string {
	line := "summary: tier " + r.tierText()
	if r.Tier != "" && r.Tier == r.Ceiling && nextTier(r.Tier) != "" {
		line += ", capped by the machine config (" + r.CeilingSource + ")"
	}
	for _, t := range backend.Tiers() {
		if names := r.missingNames(t); len(names) > 0 {
			line += "; " + string(t) + " needs " + strings.Join(names, ", ")
		}
	}
	return line
}

// missingNames names what Missing lists for tier t, each name once, in Missing's order. A reason's name is the
// check, "root", "build" or "plane" it begins with ("lsm: bpf is not in the active LSM list ..."); D7's own,
// "programs", for a row of D7, which begins with its hook's name ("tp_btf/cgroup_mkdir: ..."); and the first word
// of the one reason that begins with no name ("landlock ABI 1 is below the supported minimum 2 ..."). Where root
// is named, a check that did not run for want of it (Result.Skipped, "requires root to test") is left out: root is
// what is known to be missing, and the check may pass once it runs.
func (r *Report) missingNames(t backend.Tier) []string {
	var names []string
	seen := map[string]bool{}
	for _, reason := range r.Missing[t] {
		name, _, ok := strings.Cut(reason, ": ")
		if !ok {
			name, _, _ = strings.Cut(reason, " ")
		}
		if r.hookRow(name) {
			name = string(CheckPrograms)
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if !seen["root"] {
		return names
	}
	kept := names[:0]
	for _, name := range names {
		if !r.skipped(CheckID(name)) {
			kept = append(kept, name)
		}
	}
	return kept
}

// hookRow reports whether name is the hook of one of D7's rows.
func (r *Report) hookRow(name string) bool {
	for _, h := range r.Programs {
		if h.Hook == name {
			return true
		}
	}
	return false
}

// skipped reports whether check id did not run (Result.Skipped).
func (r *Report) skipped(id CheckID) bool {
	for _, res := range r.Results {
		if res.ID == id {
			return res.Skipped
		}
	}
	return false
}

// optionalTier is the lowest tier check id stands in the way of when only the tiers above tier 1 need it (missingFor):
// BTF, the program loads and fanotify for tier cgroup, the LSM for tier bpflsm. "" for a check every tier needs, or
// none does (swap).
func optionalTier(id CheckID) backend.Tier {
	switch id {
	case CheckBTF, CheckPrograms, CheckFanotify:
		return backend.TierCgroup
	case CheckLSM:
		return backend.TierBPFLSM
	}
	return ""
}

// optionalOff reports whether the failed probe res is printed "off" rather than FAIL: it stands in the way
// only of a tier above the one this machine reaches, and doctor exits 0 (a tier runs, and --require, when given, is
// met). On a stock Ubuntu with no BPF LSM at boot, tier bpflsm is an option the machine does not offer, not a broken
// machine. The line still says what is missing and the fix; only the word changes, never the exit code or --json.
func (r *Report) optionalOff(res Result) bool {
	t := optionalTier(res.ID)
	return !res.OK && !res.Skipped && t != "" && r.Tier != "" && !t.AtOrBelow(r.Tier) && r.ExitCode() == identity.ExitOK
}

// ceiling reads the machine config's tier ceiling; an absent or `auto` setting is unbounded.
func ceiling(m *config.Machine) backend.Tier {
	if m == nil || !m.Tier.Bounded || m.Tier.Value.Auto || m.Tier.Value.Tier == "" {
		return ""
	}
	return backend.Tier(m.Tier.Value.Tier)
}

// probeState is what the nine probes learned, before it becomes a Report.
type probeState struct {
	// rootTierWhy is the PID-namespace precondition shared by doctor and run.
	rootTierWhy string
	results     []Result
	byID        map[CheckID]Result
	root        bool
	release     string
	// wslHeld is checks.wslHeld's answer: this machine is WSL and the rule's gate holds there (pendingWSLProofs).
	wslHeld bool
	kernel  Version
	// kernelProbe is what D1 asked the kernel, kept so D1 can be rendered again with D7's answer (kernelFromD7).
	kernelProbe kernelProbe
	landlockABI int
	lsm         LSMState
	hooks       []HookResult
	// plane is the decision plane's mode probe, nil when it did not run.
	plane    *PlaneState
	fanotify FanotifyState
	ptrace   PtraceState
	// seccompErr is D5's round trip's own error, nil when the filter, the notification and the
	// ADDFD(SEND) answer all worked. D5's Result is not OK for either of two reasons — this, or
	// Yama in ptrace — and the derivation (derive.go) lists each one that holds, so it needs them apart.
	seccompErr error
	// built is the build's half of the derivation; nil means enforce.Buildable, this binary's own
	// answer. It is a field so a test can describe a build other than the one it runs in.
	built func(backend.Tier) error
	// reach is the highest tier whose checks were probed: "" when every check of R27 ran (doctor), else the
	// tier a run's selection can reach (ForRun). Nothing above it was probed, so the derivation reports no
	// tier above it (derive.go unprobed).
	reach backend.Tier
	// cached is the run-probe cache entry D7's tier-2 rows and D8 came from, nil when they did not.
	cached *cachedAnswer
	// cacheNote is why the run-probe cache was refused, "" otherwise (Report.CacheNote).
	cacheNote string
	// coordinationNote is why the run could not take its key's probe flight, "" otherwise
	// (Report.CoordinationNote).
	coordinationNote string
	// unixDiag is whether the kernel answers sock_diag for AF_UNIX (checks.unixDiag), nil when it was not asked.
	unixDiag *bool
}

// runProbes runs D1..D9 in R27's exact order, stopping early when ctx ends: every check, as doctor
// reports it, and never through the run-probe cache.
func runProbes(ctx context.Context, uid int, pin string, ceilings []config.Value) probeState {
	return scope{uid: uid, root: config.InitNSRoot(), checks: machineChecks, planePin: pin, ceilings: ceilings}.run(ctx)
}

// planePin reads the machine's bpf.plane setting; an absent one is auto.
func planePin(m *config.Machine) string {
	if m == nil || m.BPF.Plane.Value == "" {
		return config.PlaneAuto
	}
	return m.BPF.Plane.Value
}
