// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/doctor"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/capture/uprobe"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// doctorReport is the --json shape: the version banner and the whole probe report.
type doctorReport struct {
	Version BuildInfo `json:"version"`
	*doctor.Report
	// Ledger is what the ledger root holds that no sweep on this host finishes, nil when there is nothing to
	// say (R27).
	Ledger *tegoruntime.LedgerCheck `json:"ledger,omitempty"`
	// Builds are the tier-2 builds on the bpf filesystem, as root: what is attached, whether a run holds it and
	// how long it has lingered (ADR 0022 (8)); absent unprivileged or when there is none.
	Builds []cgroupenforce.BuildInfo `json:"builds,omitempty"`
	// Rings is bpf.ring_budget and what every build's live run rings charge against it (ADR 0026 (2)), as root;
	// absent unprivileged.
	Rings *cgroupenforce.RingUse `json:"rings,omitempty"`
	// Dashboard is whether the kernel can tell which run a dashboard connection comes from (doctordashboard.go).
	Dashboard dashboardCheck `json:"dashboard"`
}

func init() { register(cmdDoctor) }

// cmdDoctor is `tego doctor [--json] [--require <tier>]`: the version banner (VERSIONING.md §1)
// and R27's nine probes, the capability matrix with this machine's values, the highest reachable
// tier, what the next tier is missing and the one-line fix, then whether the dashboard can tell which
// run a connection comes from (doctordashboard.go, never the exit). Exit 0 when a tier runs, 211 when
// --require named a tier this machine cannot reach (R25).
func cmdDoctor() Command {
	var asJSON bool
	var require string
	return Command{
		Name:    "doctor",
		Summary: "check the machine: kernel, BTF, cgroup v2, Landlock, seccomp, LSM, programs, fanotify, swap",
		Usage:   "[--json] [--require <landlock|cgroup|bpflsm>]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "one JSON object")
			fs.StringVar(&require, "require", "", "exit 211 unless this tier is available (landlock|cgroup|bpflsm)")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 0 {
				message(stderr, "", 0, 0, "tego doctor: takes no arguments", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			return runDoctor(ctx, asJSON, require, stdout, stderr)
		},
	}
}

// runDoctor is the in-process body of doctor.
func runDoctor(ctx context.Context, asJSON bool, require string, stdout, stderr io.Writer) int {
	var tier backend.Tier
	if require != "" {
		t, err := backend.ParseTier(require)
		if err != nil || t == backend.TierObserve {
			message(stderr, "", 0, 0, fmt.Sprintf("tego doctor: --require %q is not a tier: landlock, cgroup or bpflsm", require), codeUsage)
			return identity.ExitUsage
		}
		tier = t
	}
	// The machine config is read the way compile reads it (spec/config/v0: compile and doctor warn and
	// continue on an untrusted layer, run aborts): its tier ceiling is part of the answer, because a run
	// selects at or below it, and doctor called with no config reported a tier a capped run never gets.
	m, cds, err := loadMachine(config.TrustWarn)
	writeConfigDiagnostics(stderr, cds)
	if err != nil {
		message(stderr, "", 0, 0, "tego doctor: machine config: "+err.Error(), config.CodeUntrusted)
		return identity.ExitError // R25: Tego's own error (I/O on a config layer)
	}
	rep, err := doctor.Run(ctx, m, tier)
	if err != nil {
		message(stderr, "", 0, 0, "tego doctor: "+err.Error(), codeIO)
		return identity.ExitError // R25: Tego's own error
	}
	lc := checkLedger(m, stderr)
	builds := listBuilds(stderr, m)
	rings := ringUse(builds, m)
	dash := checkDashboard()
	if asJSON {
		err = writeJSON(stdout, doctorReport{Version: buildInfo(debug.ReadBuildInfo), Report: rep, Ledger: lc, Builds: builds,
			Rings: rings, Dashboard: dash})
	} else {
		if _, err = fmt.Fprintln(stdout, buildInfo(debug.ReadBuildInfo).Line()); err == nil {
			err = rep.WriteText(stdout)
		}
		if err == nil {
			err = writeDashboardCheck(stdout, dash)
		}
		if err == nil && lc != nil {
			err = writeLedgerCheck(stdout, *lc)
		}
		if err == nil && len(builds) > 0 {
			err = writeBuilds(stdout, builds, m.BPF.Linger.Value, rings)
		}
	}
	if err != nil {
		message(stderr, "", 0, 0, "tego doctor: "+err.Error(), codeIO)
		return identity.ExitError // R25: Tego's own error
	}
	return rep.ExitCode()
}

// checkLedger is the ledger half of doctor: the runs in the ledger root no sweep on this host finishes. It reads
// and writes nothing when the root cannot be resolved, and a check that fails is a warning, never doctor's exit.
func checkLedger(m *config.Machine, stderr io.Writer) *tegoruntime.LedgerCheck {
	root, err := ledgerRootOf(m)
	if err != nil {
		return nil
	}
	lc, err := tegoruntime.CheckLedger(root)
	if err != nil {
		message(stderr, "", 0, 0, "tego doctor: "+err.Error(), codeIO)
		return nil
	}
	if lc.Empty() {
		return nil
	}
	return &lc
}

// listBuilds is the tier-2 builds on the bpf filesystem, read as root only: the pins are root's. A listing that
// fails is a warning, never doctor's exit. Before listing, it removes what is overdue and no one holds, as tego gc
// does (ADR 0022 (4), the lingering cap included): a build idle past bpf.linger that no run needs, and a library's
// capture probes whose detacher never ran (both helpers can be killed). The sweep's states say why a build it kept
// is still there (BuildInfo.Kept).
func listBuilds(stderr io.Writer, m *config.Machine) []cgroupenforce.BuildInfo {
	if !config.InitNSRoot() {
		return nil
	}
	swept, err := cgroupenforce.SweepBuilds(cgroupenforce.SweepOptions{Linger: m.BPF.Linger.Value})
	if err != nil {
		message(stderr, "", 0, 0, "tego doctor: builds: "+err.Error(), codeIO)
	}
	if _, err := uprobe.SweepLibraries("", "", time.Now()); err != nil {
		message(stderr, "", 0, 0, "tego doctor: capture probes: "+err.Error(), codeIO)
	}
	builds, err := cgroupenforce.ListBuilds(cgroupenforce.SweepOptions{}, swept)
	if err != nil {
		message(stderr, "", 0, 0, "tego doctor: builds: "+err.Error(), codeIO)
	}
	return builds
}

// ringUse is the host's ring budget and its use, summed over the builds listBuilds read: nil unprivileged, where
// no build was read.
func ringUse(builds []cgroupenforce.BuildInfo, m *config.Machine) *cgroupenforce.RingUse {
	if !config.InitNSRoot() {
		return nil
	}
	u := &cgroupenforce.RingUse{Budget: uint64(m.BPF.RingBudget.Value)}
	for _, b := range builds {
		u.Used += b.RingBytes
		u.Rings += b.Rings
	}
	return u
}

// writeBuilds writes the host's ring budget and its use (ADR 0026 (2)) and the memory every build's objects charge,
// then one line per tier-2 build (ADR 0022 (8)): whether a run holds it; or how long it has lingered and, while its
// timer runs, when that timer removes it, or that no timer does and what will; or why the sweep kept it past its
// linger and that gc --builds does not remove it then (ADR 0022 (1), (5)); what of it is attached, its runs' rings,
// its memlock, and where root sees and removes it.
func writeBuilds(w io.Writer, builds []cgroupenforce.BuildInfo, linger time.Duration, rings *cgroupenforce.RingUse) error {
	head := "\ntier-2 builds (bpf.linger " + config.FormatDuration(linger)
	if rings != nil {
		head += fmt.Sprintf("; %d run rings charge %s of bpf.ring_budget %s", rings.Rings,
			config.ByteSize(rings.Used), config.ByteSize(rings.Budget))
	}
	var memlock uint64
	unreported := 0
	for _, b := range builds {
		memlock += b.MemlockBytes
		unreported += b.MemlockUnreported
	}
	lines := []string{head + "; their programs and maps charge " + memlockText(memlock, unreported) + "):"}
	for _, b := range builds {
		state := "in use by a run"
		switch {
		case b.InUse:
		case b.Kept == cgroupenforce.KeptLive || b.Kept == cgroupenforce.KeptUnread:
			state = "idle " + b.Idle.String() + ", kept: " + b.Kept
			if b.Kept == cgroupenforce.KeptUnread {
				state += " (ADR 0022 (5))"
			}
			if b.KeptCause != "" {
				state += ": " + b.KeptCause
			}
			state += "; tego gc --builds does not remove it while that holds" + keptTimerText(b)
		case b.Kept != "":
			state = "idle " + b.Idle.String() + ", kept: " + b.Kept + ": " + b.KeptCause + keptTimerText(b)
		default:
			state = "idle " + b.Idle.String()
			switch left := (linger - b.Idle).Round(time.Second); {
			case left <= 0:
				state += ", past bpf.linger: the next sweep removes it"
			case b.Timer:
				state += fmt.Sprintf(", removed in about %s by its timer (pid %d)", left, b.TimerPID)
			default:
				state += ", past bpf.linger in about " + left.String() + "; no timer runs for it: the next run, " +
					"tego stop or tego gc removes it after that"
			}
			state += "; tego gc --builds removes it now"
		}
		what := fmt.Sprintf("%d programs, %d links", b.Programs, b.Links)
		if len(b.Runs) > 0 {
			what += fmt.Sprintf(", cgroup links of %d run(s) %s", len(b.Runs), strings.Join(b.Runs, " "))
		}
		if b.Rings > 0 {
			what += fmt.Sprintf(", %d run rings (%s)", b.Rings, config.ByteSize(b.RingBytes))
		}
		if b.CaptureProbes > 0 {
			what += fmt.Sprintf(", %d capture probes on %d librar", b.CaptureProbes, len(b.CaptureLibraries))
			if len(b.CaptureLibraries) == 1 {
				what += "y"
			} else {
				what += "ies"
			}
		}
		what += ", memlock " + memlockText(b.MemlockBytes, b.MemlockUnreported)
		lines = append(lines, fmt.Sprintf("  %s  %s; %s (%s)", b.Hash, state, what, b.Path))
	}
	if _, err := fmt.Fprintln(w, strings.Join(lines, "\n")); err != nil {
		return fmt.Errorf("doctor: write builds: %w", err)
	}
	return nil
}

// keptTimerText is the timer of a build kept past what its linger alone would say: whether one runs, with its pid.
func keptTimerText(b cgroupenforce.BuildInfo) string {
	if b.Timer {
		return fmt.Sprintf("; its timer runs (pid %d)", b.TimerPID)
	}
	return "; no timer runs for it"
}

// memlockText is a memlock sum for a person, to a tenth of its unit, with how many objects it leaves out: "n/a"
// when the kernel reported none of them, never a 0 it did not say.
func memlockText(n uint64, unreported int) string {
	var s string
	switch {
	case n == 0 && unreported > 0:
		s = "n/a"
	case n < 1<<10:
		s = fmt.Sprintf("%dB", n)
	case n < 1<<20:
		s = fmt.Sprintf("%.1fKiB", float64(n)/(1<<10))
	default:
		s = fmt.Sprintf("%.1fMiB", float64(n)/(1<<20))
	}
	switch unreported {
	case 0:
		return s
	case 1:
		return s + " with 1 object unreported"
	}
	return fmt.Sprintf("%s with %d objects unreported", s, unreported)
}

// writeLedgerCheck writes the ledger findings, one line each.
func writeLedgerCheck(w io.Writer, lc tegoruntime.LedgerCheck) error {
	lines := []string{"\nledger " + lc.Root + ":"}
	hosts := make([]string, 0, len(lc.Foreign))
	for h := range lc.Foreign {
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	for _, h := range hosts {
		lines = append(lines, fmt.Sprintf("  %d run(s) minted on host %s, not this one (%s): no sweep here ends, repairs "+
			"or kills them, and tego gc removes them past retention. If this machine's id changed (a reinstall "+
			"keeping home, a cloned image), they are this machine's own runs.", lc.Foreign[h], h, lc.Host))
	}
	for _, id := range lc.Unfinished {
		lines = append(lines, fmt.Sprintf("  run %s ended, its launcher is gone, and its live-index entry stays: no sweep "+
			"has finished it (its anchor repair or its scope removal failed); tego events --verify %s says whether "+
			"it is anchored", id, id))
	}
	if _, err := fmt.Fprintln(w, strings.Join(lines, "\n")); err != nil {
		return fmt.Errorf("doctor: write ledger: %w", err)
	}
	return nil
}
