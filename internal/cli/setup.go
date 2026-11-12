// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/buildinfo"
	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func init() { register(cmdSetup) }

// cmdSetup is `tego setup [--json] [-v]` (ADR 0142): it runs doctor's no-root
// probes (tier landlock's checks, doctor.ForRun at reach landlock: no BPF program is loaded and no fanotify group made,
// as root too), stores their answer in ~/.tego/state/check.json for this boot and this build, then prints the six
// steps (internal/guide), each with the fact that decided it, and the one next step as the `next:` block on stderr.
// It prompts for nothing and starts no program. Exit 0 when a tier runs from here, 1 when none does (doctor's
// finding), 2 for usage, 125 when the machine config, the record or a registry cannot be read or a recorded run cannot
// be checked against the chain anchor, inside a governed run ([governed]) and as root for another user ([privilege]).
func cmdSetup() Command {
	var asJSON, verbose bool
	return Command{
		Name:    "setup",
		Summary: "where this machine is, step by step, and the one command to type next",
		Usage:   "[--json] [-v]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "one JSON object (schema tego.setup/1)")
			fs.BoolVar(&verbose, "v", false, "say where each fact was read and why each run or contract was taken")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 0 {
				message(stderr, "", 0, 0, "tego setup: takes no arguments", codeUsage)
				return identity.ExitUsage
			}
			if refuseSetup(stderr) {
				return identity.ExitError
			}
			return runSetup(ctx, asJSON, verbose, stdout, stderr)
		},
	}
}

// setupProbe is probeHere; a variable so a test can describe a machine without probing this one.
var setupProbe = probeHere

// probeAnswer is what doctor's probes said from here: the tier a run started from here gets ("" for none), doctor's
// first fix when none (doctor.Report.Verdict), and whether none runs only because this shell is outside the user
// manager's cgroup (doctor.Report.OutsideUserManager).
type probeAnswer struct {
	tier    backend.Tier
	fix     string
	outside bool
	// noManager: none runs only because no user manager runs for this user (doctor.Report.NoUserManager).
	noManager bool
}

// probeHere is doctor's no-root probes, tier landlock's checks (doctor.ForRun at reach landlock: D1, D3, D4 and D5, in
// this process, so in this shell's cgroup and with its privilege), and what they say (probeAnswer).
func probeHere(ctx context.Context, m *config.Machine) (probeAnswer, error) {
	rep, err := doctor.ForRun(ctx, m, backend.TierLandlock)
	if err != nil {
		return probeAnswer{}, err
	}
	_, fix := rep.Verdict()
	return probeAnswer{tier: rep.Tier, fix: fix, outside: rep.OutsideUserManager, noManager: rep.NoUserManager}, nil
}

// setupNow is the clock a stored check is stamped with; a variable so the golden tests are stable.
var setupNow = time.Now

// setupInputs fills what is this process's own in a guide's inputs: who asks, the host and the build. A variable so
// the golden tests describe one machine.
var setupInputs = func(in *guide.Inputs) {
	as := guide.Invoker()
	in.As = &as
	in.Host = guide.ThisHost()
	s := buildinfo.Resolve(debug.ReadBuildInfo)
	in.Version, in.Commit = s.Version, s.Commit
	in.Build = guide.BuildID(s.Version, s.Commit)
	in.Linger = lingerCommand(as.UID)
	in.ManagerRefused = managerRefused(as.UID)
}

// refuseSetup is setup's refusal inside a governed run (125 [governed]): an agent held by Tego must not store the
// person's machine check, which would describe the agent's cgroup, not the person's shell; and as root for another
// user, under sudo (125 [privilege]): the folder and file root makes in that user's ~/.tego would be root's, and that
// user's own tego setup could not replace them. It reports true when it refused.
func refuseSetup(stderr io.Writer) bool {
	if in, err := selfInRun(); in {
		why := "this process is inside a tego run's cgroup"
		if err != nil {
			why = "this process cannot be shown to be outside every tego run (" + err.Error() + ")"
		}
		message(stderr, "", 0, 0, "tego setup: a governed agent cannot check the machine for you: "+why+
			"; nothing was written; run it from a terminal outside any tego run", codeGoverned)
		return true
	}
	if learnEUID() == 0 {
		if uid, _ := config.InvokingUID(); uid != 0 {
			message(stderr, "", 0, 0, "tego setup: as root for another user: the stored check would be root's, in that "+
				"user's ~/.tego; nothing was written; run tego setup without sudo, and "+sudoTego("doctor")+
				" for the root tiers", codePrivilege)
			return true
		}
	}
	return false
}

// runSetup is the in-process body of setup.
func runSetup(ctx context.Context, asJSON, verbose bool, stdout, stderr io.Writer) int {
	m, cds, err := loadMachine(config.TrustWarn)
	writeConfigDiagnostics(stderr, cds)
	if err != nil {
		message(stderr, "", 0, 0, "tego setup: machine config: "+err.Error(), config.CodeUntrusted)
		return identity.ExitError
	}
	pa, err := setupProbe(ctx, m)
	tier := pa.tier
	if err != nil {
		message(stderr, "", 0, 0, "tego setup: "+err.Error(), codeIO)
		return identity.ExitError
	}
	uid, _ := config.InvokingUID()
	in := guide.Inputs{Machine: m, Home: m.Home, UID: uid, PATH: os.Getenv("PATH"), Exe: runningBinary(),
		RuntimeDirs: config.RuntimeDirBases()}
	if root, err := ledgerRootOf(m); err == nil {
		in.LedgerRoot = root
	}
	if a, err := anchorPath(m); err == nil {
		in.Anchor = a
	}
	if wd, err := os.Getwd(); err == nil {
		in.Dir = wd
	}
	setupInputs(&in)
	fresh := guide.Check{Where: in.As.Where, Build: in.Build, BootID: in.Host.BootID, Tier: string(tier),
		FirstFix: fixText(pa.fix), Time: setupNow().UTC().Truncate(time.Second)}
	switch {
	case tier != "":
		fresh.FirstFix = ""
	case pa.outside && in.As.Where == guide.WhereShell:
		fresh.Cause = guide.CauseOutsideUserManager
	case pa.noManager && in.As.Where == guide.WhereShell:
		fresh.Cause = guide.CauseNoUserManager
	}
	in.Fresh = &fresh
	// The object is computed before the check is stored: storing drops the other places' checks of an earlier boot,
	// which the check step names as not checked since this machine started (acceptance B, 2026-11-11).
	s := guide.Compute(ctx, in)
	var notStored string
	switch {
	case in.Build == "" || in.Host.BootID == "":
		notStored = "this boot's id or this build could not be read"
	case !filepath.IsAbs(in.Home):
		notStored = "your home could not be named"
	default:
		if err := guide.StoreCheck(in.Home, fresh); err != nil {
			notStored = err.Error()
		}
	}
	if notStored != "" {
		s.NotKnown = append([]string{"this check was not stored, so the dashboard will not see it: " +
			record.Printable(notStored)}, s.NotKnown...)
	}
	if asJSON {
		err = writeJSON(stdout, s)
	} else {
		err = writeSetup(stdout, s, m.Home, verbose)
	}
	if err != nil {
		message(stderr, "", 0, 0, "tego setup: "+err.Error(), codeIO)
		return identity.ExitError
	}
	if s.Unreadable() {
		return identity.ExitError
	}
	if !asJSON {
		writeHint(stderr, s.Next.Text, s.Next.Command)
	}
	if tier == "" {
		return identity.ExitFinding
	}
	return identity.ExitOK
}

// fixText is doctor's fix as the check stores it: printable, and cut to a kilobyte at a character's end.
func fixText(fix string) string {
	const maxFix = 1000
	fix = record.Printable(strings.TrimSpace(fix))
	for len(fix) > maxFix {
		_, size := utf8.DecodeLastRuneInString(fix)
		fix = fix[:len(fix)-size]
	}
	return fix
}

// setupMarks are the marks the steps print with, by state.
var setupMarks = map[string]string{
	guide.Done:     "[x]",
	guide.Todo:     "[ ]",
	guide.Waiting:  "[~]",
	guide.Blocked:  "[!]",
	guide.Skipped:  "[-]",
	guide.NotKnown: "[?]",
}

// writeSetup is the human form of s: one line per step with its mark and fact, then what is not known. With verbose
// (-v, the Full view), who asks and the host first, under each step where its fact was read, the run it is about and
// why that run or contract was taken, and at the end the rule that chose the next step. Paths under home are written
// with ~.
func writeSetup(w io.Writer, s *guide.State, home string, verbose bool) error {
	var b strings.Builder
	b.WriteString("Tego on this machine, step by step:\n")
	if verbose && s.As != nil {
		fmt.Fprintf(&b, "  as %s (uid %d) from %s; root %s, over SSH %s, in your user manager's cgroup %s, in a tego run %s\n",
			record.Printable(s.As.User), s.As.UID, s.As.Where, yesNo(s.As.Root), yesNo(s.As.SSH), yesNo(s.As.InUserCgroup),
			yesNo(s.As.InRun))
		fmt.Fprintf(&b, "  host: kernel %s, boot %s\n", record.Printable(orNone(s.Host.Kernel)), record.Printable(orNone(s.Host.BootID)))
	}
	// The steps' and not-known lines' words are the guide's (State.Words), the ones the dashboard's guide shows.
	words := s.Words(home)
	for _, st := range words.Steps {
		fmt.Fprintf(&b, "  %s %d %-18s  %s\n", setupMarks[st.State], st.N, st.Title, st.Fact)
		if verbose {
			fmt.Fprintf(&b, "        read from: %s\n", st.Source)
			if st.Run != "" {
				fmt.Fprintf(&b, "        run: %s\n", st.Run)
			}
			if st.Link != "" {
				fmt.Fprintf(&b, "        why this one: %s\n", st.Link)
			}
		}
	}
	if len(words.NotKnown) > 0 {
		b.WriteString("Not known:\n")
		for _, n := range words.NotKnown {
			fmt.Fprintf(&b, "  - %s\n", n)
		}
	}
	if verbose {
		fmt.Fprintf(&b, "Next step chosen by rule %s.\n", s.Next.Rule)
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "not known"
	}
	return s
}
