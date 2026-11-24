// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func init() { register(cmdUninstall) }

// cmdUninstall is `tego uninstall [--yes] [--stop-agents] [--delete-records]` on Linux (and inside the Mac's VM): it
// shows what it will remove, asks once, and removes what Tego put on this machine for this user: the user units
// `tego start` and `tego dashboard` made (tego-dashboard, tego-gc), the installed tego and tego-control, the lines Tego
// added to the shell's start-up files (each with a backup), and the dashboard's own state. It keeps what is the
// person's: the records (~/.tego: runs, chain, logs) and the saved contracts (~/.config/tego) unless a second,
// separate answer says to delete them (default no), and every service the person set up (tego-agent@<name>) unless a
// third says to stop and remove them (default no). --yes answers only the first question; the other two have their own
// flags, so a script never deletes proof or stops an agent by accident.
//
// A system-wide install (root-owned binaries, /etc/tego, system units) is not touched: the command names what needs
// sudo and prints the exact commands. It reads and removes nothing outside the invoking user's home, runs twice
// without harm, and works when the dashboard or the units are already gone. The Mac's tego command (a shell script
// the installer writes) handles `tego uninstall` itself, on the Mac, before the VM is asked (scripts/install.sh); the
// Windows launcher has its own (cmd/tego-windows).
func cmdUninstall() Command {
	var yes, stopAgents, deleteRecords bool
	return Command{
		Name:    "uninstall",
		Summary: "remove Tego from this machine",
		Usage:   "[--yes] [--stop-agents] [--delete-records]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&yes, "yes", false, "do not ask whether to remove Tego (for scripts); your records and agent services stay unless the two flags below say otherwise")
			fs.BoolVar(&stopAgents, "stop-agents", false, "also stop and remove the tego-agent@ services you set up, without asking")
			fs.BoolVar(&deleteRecords, "delete-records", false, "also delete your records (~/.tego) and saved contracts (~/.config/tego), without asking: they are the proof of what your agents did")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if fs.NArg() != 0 {
				message(stderr, "", 0, 0, "tego uninstall: takes no arguments", codeUsage)
				return identity.ExitUsage
			}
			if setupHost() == hostWindows {
				message(stderr, "", 0, 0, "tego uninstall: this is Tego's Linux inside Windows; to remove Tego, run tego uninstall from PowerShell or cmd, which removes it and everything in it", codeUsage)
				return identity.ExitUsage
			}
			if refuseUninstall(stderr) {
				return identity.ExitError
			}
			env, err := realUninstallEnv(stdout, stderr)
			if err != nil {
				message(stderr, "", 0, 0, "tego uninstall: "+err.Error(), codeUsage)
				return identity.ExitError
			}
			env.yes, env.stopAgents, env.deleteRecords = yes, stopAgents, deleteRecords
			return runUninstall(ctx, env)
		},
	}
}

// refuseUninstall is the governed-agent refusal of tego uninstall: an agent inside a run cannot remove the program
// that governs it, nor the record of what it did. It writes the refusal and reports true unless the caller is outside
// every run.
func refuseUninstall(stderr io.Writer) bool {
	a := selfAnswer()
	if a.Outside() {
		return false
	}
	message(stderr, "", 0, 0, notOutside("uninstall", a, "cannot remove Tego, nor the record of what it did", "Tego was not removed",
		"nothing was removed"), codeGoverned)
	return true
}

// uninstallEnv is everything runUninstall touches, so a test runs it against a folder it made: the home it works in,
// the program it was started from, the user service manager, the answers and the output. Nothing in it is read from
// the process's own environment.
type uninstallEnv struct {
	home string // the invoking user's home: the only folder whose contents this removes, beyond the binaries' own folder
	self string // the running tego's path, links resolved; "" when it cannot be found
	euid int

	in          io.Reader
	out         io.Writer
	errOut      io.Writer
	interactive bool // a person can answer
	color       bool

	yes, stopAgents, deleteRecords bool

	// systemctl runs `systemctl --user args...` and returns its output. A variable so a test has a service manager
	// of its own; nil when there is none to ask.
	systemctl func(ctx context.Context, args ...string) (string, error)
	// pin is the SHA-256 of the tego-control this build was made with (handoff.PinnedSum): the only tego-control this
	// command removes.
	pin func() (string, bool)
	// liveRuns counts the runs still going; an error means it could not tell.
	liveRuns func(ctx context.Context) (int, error)
	// systemPaths are the places a system-wide install puts its files: reported, never touched.
	systemPaths []string
}

// stepGroup is the question a step is answered by.
type stepGroup int

const (
	groupTego     stepGroup = iota // what Tego itself put here: asked once
	groupServices                  // the person's own services (tego-agent@...): asked separately
	groupRecords                   // the proof: asked separately, default no
)

// step is one thing the command removes: what it says before, and what it does.
type step struct {
	group stepGroup
	text  string
	do    func(ctx context.Context) error
}

// uninstallPlan is what the scan found: the steps to run, what stays, and what a system-wide install leaves for the
// person to remove with sudo.
type uninstallPlan struct {
	steps []step
	kept  []string
	notes []string // why something found is left alone
	sudo  []string // exact commands the person types
}

func (p *uninstallPlan) appendStep(g stepGroup, text string, do func(ctx context.Context) error) {
	p.steps = append(p.steps, step{group: g, text: text, do: do})
}

func (p *uninstallPlan) hasGroup(g stepGroup) bool {
	for _, s := range p.steps {
		if s.group == g {
			return true
		}
	}
	return false
}

// runUninstall is the in-process body of uninstall.
func runUninstall(ctx context.Context, e *uninstallEnv) int {
	g := newWalk(e.in, e.out, e.color)
	g.col = colTop
	if e.euid == 0 {
		g.bad("tego uninstall removes Tego from one account: run it as the user it was installed for, without sudo")
		g.detail("For files only root can remove, run it as that user: it prints the exact sudo commands.")
		return identity.ExitUsage
	}
	if e.home == "" || !strings.HasPrefix(e.home, "/") || e.home == "/" {
		g.bad("tego uninstall: your home folder is not known, so nothing was removed")
		return identity.ExitError
	}
	rd := bufio.NewReader(e.in)
	if e.in == nil {
		rd = bufio.NewReader(strings.NewReader(""))
	}
	if !e.yes && !e.interactive {
		g.bad("tego uninstall asks before it removes anything, so it runs in a terminal")
		g.detail("For a script, run: tego uninstall --yes   (your records and agent services stay unless you add --delete-records or --stop-agents)")
		return identity.ExitUsage
	}

	plan := scanUninstall(ctx, e)
	if len(plan.steps) == 0 && len(plan.sudo) == 0 {
		g.ok("Nothing of Tego is installed for you here: no program, units or start-up lines to remove.")
		e.reportKept(g, plan)
		return identity.ExitOK
	}

	g.line("")
	g.line("%sRemove Tego from this machine%s", g.bold, g.offEsc)
	if !plan.hasGroup(groupTego) && !plan.hasGroup(groupServices) {
		g.line("")
		g.ok("Tego's program, units and start-up lines are already gone.")
	}
	e.showGroup(g, plan, groupTego, "Tego will remove")
	e.showGroup(g, plan, groupServices, "Services you set up (stopped and removed only if you say so)")
	e.showGroup(g, plan, groupRecords, "Your records and contracts (kept unless you say so)")
	e.reportKept(g, plan)
	for _, n := range plan.notes {
		g.line("%s%s%s%s", colTop, g.dim, n, g.offEsc)
	}
	if len(plan.sudo) > 0 {
		g.line("")
		g.todo("This needs sudo; Tego does not run it for you. Type each line yourself:")
		for _, c := range plan.sudo {
			g.cmd(c)
		}
	}
	g.line("")

	// Question 1: the removal itself. Nothing else is asked until this is yes.
	if plan.hasGroup(groupTego) {
		if !e.yes {
			ok, err := askYesNo(rd, e.out, "Remove what is listed under \"Tego will remove\"?", true)
			if err != nil || !ok {
				g.line("Nothing was changed.")
				return identity.ExitOK
			}
		}
	}
	doServices := false
	if plan.hasGroup(groupServices) {
		switch {
		case e.stopAgents:
			doServices = true
		case e.yes || !e.interactive:
			g.detail("Left running: your agent services. Add --stop-agents to stop and remove them.")
		default:
			ok, err := askYesNo(rd, e.out, "Also stop and remove the services you set up (listed above)? They stop running.", false)
			doServices = err == nil && ok
		}
	}
	doRecords := false
	if plan.hasGroup(groupRecords) {
		switch {
		case e.deleteRecords:
			doRecords = true
		case e.yes || !e.interactive:
			g.detail("Kept: your records and contracts. Add --delete-records to delete them.")
		default:
			ok, err := askYesNo(rd, e.out, "Also delete your records and contracts? They are the proof of what your agents did. This cannot be undone.", false)
			doRecords = err == nil && ok
		}
	}

	failed := 0
	for _, s := range plan.steps {
		switch {
		case s.group == groupServices && !doServices, s.group == groupRecords && !doRecords:
			continue
		}
		if err := s.do(ctx); err != nil {
			failed++
			g.bad(s.text + ": " + err.Error())
			continue
		}
		g.ok(doneText(s.text))
	}
	g.line("")
	if failed > 0 {
		g.bad(fmt.Sprintf("%d step(s) did not finish (marked above); the other steps were done. Run tego uninstall again, or do the marked ones yourself.", failed))
		return identity.ExitError
	}
	switch {
	case doRecords:
		g.ok("Tego is removed, with your records and contracts.")
	case plan.hasGroup(groupRecords):
		g.ok("Tego is removed. Your records and contracts stay where they were.")
	default:
		g.ok("Tego is removed.")
	}
	return identity.ExitOK
}

// doneText is a step's text in the past tense of a result line: the steps are written as what they do ("remove X"),
// and a finished line says it is so.
func doneText(s string) string {
	for _, p := range [][2]string{{"stop and remove ", "Stopped and removed "}, {"stop ", "Stopped "}, {"remove ", "Removed "}, {"delete ", "Deleted "}, {"reload ", "Reloaded "}} {
		if strings.HasPrefix(s, p[0]) {
			return p[1] + strings.TrimPrefix(s, p[0])
		}
	}
	return s
}

func (e *uninstallEnv) showGroup(g *walk, p *uninstallPlan, grp stepGroup, title string) {
	first := true
	for _, s := range p.steps {
		if s.group != grp {
			continue
		}
		if first {
			g.line("")
			g.line("%s%s%s", g.bold, title, g.offEsc)
			first = false
		}
		g.line("%s  - %s", colTop, s.text)
	}
}

func (e *uninstallEnv) reportKept(g *walk, p *uninstallPlan) {
	for _, k := range p.kept {
		g.line("")
		g.line("%s%s%s%s", colTop, g.dim, k, g.offEsc)
	}
}

// askYesNo asks question and reads one line: Enter takes the default. An input that ends before an answer is a no.
func askYesNo(rd *bufio.Reader, out io.Writer, question string, def bool) (bool, error) {
	choices := "[y/N]"
	if def {
		choices = "[Y/n]"
	}
	fmt.Fprintf(out, "  ? %s %s ", question, choices)
	line, err := rd.ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(out)
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "":
		return def, nil
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// realUninstallEnv is the environment of the real command: this process's own user, home and service manager.
func realUninstallEnv(stdout, stderr io.Writer) (*uninstallEnv, error) {
	if err := uninstallRealGuard(); err != nil {
		return nil, err
	}
	return newRealUninstallEnv(stdout, stderr)
}

// symbolic names of the files and units Tego makes, in one place.
const (
	unitDashboard = "tego-dashboard.service"
	// the transient timer `tego start` makes (retain_timer.go) is systemd-run --unit=<retentionTimerUnit>: systemd
	// names its two units from that one name, so uninstall derives them from it and cannot drift from the maker.
	unitGCService = retentionTimerUnit + ".service"
	unitGCTimer   = retentionTimerUnit + ".timer"
)
