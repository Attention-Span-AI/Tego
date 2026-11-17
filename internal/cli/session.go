// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/registry"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// sessionName is how a session is named to a person: its agent, a dash and the last four characters of its run id
// (tego-sample-7f3a). The four are the end of the id's random part, so every command that takes a run also takes them
// alone (expandRunAbbrev), and with the agent in front two agents' sessions never share a name by chance.
func sessionName(agentName, runID string) string {
	if agentName == "" {
		agentName = "session"
	}
	if len(runID) < minRunAbbrev {
		return agentName
	}
	return agentName + "-" + runID[len(runID)-minRunAbbrev:]
}

// sessionShape splits a session name into its agent and the run id's last four characters.
func sessionShape(ref string) (agentName, end string, ok bool) {
	i := strings.LastIndexByte(ref, '-')
	if i < 1 || len(ref)-i-1 != minRunAbbrev || !registry.IsName(ref[:i]) || !registry.IsName(ref[i+1:]) {
		return "", "", false
	}
	return ref[:i], ref[i+1:], true
}

// sessionRun is the id of the one run under root that the session name ref names: its id ends with the name's last
// four characters and its agent is the name's agent.
func sessionRun(ref, root string) (string, bool) {
	name, end, ok := sessionShape(ref)
	if !ok {
		return "", false
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", false
	}
	found := ""
	for _, e := range entries {
		id := e.Name()
		if !ledger.IsRunID(id) || !strings.HasSuffix(id, end) {
			continue
		}
		if a, err := runAgent(filepath.Join(root, id)); err != nil || string(a) != name {
			continue
		}
		if found != "" {
			return "", false // two sessions of one name: the run ids tell them apart
		}
		found = id
	}
	return found, found != ""
}

// sessionRunIn is sessionRun under the machine's ledger root, as a run directory.
func sessionRunIn(ref string, mc *machineOnce) (string, bool) {
	if _, _, ok := sessionShape(ref); !ok {
		return "", false
	}
	m, err := mc.load()
	if err != nil {
		return "", false
	}
	root, err := ledgerRootOf(m)
	if err != nil {
		return "", false
	}
	id, ok := sessionRun(ref, root)
	if !ok {
		return "", false
	}
	return filepath.Join(root, id), true
}

// sessionStarted prints the session's name once the run has started, then tells next, if any. In a terminal (quiet)
// it is the start of the two lines a person reads around their agent: the session, its rules file and where to watch
// it live (the dashboard's run page, which a browser that opened the dashboard is signed in to).
func sessionStarted(rt *agent.RuleTable, stderr io.Writer, quiet *runTerminal, next func(tegoruntime.StartedRun) error) func(tegoruntime.StartedRun) error {
	name := ""
	if rt != nil && rt.Contract != nil {
		name = rt.Contract.Name
	}
	return func(s tegoruntime.StartedRun) error {
		// a line that cannot be written does not end the run
		if quiet != nil {
			fmt.Fprintf(stderr, "\n  ✓ Started session %s%s\n      Watch it live: http://127.0.0.1:%d/runs/%s\n\n",
				sessionName(name, string(s.ID)), quiet.rules, quiet.port, s.ID)

		}
		if next != nil {
			return next(s)
		}
		return nil
	}
}

// runTerminal is a tego run whose stderr is a terminal and that was not asked for -v: it prints a person's two lines
// (started, ended) in place of the notes and the summary a script reads.
type runTerminal struct {
	rules string // " · rules ~/.config/tego/agents/x.yaml", or ""
	port  int    // the dashboard's port
}

// quietRun is the runTerminal of a run, nil when it prints what it always has.
func quietRun(o runOptions, m *config.Machine, src *record.ContractSource, stderr io.Writer) *runTerminal {
	if ow, ok := stderr.(*outputWriter); !ok || ow.dst != os.Stderr {
		return nil // a test's buffer, or a command run inside another
	}
	if o.cmd != "" || o.verbose || !stderrIsTerminal() {
		return nil
	}
	q := &runTerminal{port: 8484}
	if m.ServePort.Source.Layer != config.LayerBuiltin && m.ServePort.Value != 0 {
		q.port = m.ServePort.Value
	}
	if src != nil && src.Path != "" {
		q.rules = " · rules " + record.Printable(tildeHome(src.Path, m.Home))
		if b, err := os.ReadFile(src.Path); err == nil {
			if l := chosenRulesLine.FindSubmatch(b); l != nil {
				q.rules += " (setup name from file comment: " + strconv.Quote(record.Printable(string(l[1]))) + ")"
			}
		}
	}
	return q
}

// chosenRulesLine is the line tego start writes into the rules files it makes (withRulesLine).
var chosenRulesLine = regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(rulesLinePrefix) + `(.+)$`)

// ended is the end line: the session, how many actions Tego blocked, and the command that shows the rest.
func (q *runTerminal) ended(stderr io.Writer, name string, sum *endSummary) bool {
	// A check mark needs a complete, verified record and an ordinary successful exit.
	// Keep the existing summary's facts whenever the abbreviated count needs qualification.
	if sum.err != nil || sum.rc == nil || sum.chain != "chain verified" || sum.recordOff || sum.how != "" ||
		!sum.rc.Ended || sum.rc.EndReason != record.RunEndExit || sum.rc.ExitCode == nil || *sum.rc.ExitCode != 0 || sum.readsLine() != "" {
		_, _ = io.WriteString(stderr, sum.text()+sum.readsLine())
		return false
	}
	session := sessionName(name, sum.run)
	what := "ended"
	if sum.how != "" {
		what = "ended: " + sum.how
	}
	blocked := ""
	if sum.rc != nil {
		n := sum.rc.Refusals.Total
		blocked = fmt.Sprintf(" · %d action%s blocked", n, map[bool]string{true: "", false: "s"}[n == 1])
	}
	fmt.Fprintf(stderr, "\n  ✓ Session %s %s%s\n      Details: tego session show %s\n", record.Printable(session), what, blocked, record.Printable(session))
	return true
}

// stderrIsTerminal reports whether standard error is a terminal; tests replace it.
var stderrIsTerminal = func() bool {
	tty := false
	_ = sys.FileDo(os.Stderr, func(fd int) error {
		_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		tty = err == nil
		return nil
	})
	return tty
}

// runMinted is when run id was minted: its time36 field, the UnixNano in base 36; zero when id is no run id.
func runMinted(id string) time.Time {
	if !ledger.IsRunID(id) {
		return time.Time{}
	}
	n, err := strconv.ParseInt(id[runHostLen:runHostLen+13], 36, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// shortAge is d as a person reads an age in a table: 45s, 12m, 5h, 3d.
func shortAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", max(0, int(d.Seconds())))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
