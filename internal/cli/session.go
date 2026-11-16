// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/registry"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
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

// sessionStarted prints the session's name once the run has started, then tells next, if any.
func sessionStarted(rt *agent.RuleTable, stderr io.Writer, next func(tegoruntime.StartedRun) error) func(tegoruntime.StartedRun) error {
	name := ""
	if rt != nil && rt.Contract != nil {
		name = rt.Contract.Name
	}
	return func(s tegoruntime.StartedRun) error {
		fmt.Fprintf(stderr, "✓ Session %s started\n", sessionName(name, string(s.ID))) // a line that cannot be written does not end the run
		if next != nil {
			return next(s)
		}
		return nil
	}
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
