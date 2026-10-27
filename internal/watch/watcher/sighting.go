// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The events a watcher reports. A sighting is a report about a process; none of them is an action on it.
const (
	EventAgentStarted = "agent_started"   // a process a rule names, and where it stands against a governed run
	EventAgentExited  = "agent_exited"    // that process exited (its descendants may still run)
	EventChildForked  = "child_forked"    // only with Options.Children: a followed process forked
	EventChildExec    = "child_exec"      // only with Options.Children: a followed child ran a program
	EventChildExited  = "child_exited"    // only with Options.Children: a followed child exited
	EventSessionDrop  = "session_dropped" // a session left the bounded tree; its processes are no longer followed
	EventUntracked    = "untracked"       // a session is at the process cap and a child was not followed
	EventResync       = "resync"          // events were lost and /proc was read again
)

// The events of `tego agents --follow --adopt` (ADR 0055): the guard's own lines, beside the
// watcher's. They are about an adoption, which acts on a process; the watcher's lines never are.
const (
	EventAdopted         = "adopted"          // the agent's tree moved into a run, which records it from the kernel
	EventAdoptionRefused = "adoption_refused" // the agent is not adopted, and why (Rule, Note); nothing was done to it
	EventAdoptionFailed  = "adoption_failed"  // the adoption began and failed before it recorded; what moved went back
	EventAdoptionEnded   = "adoption_ended"   // the adoption's run ended (Reason: exit, stopped, error)
)

// How an agent came to be seen.
const (
	SeenExec = "exec" // the kernel reported its exec
	SeenScan = "scan" // /proc held it when the watcher looked: it predates the watcher, or its exec event was lost
)

// maxArgvBytes caps the argv a sighting carries. An argument vector can be megabytes; a report of one process
// must not be.
const maxArgvBytes = 4096

// Sighting is one line of the watcher's report. The same type is the JSON line (`tego agents --json`) and the
// source of the text line. Fields that do not apply to an event are absent.
type Sighting struct {
	Event   string   `json:"event"`
	Time    string   `json:"time"`
	Session uint64   `json:"session,omitempty"`
	PID     int32    `json:"pid,omitempty"`
	PPID    int32    `json:"ppid,omitempty"`
	Exe     string   `json:"exe,omitempty"`
	Argv    []string `json:"argv,omitempty"`
	// ArgvTruncated says Argv holds only the first arguments (maxArgvBytes).
	ArgvTruncated bool   `json:"argv_truncated,omitempty"`
	Comm          string `json:"comm,omitempty"`
	// Rule is the name of the signature that matched.
	Rule string `json:"rule,omitempty"`
	Seen string `json:"seen,omitempty"`
	// OutsideGovernedRun is true when the agent runs in no tego run's cgroup: it was not started by `tego run`
	// or `tego watch`, or it was moved out of the run. It is present on agent_started only.
	OutsideGovernedRun *bool `json:"outside_governed_run,omitempty"`
	// RunID is the TEGO_RUN_ID in the process's environment, whether or not its cgroup agrees: an environment
	// is copied into any child. RunCgroupID is the run its cgroup names. Governed means the second is set.
	RunID       string `json:"run_id,omitempty"`
	RunCgroupID string `json:"run_cgroup_id,omitempty"`
	Cgroup      string `json:"cgroup,omitempty"`
	// ExitCode is the exit status; Signal the signal number that ended the process, 0 for an exit.
	ExitCode *int `json:"exit_code,omitempty"`
	Signal   int  `json:"signal,omitempty"`
	// Descendants counts the processes the agent's session ever held beyond the agent itself. StillRunning counts
	// those alive when the agent exited.
	Descendants  int `json:"descendants,omitempty"`
	StillRunning int `json:"still_running,omitempty"`
	// Dropped and Untracked say how many processes were given up under the caps.
	Dropped   int    `json:"dropped,omitempty"`
	Untracked int    `json:"untracked,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Note      string `json:"note,omitempty"`
	// Start is the process's start time (/proc/<pid>/stat starttime, clock ticks since boot): with PID, its identity,
	// on agent_started and the adoption events.
	Start uint64 `json:"start,omitempty"`
	// UID is the process's user id, on the adoption events.
	UID *int `json:"uid,omitempty"`
	// Run is the run an adoption records the agent into; Moved how many processes it moved; WindowMS how long after
	// the agent was found the record began (everything before is a gap of the run's).
	Run      string `json:"run,omitempty"`
	Moved    int    `json:"moved,omitempty"`
	WindowMS *int64 `json:"window_ms,omitempty"`
}

// Emit receives each sighting. A non-nil error (the output is gone) stops the watcher.
type Emit func(Sighting) error

// JSONLines is an Emit that writes each sighting as one JSON object and a newline.
func JSONLines(w io.Writer) Emit {
	var mu sync.Mutex
	return func(s Sighting) error {
		b, err := json.Marshal(s)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		_, err = w.Write(append(b, '\n'))
		return err
	}
}

// Text is an Emit that writes each sighting as one readable line. Every string a process controls (its path, its
// arguments) is made printable first: a name with a terminal escape in it is shown, not run.
func Text(w io.Writer) Emit {
	var mu sync.Mutex
	return func(s Sighting) error {
		line := s.TextLine()
		mu.Lock()
		defer mu.Unlock()
		_, err := io.WriteString(w, line+"\n")
		return err
	}
}

// TextLine is the sighting as one line of text.
func (s Sighting) TextLine() string {
	var b strings.Builder
	b.WriteString(s.Time)
	b.WriteString(" ")
	b.WriteString(s.Event)
	f := func(k string, v any) { fmt.Fprintf(&b, " %s=%v", k, v) }
	if s.Session != 0 {
		f("session", s.Session)
	}
	if s.PID != 0 {
		f("pid", s.PID)
	}
	if s.PPID != 0 {
		f("ppid", s.PPID)
	}
	if s.UID != nil {
		f("uid", *s.UID)
	}
	if s.Rule != "" {
		f("rule", s.Rule)
	}
	if s.Run != "" {
		f("run", s.Run)
	}
	if s.Moved != 0 {
		f("moved", s.Moved)
	}
	if s.WindowMS != nil {
		f("window-ms", *s.WindowMS)
	}
	if s.Seen != "" {
		f("seen", s.Seen)
	}
	if s.OutsideGovernedRun != nil {
		if *s.OutsideGovernedRun {
			b.WriteString(" OUTSIDE-GOVERNED-RUN")
		} else {
			f("governed-by", s.RunCgroupID)
		}
	}
	if s.RunID != "" && s.RunID != s.RunCgroupID {
		f("env-run-id", s.RunID)
	}
	if s.ExitCode != nil {
		if s.Signal != 0 {
			f("signal", s.Signal)
		} else {
			f("exit", *s.ExitCode)
		}
	}
	if s.Descendants != 0 {
		f("descendants", s.Descendants)
	}
	if s.StillRunning != 0 {
		f("still-running", s.StillRunning)
	}
	if s.Dropped != 0 {
		f("dropped", s.Dropped)
	}
	if s.Untracked != 0 {
		f("untracked", s.Untracked)
	}
	if s.Reason != "" {
		f("reason", s.Reason)
	}
	if s.Exe != "" {
		f("exe", record.Printable(s.Exe))
	}
	if len(s.Argv) > 0 {
		f("argv", fmt.Sprintf("%q", s.Argv)) // %q escapes every control character, so no argument can carry a terminal escape
		if s.ArgvTruncated {
			b.WriteString("...")
		}
	}
	if s.Note != "" {
		f("note", record.Printable(s.Note))
	}
	return b.String()
}

// capArgv keeps whole arguments up to maxArgvBytes. At least the first argument is kept, shortened if need be.
func capArgv(argv []string) ([]string, bool) {
	total := 0
	for i, a := range argv {
		if total+len(a) > maxArgvBytes {
			if i == 0 {
				return []string{a[:maxArgvBytes]}, true
			}
			return argv[:i], true
		}
		total += len(a)
	}
	return argv, false
}
