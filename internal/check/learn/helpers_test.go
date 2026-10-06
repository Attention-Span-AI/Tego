// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// run builds a record the way a ledger holds it: events in seq order, which the helpers number.
type run struct {
	t      *testing.T
	events []*record.Event
	t0     time.Time
	pid    int
}

func newRun(t *testing.T, cwd string, command ...string) *run {
	t.Helper()
	r := &run{t: t, t0: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC), pid: 100}
	if len(command) == 0 {
		command = []string{"agent"}
	}
	r.add(record.KindRunStart, "", record.RunStartPayload{Command: command, Cwd: cwd, Tier: "observe"})
	return r
}

func (r *run) add(kind record.Kind, verdict record.Verdict, payload any) *record.Event {
	r.t.Helper()
	e := &record.Event{V: record.Version, Seq: uint64(len(r.events)), Run: "r-12345678-0aaaaaaaaaaaa-abcdef", Agent: "watch-agent",
		PID: r.pid, TS: r.t0.Add(time.Duration(len(r.events)) * time.Millisecond), Kind: kind, Verdict: verdict}
	if err := e.SetPayload(payload); err != nil {
		r.t.Fatal(err)
	}
	r.events = append(r.events, e)
	return e
}

// Open flags as the kernel numbers them.
const (
	rdonly = 0
	wronly = 1
	rdwr   = 2
	creat  = 0o100
)

func (r *run) open(path string, flags int) { r.fs(record.FSOpen, path, "", flags) }

func (r *run) fs(op, path, path2 string, flags int) {
	r.add(record.KindFS, record.VerdictObserved, record.FSPayload{Op: op, Path: path, Path2: path2, Flags: flags})
}

func (r *run) exec(pid int, path string, argv ...string) {
	if len(argv) == 0 {
		argv = []string{filepath.Base(path)}
	}
	r.add(record.KindExec, record.VerdictObserved, record.ExecPayload{Path: path, Argv: argv, ExecID: "r/" + itoa(pid) + "/1"})
}

func (r *run) net(proto, dst string) {
	r.add(record.KindNet, record.VerdictObserved, record.NetPayload{Proto: proto, Dst: dst})
}

func (r *run) end(memPeak, pidsPeak uint64, ran time.Duration) {
	res := &record.Resources{MemoryPeak: &memPeak, PidsPeak: &pidsPeak}
	e := r.add(record.KindRunEnd, "", record.RunEndPayload{Reason: "exit", Resources: res})
	e.TS = r.t0.Add(ran)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// propose runs the learner over the record with options o.
func (r *run) propose(o Options) *Proposal {
	r.t.Helper()
	p, err := propose(r.events, o)
	if err != nil {
		r.t.Fatal(err)
	}
	return p
}

func propose(events []*record.Event, o Options) (*Proposal, error) {
	if o.Executable == nil {
		o.Executable = testExecutable
	}
	l := New(o)
	for _, e := range events {
		if err := l.Add(e); err != nil {
			return nil, err
		}
	}
	return l.Proposal()
}

// testMissing are the paths the tests' machine has no program at: a PATH search's misses in the records, which the
// learner tests every candidate against (Options.Executable). Every other absolute path is a program, so the tests
// and the fixtures do not depend on what the machine running them has installed.
var testMissing = map[string]bool{
	"/usr/sbin/lsb_release": true, "/usr/sbin/bash": true, "/usr/local/bin/bash": true, "/home/u/.local/bin/bash": true,
	"/home/u/bin/tool": true, "/usr/local/bin/tool": true, "/opt/missing/tool": true,
}

func testExecutable(p string) bool { return !testMissing[p] }

// section is the lines of the contract's top-level key (fs, exec, net) up to the next blank line.
func section(contract, key string) []string {
	var out []string
	in := false
	for _, l := range strings.Split(contract, "\n") {
		switch {
		case l == key+":":
			in = true
		case in && l == "":
			return out
		case in:
			out = append(out, l)
		}
	}
	return out
}

// entries are the list items of a section, unquoted, without their trailing comment.
func entries(contract, key string) []string {
	var out []string
	for _, l := range section(contract, key) {
		l = strings.TrimSpace(l)
		if rest, ok := strings.CutPrefix(l, "- \""); ok {
			v, _, _ := strings.Cut(rest, "\"  #")
			out = append(out, strings.TrimSuffix(v, "\""))
		}
	}
	return out
}

// load writes the contract into a new directory and loads it as tego does: no error, and no diagnostic.
func load(t *testing.T, contract string) *agent.Contract {
	t.Helper()
	path := filepath.Join(t.TempDir(), "learned.yaml")
	if err := os.WriteFile(path, []byte(contract), 0o600); err != nil {
		t.Fatal(err)
	}
	c, diags, err := agent.Load(path, nil)
	if err != nil {
		t.Fatalf("agent.Load: %v\n%s", err, contract)
	}
	if len(diags) > 0 {
		t.Fatalf("agent.Load diagnostics: %v\n%s", diags, contract)
	}
	return c
}
