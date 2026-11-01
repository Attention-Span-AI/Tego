// SPDX-License-Identifier: Apache-2.0

// dashgen writes a big ledger root for measuring the dashboard (docs/DASHBOARD.md "Read model"): -runs ended runs
// of -lines lines each, one run of -big lines, and one live run, every one through the ledger's own Writer and
// anchored in -anchor, so the chain verifies as a real run's does. It never touches a real ledger: -root and
// -anchor are required.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func main() {
	root := flag.String("root", "", "ledger root to write (required, must not exist)")
	anchor := flag.String("anchor", "", "chain anchor file (required)")
	runs := flag.Int("runs", 300, "ended runs")
	lines := flag.Int("lines", 500, "lines per ended run")
	big := flag.Int("big", 200_000, "lines of the one big run (0 for none)")
	flag.Parse()
	if *root == "" || *anchor == "" {
		fmt.Fprintln(os.Stderr, "dashgen: -root and -anchor are required")
		os.Exit(2)
	}
	if _, err := os.Stat(*root); err == nil {
		fmt.Fprintln(os.Stderr, "dashgen: -root exists; give a new directory")
		os.Exit(2)
	}
	if err := generate(*root, *anchor, *runs, *lines, *big); err != nil {
		fmt.Fprintln(os.Stderr, "dashgen:", err)
		os.Exit(1)
	}
}

// clock is a scripted clock: each line one millisecond after the last.
type clock struct{ t time.Time }

func (c *clock) Now() time.Time { c.t = c.t.Add(time.Millisecond); return c.t }
func (c *clock) Mono() uint64   { return uint64(c.t.UnixNano()) }

func generate(root, anchor string, runs, lines, big int) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	c := &clock{t: time.Now().Add(-time.Duration(runs+2) * time.Hour)}
	for i := range runs {
		c.t = c.t.Add(time.Hour)
		if err := writeRun(root, anchor, c, i, lines, true); err != nil {
			return err
		}
	}
	if big > 0 {
		c.t = c.t.Add(time.Hour)
		if err := writeRun(root, anchor, c, runs, big, true); err != nil {
			return err
		}
	}
	c.t = time.Now().Add(-time.Minute)
	if err := writeRun(root, anchor, c, runs+1, lines, false); err != nil {
		return err
	}
	return nil
}

// contract is the contract.yaml each run keeps a copy of, as a real run does (the dashboard reads its lists).
const contract = `agent: demo-agent
fs:
  write: [./out]
  deny_read: [~/.ssh, ~/.aws, .env]
  ask: [./held]
exec:
  allow: [git, sh, curl]
net:
  allow: ["tcp://api.example.com:443"]
`

func runID(i int) string { return fmt.Sprintf("r-da5b0a2d-%013d-%06d", i, i) }

func writeRun(root, anchor string, c *clock, i, n int, end bool) error {
	id := runID(i)
	agent := []string{"claude-code", "codex", "supply-chain", "demo-agent"}[i%4]
	w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: agent},
		ledger.WithAnchor(ledger.NewFileChainAnchor(anchor)), ledger.WithClock(c), ledger.WithContract([]byte(contract)))
	if err != nil {
		return err
	}
	start := record.RunStartPayload{LauncherPID: 4821, LauncherStartNS: 1, TegoVersion: "0.1.0-dev", Commit: "dashgen",
		Tier: "landlock", Capture: "forwarder", Kernel: "6.17.0", ContractHash: strings.Repeat("7a", 32),
		Parsers: map[string]string{"anthropic": "1", "mcp": "1", "openai": "0"}, StopGrace: "10s",
		Command: []string{"sh", "agent.sh"}, Cwd: "/home/u/proj"}
	if err := w.WriteRunStart(start); err != nil {
		return err
	}
	for j := 1; j < n-1; j++ {
		e, err := line(j)
		if err != nil {
			return err
		}
		if err := w.Append(e); err != nil {
			return err
		}
	}
	if !end {
		if err := w.Abandon(); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Join(root, ".live"), 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(root, ".live", id), nil, 0o600)
	}
	return w.Close(record.RunEndPayload{Reason: "exit"})
}

// line is the j-th line of a run: mostly file reads and writes, some execs and connections, a refusal every 17th
// line (folding into a handful of groups) and a system-lookup refusal every 101st.
func line(j int) (*record.Event, error) {
	e := &record.Event{PID: 4822, TID: 4822, Cgroup: 9, Attr: record.Unattributed()}
	var p any
	switch {
	case j%101 == 0:
		e.Kind, e.Source, e.Rule, e.Reason = record.KindRefused, record.SourceSupervisor, "unmatched", "net-not-allowed"
		p = record.RefusedPayload{Op: "connect", Target: "unix:/var/run/nscd/socket", Reason: "net-not-allowed", Rule: "unmatched"}
	case j%17 == 0:
		e.Kind, e.Source, e.Rule, e.Reason = record.KindRefused, record.SourceSupervisor, "unmatched", "exec-not-allowed"
		p = record.RefusedPayload{Op: "exec", Target: fmt.Sprintf("/usr/bin/tool%d", j%7), Reason: "exec-not-allowed", Rule: "unmatched"}
	case j%13 == 0:
		e.Kind, e.Source, e.Rule, e.Verdict, e.Authority = record.KindNet, record.SourceSupervisor, "net.allow[tcp://api.example.com:443]", record.VerdictAllow, record.AuthorityRule
		p = record.NetPayload{Proto: "tcp", Dst: "93.184.216.34:443", Host: "api.example.com"}
	case j%7 == 0:
		e.Kind, e.Source, e.Rule, e.Verdict, e.Authority = record.KindExec, record.SourceSupervisor, "exec.allow[git]", record.VerdictAllow, record.AuthorityRule
		p = record.ExecPayload{Path: "/usr/bin/git", Argv: []string{"git", "status", fmt.Sprintf("--n=%d", j)}, ExecID: fmt.Sprintf("r/4822/%d", j)}
	default:
		e.Kind, e.Source, e.Rule, e.Verdict, e.Authority = record.KindFS, record.SourceLandlock, "fs.write[./out]", record.VerdictAllow, record.AuthorityRule
		p = record.FSPayload{Op: record.FSOpen, Path: fmt.Sprintf("out/file-%d.txt", j%500), Flags: 0x241}
	}
	if e.Kind == record.KindRefused {
		e.Attr = nil // a refused line carries no attribution (record.Validate)
	}
	if err := e.SetPayload(p); err != nil {
		return nil, err
	}
	return e, nil
}
