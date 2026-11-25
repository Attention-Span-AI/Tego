// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// runScan is what one pass over a run's ledger found.
type runScan struct {
	// firstLine is the run_start line the scan decoded, kept so the scan can cross to the worker (scanWire) and be
	// decoded there again, in place of the run's whole ledger being read twice more.
	firstLine []byte
	start     record.RunStartPayload
	started   time.Time
	ended     bool
	lines     int
	// rules counts each rule key the lines carry; from the read model (cachedScan) it is shared and only read.
	rules map[string]int
	// unmatched counts, by line kind, the lines whose rule is unmatched (the defaults decided them), so each counts
	// on the default of the group that decided it (inforce's CountDefault).
	unmatched map[string]int
	// commands counts the allowed exec lines by the exec.allow entry with command words that admitted them
	// (command_rule, command_list allow): every such line, not only the first maxExecScan.
	commands map[string]int
	// execDirs is the directories of the programs the run exec'd, first seen first, from at most maxExecScan lines.
	execDirs []string
}

// maxExecScan bounds the exec lines a scan decodes for their programs' directories.
const maxExecScan = 5000

// scanRun reads the run's ledger in dir once. The first line is decoded in full (run_start); every other line's kind,
// rule and, for an exec line, its command entry are read as data by record.Strings, which takes the members of a
// line's top level whatever their order or spelling (no search of the line's text), without decoding the payload;
// only exec lines' programs are decoded, only the first maxExecScan of them, and not those that run from a folder the scan
// has listed already.
func scanRun(ctx context.Context, dir string) (*runScan, error) {
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }() // read-only
	sc := &runScan{rules: map[string]int{}, unmatched: map[string]int{}, commands: map[string]int{}}
	execs := 0
	seenDir := map[string]bool{}
	for line, err := range r.Lines() {
		if err != nil {
			return nil, err
		}
		sc.lines++
		if sc.lines&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		if sc.lines == 1 {
			if err := sc.first(line); err != nil {
				return nil, err
			}
			continue
		}
		// The line is read as data (record.Strings), whatever the order of its keys or the spelling of its tokens; a
		// line the decoder refuses (a newer writer's, or one this binary cannot read) names no rule shown here.
		f, err := record.Strings(line, keyKind, keyRule, keyVerdict, keyCommandRule, keyCommandList, keyPath)
		if err != nil {
			continue
		}
		kind, rule := f[0], f[1]
		if rule != "" {
			sc.rules[rule]++
			if rule == agent.UnmatchedRule {
				sc.unmatched[kind]++
			}
		}
		switch record.Kind(kind) {
		case record.KindRunEnd:
			sc.ended = true
		case record.KindExec:
			sc.addCommand(f[2], f[4], f[3])
			if execs < maxExecScan {
				execs++
				if !knownProgramDir(f[5], seenDir) {
					sc.addExec(line, seenDir)
				}
			}
		}
	}
	if sc.lines == 0 {
		return nil, errors.New("the run holds no run_start yet")
	}
	return sc, nil
}

// knownProgramDir reports whether path, the "path" member Strings read from an exec line, is an absolute path in a folder
// already listed: the line then adds nothing, whether its full decode (addExec) would succeed or not, so it is not
// decoded. A path that is not valid UTF-8 is always decoded: the full decode spells it its own way.
func knownProgramDir(path string, seen map[string]bool) bool {
	return path != "" && filepath.IsAbs(path) && utf8.ValidString(path) && seen[filepath.Dir(path)]
}

// cachedScan is scanRun's findings for a run the dashboard's read model holds: run_start read from the ledger (the
// read model keeps its common fields, not the payload a compile needs), the rest from r: its lines, its end, the
// hits per rule key (ledgerview.RuleHits: a refused action's mirror left out, so a refusal counts once as Logs counts
// it), its unmatched lines by kind (mirrors left out alike) and its programs' folders from its first maxExecScan exec
// lines.
func cachedScan(dir string, r *ledgerview.Run) (*runScan, error) {
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rd.Close() }() // read-only
	sc := &runScan{lines: r.Lines, ended: r.Ended, rules: ledgerview.RuleHits(r), commands: map[string]int{}}
	next, stop := iter.Pull2(rd.Lines())
	defer stop()
	line, err, ok := next()
	switch {
	case !ok:
		return nil, errors.New("the run holds no run_start yet")
	case err != nil:
		return nil, err
	}
	if err := sc.first(line); err != nil {
		return nil, err
	}
	execs := 0
	seen := map[string]bool{}
	sc.unmatched = map[string]int{}
	evs := r.AllEvents()
	for i := range evs {
		if evs[i].Rule == agent.UnmatchedRule && !evs[i].Mirror {
			sc.unmatched[evs[i].Kind]++
		}
		if evs[i].Kind == string(record.KindExec) && strings.Contains(evs[i].Raw, `"command_rule":"`) {
			var c struct {
				CommandRule string `json:"command_rule"`
				CommandList string `json:"command_list"`
			}
			if json.Unmarshal([]byte(evs[i].Raw), &c) == nil {
				sc.addCommand(evs[i].Verdict, c.CommandList, c.CommandRule)
			}
		}
		if evs[i].Kind != string(record.KindExec) || execs >= maxExecScan {
			continue
		}
		execs++
		p := evs[i].ExecPath() // the path the read model decoded: no second decode of the line
		if !filepath.IsAbs(p) {
			continue
		}
		if d := filepath.Dir(p); !seen[d] {
			seen[d] = true
			sc.execDirs = append(sc.execDirs, d)
		}
	}
	return sc, nil
}

// addCommand counts an exec line the exec.allow entry rule admitted: allowed, with the entry's list allow. A line
// that names a command rule under another list (a refusal's deny entry, a constrained tool's unlisted invocation) is
// no entry's use.
func (sc *runScan) addCommand(verdict, list, rule string) {
	if verdict == string(record.VerdictAllow) && list == "allow" && rule != "" {
		sc.commands[rule]++
	}
}

// first reads the run_start line.
func (sc *runScan) first(line []byte) error {
	sc.firstLine = bytes.Clone(line)
	e, err := record.Decode(line)
	if err != nil {
		return fmt.Errorf("its first line: %w", err)
	}
	if e.Kind != record.KindRunStart {
		return fmt.Errorf("its first line is %s, not run_start", e.Kind)
	}
	if err := e.DecodePayload(&sc.start); err != nil {
		return fmt.Errorf("run_start: %w", err)
	}
	sc.started = e.TS
	return nil
}

// addExec records the directory of the program an exec line ran.
func (sc *runScan) addExec(line []byte, seen map[string]bool) {
	e, err := record.Decode(line)
	if err != nil {
		return
	}
	var p record.ExecPayload
	if e.DecodePayload(&p) != nil || !filepath.IsAbs(p.Path) {
		return
	}
	if d := filepath.Dir(p.Path); !seen[d] {
		seen[d] = true
		sc.execDirs = append(sc.execDirs, d)
	}
}

// moreDirs is the directories of the programs the run exec'd that are not on path, ":"-joined (loadCopy's moreDirs).
func (sc *runScan) moreDirs(path string) string {
	on := map[string]bool{}
	for _, d := range strings.Split(path, ":") {
		on[d] = true
	}
	var out []string
	for _, d := range sc.execDirs {
		if !on[d] {
			out = append(out, d)
		}
	}
	return strings.Join(out, ":")
}

// The members of a line the scan reads (record.Strings).
const (
	keyKind        = "kind"
	keyRule        = "rule"
	keyVerdict     = "verdict"
	keyCommandRule = "command_rule"
	keyCommandList = "command_list"
	keyPath        = "path" // an exec line's program
)

// scanWire is a runScan on its way to the worker that composes the view (viewRequest.Scan): the caller reads the
// ledger once, or takes the findings from the read model (memoScan), and the worker, which a fresh process starts for
// every exchange and which therefore keeps nothing from one to the next, reads none of it. The run_start line is
// carried as it was written and decoded there by the same code (first), so what the worker holds is what a scan of
// its own finds, field for field (TestInForceViewIsTheSameWhoeverScans).
type scanWire struct {
	StartLine       []byte
	RunEnded        bool
	LinesRead       int
	HitsByRule      map[string]int
	UnmatchedByKind map[string]int
	UsesByCommand   map[string]int
	ProgramDirs     []string
}

func (sc *runScan) toWire() *scanWire {
	return &scanWire{StartLine: sc.firstLine, RunEnded: sc.ended, LinesRead: sc.lines, HitsByRule: sc.rules, UnmatchedByKind: sc.unmatched, UsesByCommand: sc.commands, ProgramDirs: sc.execDirs}
}

// decode is the runScan the wire carries; an error is the run_start line no longer decoding.
func (w *scanWire) decode() (*runScan, error) {
	sc := &runScan{ended: w.RunEnded, lines: w.LinesRead, rules: w.HitsByRule, unmatched: w.UnmatchedByKind, commands: w.UsesByCommand, execDirs: w.ProgramDirs}
	if err := sc.first(w.StartLine); err != nil {
		return nil, err
	}
	return sc, nil
}
