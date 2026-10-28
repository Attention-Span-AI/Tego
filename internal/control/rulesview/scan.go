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

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// runScan is what one pass over a run's ledger found.
type runScan struct {
	start   record.RunStartPayload
	started time.Time
	ended   bool
	lines   int
	// rules counts each rule key the lines carry; from the read model (cachedScan) it is shared and only read.
	rules map[string]int
	// execDirs is the directories of the programs the run exec'd, first seen first, from at most maxExecScan lines.
	execDirs []string
}

// maxExecScan bounds the exec lines a scan decodes for their programs' directories.
const maxExecScan = 5000

// scanRun reads the run's ledger in dir once. The first line is decoded in full (run_start); every other line's
// kind and rule are read from its common fields, which a ledger line holds before its first nested object (record's
// MarshalLine writes the common fields first and the payload after), so only exec lines are decoded. A 55k-line
// run so takes a few tens of milliseconds where decoding every line took several times that.
func scanRun(ctx context.Context, dir string) (*runScan, error) {
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }() // read-only
	sc := &runScan{rules: map[string]int{}}
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
		kind, rule, ok := commonFields(line)
		if !ok {
			e, err := record.Decode(line)
			if err != nil {
				continue // a newer writer's line, or one this binary cannot read: it names no rule shown here
			}
			kind, rule = []byte(e.Kind), []byte(e.Rule)
		}
		if len(rule) > 0 {
			sc.rules[string(rule)]++ // the conversion in a map index does not allocate
		}
		switch record.Kind(kind) {
		case record.KindRunEnd:
			sc.ended = true
		case record.KindExec:
			if execs < maxExecScan {
				execs++
				sc.addExec(line, seenDir)
			}
		}
	}
	if sc.lines == 0 {
		return nil, errors.New("the run holds no run_start yet")
	}
	return sc, nil
}

// cachedScan is scanRun's findings for a run the dashboard's read model holds: run_start read from the ledger (the
// read model keeps its common fields, not the payload a compile needs), the rest from r: its lines, its end, the
// hits per rule key (ledgerview.RuleHits: a refused action's mirror left out, so a refusal counts once as Logs counts
// it) and its programs' folders from its first maxExecScan exec lines.
func cachedScan(dir string, r *ledgerview.Run) (*runScan, error) {
	rd, err := ledger.OpenReader(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rd.Close() }() // read-only
	sc := &runScan{lines: r.Lines, ended: r.Ended, rules: ledgerview.RuleHits(r)}
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
	evs := r.AllEvents()
	for i := range evs {
		if evs[i].Kind != string(record.KindExec) {
			continue
		}
		if execs++; execs > maxExecScan {
			break
		}
		var p record.ExecPayload
		if json.Unmarshal([]byte(evs[i].Raw), &p) != nil || !filepath.IsAbs(p.Path) {
			continue
		}
		if d := filepath.Dir(p.Path); !seen[d] {
			seen[d] = true
			sc.execDirs = append(sc.execDirs, d)
		}
	}
	return sc, nil
}

// first reads the run_start line.
func (sc *runScan) first(line []byte) error {
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

var (
	keyKind = []byte(`"kind":"`)
	keyRule = []byte(`"rule":"`)
)

// commonFields reads a ledger line's kind and rule from the part before its first nested object, where the common
// fields sit. ok is false when the kind is not there or a value holds an escape: the caller then decodes the line. A
// quoted key cannot occur inside a JSON string (its quotes would be escaped), so a match is the key itself. The
// slices alias line.
func commonFields(line []byte) (kind, rule []byte, ok bool) {
	head := line
	if i := bytes.IndexByte(line[min(1, len(line)):], '{'); i >= 0 {
		head = line[:i+1]
	}
	kind, ok = stringAt(head, keyKind)
	if !ok || len(kind) == 0 {
		return nil, nil, false
	}
	if !bytes.Contains(head, keyRule) {
		return kind, nil, true // an omitted rule is ""
	}
	rule, ok = stringAt(head, keyRule)
	if !ok {
		return nil, nil, false
	}
	return kind, rule, true
}

// stringAt is the string value after key in b, when b holds key and the value has no escape and ends within b.
func stringAt(b, key []byte) ([]byte, bool) {
	i := bytes.Index(b, key)
	if i < 0 {
		return nil, false
	}
	v := b[i+len(key):]
	j := bytes.IndexByte(v, '"')
	if j < 0 || bytes.IndexByte(v[:j], '\\') >= 0 {
		return nil, false
	}
	return v[:j], true
}
