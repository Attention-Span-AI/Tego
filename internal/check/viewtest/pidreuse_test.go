// SPDX-License-Identifier: Apache-2.0

package viewtest

import (
	"bytes"
	"reflect"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/drift"
	"github.com/attention-span-ai/tego/internal/check/events"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func execAt(t *testing.T, pid int, execID string) *record.Event {
	t.Helper()
	e := &record.Event{Kind: record.KindExec, Source: record.SourceSeccomp, PID: pid, TID: pid, MonoNS: 1,
		Rule: "exec[rg]", Verdict: record.VerdictAllow, Authority: record.AuthorityRule, Attr: record.Unattributed()}
	if err := e.SetPayload(record.ExecPayload{Path: "/usr/bin/rg", Argv: []string{"rg"}, ExecID: execID}); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestViewsIgnoreAReusedPID is limits-check-doctor-cli.md §6 case 6 (E6): the kernel handing a pid to a second
// process during one run changes nothing in the views. Two exec events that share pid 42 under different exec_ids
// are two actions in drift's counts and two lines of events; the run reads exactly as it does when the pids
// differ, because no view keys anything by the bare pid.
func TestViewsIgnoreAReusedPID(t *testing.T) {
	rt := &agent.RuleTable{Exec: []agent.ExecRule{{Raw: "rg", Basename: "rg", Verdict: agent.VerdictAllow, Source: "exec.allow"}}}
	type view struct {
		sections []struct {
			Section drift.Section
			Counts  []drift.RuleCount
		}
		lines int
	}
	run := func(pids [2]int) view {
		dir := writeRun(t,
			execAt(t, pids[0], "r/"+strconv.Itoa(pids[0])+"/100"),
			execAt(t, pids[1], "r/"+strconv.Itoa(pids[1])+"/900"))
		rep, err := drift.ComputeCtx(t.Context(), reader(t, dir), rt)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if _, err := eventsJSON(t, &buf, dir, events.Filter{Kinds: []record.Kind{record.KindExec}}); err != nil {
			t.Fatal(err)
		}
		return view{rep.Sections(), bytes.Count(buf.Bytes(), []byte("\n"))}
	}
	reused, distinct := run([2]int{42, 42}), run([2]int{42, 43})
	if reused.lines != 2 {
		t.Fatalf("events lists %d exec lines for a reused pid, want 2", reused.lines)
	}
	if !reflect.DeepEqual(reused, distinct) {
		t.Fatalf("a reused pid changed the views:\nreused   %+v\ndistinct %+v", reused, distinct)
	}
	for _, s := range reused.sections {
		if s.Section == drift.SectionExec && (len(s.Counts) != 1 || s.Counts[0].Total() != 2) {
			t.Fatalf("exec counts %+v, want the one declared rule counted twice", s.Counts)
		}
	}
}
