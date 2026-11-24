// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/events"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const stepRun = "r-aaaa-0900-stepxx"

// stepFixture is a ledger with every kind of tie: an action that the writer left unattributed (step omitted, so 0, method time), an action stamped {likely, time, step 0}, steps 1 to 3 by
// each method, an action of step 1 written late (after lines of step 3), a line stamped {unattributed, none}, and lines of
// kinds that carry no attribution at all.
func stepFixture() []string {
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Second) }
	attr := func(conf, method string, step int, extra string) string {
		s := fmt.Sprintf(`"attribution":{"confidence":"%s","method":"%s"`, conf, method)
		if step > 0 {
			s += fmt.Sprintf(`,"step":%d`, step)
		}
		return s + extra + `}`
	}
	act := func(seq int, kind, extra string) string {
		body := `"rule":"unmatched","verdict":"allow","authority":"rule",` + extra
		switch kind {
		case "exec":
			body += `,"argv":["x"]`
		case "fs":
			body += `,"op":"open","path":"/p/f"`
		case "net":
			body += `,"op":"connect","dst":"1.2.3.4:443"`
		}
		return line(stepRun, "a", seq, at(seq), kind, body)
	}
	return []string{
		line(stepRun, "a", 0, at(0), "run_start", `"tier":"landlock","command":["sh"]`),
		act(1, "exec", attr("unattributed", "time", 0, "")),                      // before the first request, writer's own words
		act(2, "fs", attr("likely", "time", 0, "")),                              // the spec's {likely, time, step 0}
		act(3, "net", attr("likely", "time", 1, "")),                             // step 1
		act(4, "exec", attr("likely", "tool_id", 2, `,"tool_use_id":"toolu_1"`)), // step 2
		act(5, "fs", attr("likely", "tid", 3, "")),                               // step 3
		line(stepRun, "a", 6, at(6), "ask", `"ask_id":"ask-1","hold":"exec"`),    // carries no attribution
		act(7, "net", attr("likely", "time", 3, "")),                             // step 3
		act(8, "exec", attr("likely", "time", 1, "")),                            // step 1, written after step 3
		act(9, "fs", attr("unattributed", "none", 0, "")),                        // no capture
		line(stepRun, "a", 10, at(10), "run_end", `"reason":"exit","exit_code":0`),
	}
}

// TestStepFilterIsWhatTheCLIPrints: the dashboard's step:N term and tego events --step N are one reader
// (record.Event.ModelStep), so for every N they select the same lines of the same ledger, including the line
// stamped unattributed (which no step number claims) and the action written late.
func TestStepFilterIsWhatTheCLIPrints(t *testing.T) {
	root := t.TempDir()
	lines := stepFixture()
	writeRun(t, root, stepRun, lines...)
	snap, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	cli := func(step int) []uint64 {
		var out []uint64
		f := events.Filter{Steps: []int{step}}
		for _, l := range lines {
			e, err := record.Decode([]byte(strings.TrimSpace(l)))
			if err != nil {
				t.Fatal(err)
			}
			if f.Match(e) {
				out = append(out, e.Seq)
			}
		}
		return out
	}
	dash := func(query string) []uint64 {
		f, _, err := ParseQuery(query)
		if err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		f.PageSize = 1000
		var out []uint64
		for _, r := range snap.Query(f).Rows {
			out = append(out, r.Seq)
		}
		slices.Sort(out)
		return out
	}
	want := map[string][]uint64{"0": {2}, "1": {3, 8}, "2": {4}, "3": {5, 7}, "4": nil, "none": {0, 1, 6, 9, 10}}
	for step, q := range map[string]int{"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "none": NoStep} {
		got := cli(q)
		if !slices.Equal(got, want[step]) {
			t.Errorf("events --step %d printed seq %v, want %v", q, got, want[step])
		}
		if d := dash("run:" + stepRun + " step:" + step); !slices.Equal(d, got) {
			t.Errorf("step:%s lists seq %v, but events --step %d prints %v", step, d, q, got)
		}
	}
	if d := dash("run:" + stepRun + " step:1 step:3"); !slices.Equal(d, []uint64{3, 5, 7, 8}) {
		t.Errorf("step:1 step:3 lists %v, want either step", d)
	}
	if d := dash("run:" + stepRun + " step:1 kind:net"); !slices.Equal(d, []uint64{3}) {
		t.Errorf("step:1 kind:net lists %v, want seq 3", d)
	}
	for _, bad := range []string{"step:x", "step:-3", "step:", "-step:1"} {
		if _, _, err := ParseQuery(bad); err == nil {
			t.Errorf("%q: no error; the query must say what it cannot read", bad)
		}
	}
}

// TestStepNoneListsARefusalOnce: a refused action is two lines, the action (tied to a step) and a standalone refused
// line, its mirror, that carries no attribution. tego events --step -1 prints both kinds of line it is given; Logs shows
// a refusal once, with its action (pair.go), so for step:none the two readers differ by exactly the mirrors, and for a
// tied step they do not. The Logs help says so; this is the one exception to "the same lines".
func TestStepNoneListsARefusalOnce(t *testing.T) {
	run := "r-aaaa-0900-mirrxx"
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Second) }
	lines := []string{
		line(run, "a", 0, at(0), "run_start", `"tier":"landlock","command":["sh"]`),
		line(run, "a", 1, at(1), "fs", `"rule":"fs.deny_read","verdict":"refused","authority":"rule","reason":"fs-gate","op":"open","path":"/home/x/.ssh/id","attribution":{"confidence":"likely","method":"tool_id","step":3,"tool_use_id":"toolu_1"}`),
		line(run, "a", 2, at(1), "refused", `"rule":"fs.deny_read","reason":"fs-gate","op":"open","target":"/home/x/.ssh/id"`),
		line(run, "a", 3, at(2), "run_end", `"reason":"exit","exit_code":0`),
	}
	root := t.TempDir()
	writeRun(t, root, run, lines...)
	snap, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	cli := func(f events.Filter) []uint64 {
		var out []uint64
		for _, l := range lines {
			e, err := record.Decode([]byte(strings.TrimSpace(l)))
			if err != nil {
				t.Fatal(err)
			}
			if f.Match(e) {
				out = append(out, e.Seq)
			}
		}
		return out
	}
	dash := func(q string) []uint64 {
		f, _, err := ParseQuery("run:" + run + " " + q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		f.PageSize = 1000
		var out []uint64
		for _, r := range snap.Query(f).Rows {
			out = append(out, r.Seq)
		}
		slices.Sort(out)
		return out
	}
	for _, c := range []struct {
		q         string
		f         events.Filter
		dash, cli []uint64
	}{
		{"step:3", events.Filter{Steps: []int{3}}, []uint64{1}, []uint64{1}},
		{"step:none", events.Filter{Steps: []int{NoStep}}, []uint64{0, 3}, []uint64{0, 2, 3}},
		{"step:3 verdict:refused", events.Filter{Steps: []int{3}, Verdicts: []record.Verdict{"refused"}}, []uint64{1}, []uint64{1}},
	} {
		if d := dash(c.q); !slices.Equal(d, c.dash) {
			t.Errorf("%s: Logs lists %v, want %v", c.q, d, c.dash)
		}
		if g := cli(c.f); !slices.Equal(g, c.cli) {
			t.Errorf("%s: tego events prints %v, want %v", c.q, g, c.cli)
		}
	}
}

func TestStepHeadsGroupConsecutiveRowsOfOneStep(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, stepRun, stepFixture()...)
	snap, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	run := snap.Find(stepRun)
	if run.StepLines != 6 {
		t.Fatalf("StepLines %d, want the 6 lines tied to a step", run.StepLines)
	}
	rows := TimelineOf(run, false).Rows(0, 100)
	GroupSteps(rows, run)
	var got []string // newest first, as the page shows them
	for _, r := range rows {
		if r.StepHead != "" {
			got = append(got, fmt.Sprintf("[%s]", r.StepHead))
		}
		got = append(got, fmt.Sprint(r.Seq))
	}
	text := strings.Join(got, " ")
	// A line the record ties to no step (the ask 6, the run_start and run_end, the line stamped unattributed) closes the
	// group around it and sits under the header "Not tied to a model step", never under the step above it.
	want := "[Not tied to a model step] 10 9 [After model request 1, matched by time (likely)] 8 " +
		"[After model request 3, matched by time (likely)] 7 [Not tied to a model step] 6 [Model step 3 (likely)] 5 [Model step 2 (likely)] 4 " +
		"[After model request 1, matched by time (likely)] 3 [Step 0, matched by time (likely)] 2 [Not tied to a model step] 1 0"
	if text != want {
		t.Errorf("headers\n%s\nwant\n%s", text, want)
	}
	// A row that stands for several folded lines can span steps: it closes the group and has a header of its own, and
	// the steps either side of it repeat theirs.
	step := func(n int) Event {
		return Event{Step: n, StepMethod: record.MethodToolID, stepTied: true}
	}
	folded := []Row{{Event: step(2)}, {Event: step(2), Count: 3}, {Event: step(2)}, {Event: step(2)}}
	GroupSteps(folded, &Run{StepLines: 1})
	var fg []string
	for _, r := range folded {
		fg = append(fg, r.StepHead+"|"+r.StepKey)
	}
	if g := strings.Join(fg, " ; "); g != "Model step 2 (likely)|2/tool_id ; "+stepFolded+"|"+StepFolded+" ; Model step 2 (likely)|2/tool_id ; |2/tool_id" {
		t.Errorf("a folded row among rows of step 2:\n%s", g)
	}
	// A run whose lines the record ties to no step shows no header at all.
	root2 := t.TempDir()
	t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	r2 := "r-aaaa-0901-nosteps"
	writeRun(t, root2, r2,
		line(r2, "a", 0, t0, "run_start", `"tier":"landlock","command":["sh"]`),
		line(r2, "a", 1, t0.Add(time.Second), "exec", `"rule":"unmatched","verdict":"allow","authority":"rule","argv":["x"],"attribution":{"confidence":"unattributed","method":"none"}`))
	s2, err := Load(root2)
	if err != nil {
		t.Fatal(err)
	}
	rows2 := TimelineOf(s2.Find(r2), false).Rows(0, 10)
	GroupSteps(rows2, s2.Find(r2))
	for _, r := range rows2 {
		if r.StepHead != "" || r.StepKey != "" {
			t.Errorf("a run with no tied line has a header %q on seq %d", r.StepHead, r.Seq)
		}
	}
}
