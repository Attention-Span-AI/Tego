// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"strings"
	"testing"
)

// racerReport is execracer's tally: what each attempt's own process saw (test/workloads/execracer).
type racerReport struct{ attempts, eacces, ran, other, busy int }

// recordLossGaps are the gaps of records the run lost on their way to the ledger: past one, a race cell's ledger
// cannot hold one line an attempt, so the cell checks it for consistency with the loss it states.
var recordLossGaps = []string{"ringbuf-full", "channel-full", "exec-fragment-overflow"}

// gapCounts sums the run's gap lines by why.
func gapCounts(events []map[string]any) map[string]int {
	gaps := map[string]int{}
	for _, e := range events {
		if e["kind"] == "gap" {
			c, _ := e["count"].(float64)
			gaps[fmt.Sprint(e["why"])] += max(int(c), 1)
		}
	}
	return gaps
}

// pinRaceWant is what a K6 race cell expects of its attempts.
type pinRaceWant struct {
	// refusedReason is the plane_reason of the bprm_check refusal an attempt refused EACCES has ("": none expected).
	refusedReason string
	// killedReason is the plane_reason of the kill an attempt that ended otherwise has ("": none expected).
	killedReason string
	// killErr is the kill_failed every kill's line carries (0: none does).
	killErr int
	// swap says the race swaps links, writing no image: every attempt is refused EACCES or runs, none ETXTBSY.
	swap bool
}

// pinRaceVerdict is a race cell's judgement: the problems that fail it, the notes it logs, and the ledger's tally.
type pinRaceVerdict struct {
	problems, notes                  []string
	ran, refused, killed, busy, odd  int
	lost                             int
	runEnd                           map[string]any
	pinRefused, endKilled, endFailed int
}

// judgePinRace decides a K6 race cell. The racer's per-attempt outcomes decide what the kernel did: every attempt
// is accounted for, and none ended in a way the cell rules out (a swap race: refused EACCES or ran, nothing else).
// The ledger is the record of those decisions, and it is how the cell knows no attempt ran an image other than the
// one decided: a pinned exec that ran says kernel_pinned only when the kernel's held sample for its own pin arrived
// (the plane matched the image the kernel opened against the pin), and any exec line that is neither such a run, the
// plane's refusal nor its kill fails the cell. With no record lost the ledger must equal the outcomes, one line an
// attempt, and run_end must count the refusals and kills it holds. Only in the two swap cells (w.swap: ADR 0048 R4's
// ruling), when the run says it lost records (a gap line with its count), is the ledger checked for consistency
// instead: it never holds more lines of a kind than attempts that ended so, the attempts without a line are no more
// than the records said lost, and run_end's counts lie between the ledger's and the racer's. Every other race cell,
// the kill cells included, keeps the exact check whatever the run says it lost, and a loss without its gap line
// leaves the ledger short and fails the exact check in every cell.
func judgePinRace(rep racerReport, events []map[string]any, w pinRaceWant) pinRaceVerdict {
	var v pinRaceVerdict
	fail := func(f string, a ...any) { v.problems = append(v.problems, fmt.Sprintf(f, a...)) }
	if rep.attempts <= 0 || rep.eacces+rep.ran+rep.other+rep.busy != rep.attempts {
		fail("%+v: the racer's outcomes do not account for its attempts", rep)
	}
	if w.swap && (rep.other != 0 || rep.busy != 0) {
		fail("%+v: a swap race's attempt neither ran nor was refused EACCES", rep)
	}
	if w.refusedReason == "" && rep.eacces != 0 {
		fail("%+v: an attempt was refused EACCES where the cell expects no refusal", rep)
	}
	if w.killedReason == "" && rep.other != 0 {
		fail("%+v: an attempt ended otherwise where the cell expects no kill", rep)
	}
	for _, e := range events {
		if e["kind"] != "exec" || strings.HasSuffix(fmt.Sprint(e["path"]), "/bin/execracer") {
			continue
		}
		switch {
		case e["syscall_ret"] == float64(-26):
			v.busy++ // ETXTBSY: the racer's write held the file
		case e["verdict"] == "refused" && e["rule"] == "exec.pin" && e["signal"] == nil && w.refusedReason != "":
			v.refused++
			if e["plane_reason"] != w.refusedReason {
				fail("a pin refusal: %v, want plane_reason %s", e, w.refusedReason)
			}
		case e["verdict"] == "refused" && e["rule"] == "exec.pin" && e["signal"] == "SIGKILL" && w.killedReason != "":
			v.killed++
			if w.killErr == 0 && (e["plane_reason"] != w.killedReason || e["kill_failed"] != nil) ||
				w.killErr != 0 && (e["plane_reason"] != w.killedReason || e["kill_failed"] != float64(w.killErr) ||
					e["detected_bypass"] != true) {
				fail("a kill: %v, want plane_reason %s and kill_failed %d", e, w.killedReason, w.killErr)
			}
		case e["verdict"] != "refused" && e["argv_facts"] == "kernel_pinned":
			v.ran++
		default:
			if v.odd++; v.odd <= 3 {
				fail("an exec line that is neither a pinned run, the plane's refusal nor its kill: %v", e)
			}
		}
	}
	if v.odd > 3 {
		fail("%d exec lines in all are neither a pinned run, the plane's refusal nor its kill", v.odd)
	}
	gaps := gapCounts(events)
	var lossWhy []string
	for _, e := range events {
		why := fmt.Sprint(e["why"])
		if e["kind"] != "gap" || !isRecordLoss(why) {
			continue
		}
		if c, ok := e["count"].(float64); !ok || c < 1 {
			fail("a %s gap line without the count of records lost: %v", why, e)
		}
	}
	for _, why := range recordLossGaps {
		if gaps[why] != 0 {
			v.lost += gaps[why]
			lossWhy = append(lossWhy, fmt.Sprintf("%s: %d", why, gaps[why]))
		}
	}
	for _, e := range events {
		if e["kind"] == "run_end" {
			sup, _ := e["supervisor"].(map[string]any)
			v.runEnd, _ = sup["exec_rules"].(map[string]any)
			if v.runEnd == nil {
				v.runEnd = map[string]any{}
			}
		}
	}
	if v.runEnd == nil {
		fail("the run has no run_end line")
		return v
	}
	count := func(k string) int { c, _ := v.runEnd[k].(float64); return int(c) }
	v.pinRefused, v.endKilled, v.endFailed = count("pin_refused"), count("killed"), count("kill_failed")
	if v.lost == 0 || !w.swap {
		why := "and no gap says a record was lost"
		if v.lost != 0 {
			why = fmt.Sprintf("and a stated loss (%s) is tolerated only in the two swap cells", strings.Join(lossWhy, ", "))
		}
		if v.refused != rep.eacces || v.killed != rep.other || v.ran != rep.ran || v.busy != rep.busy {
			fail("%+v: the ledger has %d refusals, %d kills, %d pinned runs and %d ETXTBSY, %s", rep, v.refused,
				v.killed, v.ran, v.busy, why)
		}
		wantFailed := any(nil)
		if w.killErr != 0 && v.killed != 0 {
			wantFailed = float64(v.killed)
		}
		if v.refused != 0 && v.runEnd["pin_refused"] != float64(v.refused) ||
			v.killed != 0 && v.runEnd["killed"] != float64(v.killed) || v.runEnd["kill_failed"] != wantFailed {
			fail("run_end exec_rules %v, want pin_refused %d, killed %d and kill_failed %v", v.runEnd, v.refused,
				v.killed, wantFailed)
		}
		if w.killErr != 0 && gaps["exec-pin-kill-failed"] != v.killed {
			fail("%d exec-pin-kill-failed gaps, want one a kill (%d)", gaps["exec-pin-kill-failed"], v.killed)
		}
		return v
	}
	v.notes = append(v.notes, fmt.Sprintf("the run lost %d records (%s), each stated by a gap line: the attempts' "+
		"outcomes are the racer's, and the ledger is checked for consistency with the loss", v.lost,
		strings.Join(lossWhy, ", ")))
	if v.refused > rep.eacces || v.killed > rep.other || v.ran > rep.ran || v.busy > rep.busy {
		fail("%+v: the ledger has %d refusals, %d kills, %d pinned runs and %d ETXTBSY, more of a kind than the "+
			"attempts that ended so", rep, v.refused, v.killed, v.ran, v.busy)
	}
	if missing := rep.attempts - v.refused - v.killed - v.ran - v.busy; missing > v.lost {
		fail("%+v: %d attempts have no exec line, more than the %d records the run says it lost", rep, missing, v.lost)
	} else if missing > 0 {
		v.notes = append(v.notes, fmt.Sprintf("%d attempts have no exec line; the run's gap lines account for them",
			missing))
	}
	if v.pinRefused < v.refused || v.pinRefused > rep.eacces || v.endKilled < v.killed || v.endKilled > rep.other {
		fail("run_end exec_rules %v: pin_refused and killed must lie between the ledger's %d and %d and the racer's "+
			"%d and %d", v.runEnd, v.refused, v.killed, rep.eacces, rep.other)
	}
	wantFailed := 0
	if w.killErr != 0 {
		wantFailed = v.endKilled
	}
	if v.endFailed != wantFailed {
		fail("run_end exec_rules %v: kill_failed %d, want %d", v.runEnd, v.endFailed, wantFailed)
	}
	if f := gaps["exec-pin-kill-failed"]; w.killErr != 0 && (f < v.killed || f > rep.other) {
		fail("%d exec-pin-kill-failed gaps, want between the ledger's %d kills and the racer's %d", f, v.killed, rep.other)
	}
	return v
}

func isRecordLoss(why string) bool {
	for _, w := range recordLossGaps {
		if why == w {
			return true
		}
	}
	return false
}

// raceLedger is a swap race's ledger as judgePinRace reads it: one line an attempt, the given gap lines and run_end.
func raceLedger(refused, ran int, gaps map[string]int) []map[string]any {
	var ev []map[string]any
	for range refused {
		ev = append(ev, map[string]any{"kind": "exec", "path": "/p/out/l", "verdict": "refused", "rule": "exec.pin",
			"plane_reason": "pin-mismatch"})
	}
	for range ran {
		ev = append(ev, map[string]any{"kind": "exec", "path": "/p/out/l", "verdict": "allow", "argv_facts": "kernel_pinned"})
	}
	for why, n := range gaps {
		ev = append(ev, map[string]any{"kind": "gap", "why": why, "count": float64(n)})
	}
	return append(ev, map[string]any{"kind": "run_end", "supervisor": map[string]any{
		"exec_rules": map[string]any{"pin_refused": float64(refused)}}})
}

// TestJudgePinRace holds the swap cells' judgement on ledgers made to its cases: the kernel's per-attempt outcomes
// decide, a stated loss leaves the ledger checked for consistency, and a silent loss or a run of an image other than
// the one decided fails.
func TestJudgePinRace(t *testing.T) {
	swap := pinRaceWant{refusedReason: "pin-mismatch", swap: true}
	rep := racerReport{attempts: 1000, eacces: 438, ran: 562}
	swapped := raceLedger(438, 561, map[string]int{"ringbuf-full": 1997})
	swapped = append(swapped, map[string]any{"kind": "exec", "path": "/p/out/l", "verdict": "allow",
		"argv_facts": "unproven"})
	silent := raceLedger(438, 561, nil)
	cases := []struct {
		name   string
		rep    racerReport
		events []map[string]any
		fail   string // "": passes; else a word of the expected problem
	}{
		{"exact", rep, raceLedger(438, 562, nil), ""},
		// u617-bpf, TestPlaneRunExecPinInterpreterSwap/bpflsm@lsm, 2026-11-18: one pinned run's line lost in a ring
		// overrun the run states.
		{"stated loss", rep, raceLedger(438, 561, map[string]int{"ringbuf-full": 1997}), ""},
		// u617-bpf, TestPlaneRunExecPinSymlinkSwap/cgroup@lsm: records lost, every attempt's line kept.
		{"stated loss, ledger whole", racerReport{attempts: 1000, eacces: 450, ran: 550},
			raceLedger(450, 550, map[string]int{"channel-full": 334}), ""},
		{"silent loss", rep, silent, "no gap says a record was lost"},
		{"swapped run beside a stated loss", rep, swapped, "neither a pinned run"},
		{"swapped run counted as a pinned one", rep, func() []map[string]any {
			ev := raceLedger(438, 562, nil)
			ev[438]["argv_facts"] = "copied_syscall"
			return ev
		}(), "neither a pinned run"},
		{"loss larger than stated", rep, raceLedger(400, 500, map[string]int{"ringbuf-full": 10}), "more than the 10 records"},
		{"more lines than outcomes", rep, raceLedger(439, 561, map[string]int{"ringbuf-full": 5}), "more of a kind"},
		{"a kill in a swap race", racerReport{attempts: 1000, eacces: 437, ran: 562, other: 1},
			raceLedger(437, 562, map[string]int{"ringbuf-full": 5}), "neither ran nor was refused"},
		{"ETXTBSY in a swap race", racerReport{attempts: 1000, eacces: 437, ran: 562, busy: 1},
			raceLedger(437, 562, nil), "neither ran nor was refused"},
		{"outcomes short of attempts", racerReport{attempts: 1000, eacces: 438, ran: 561},
			raceLedger(438, 561, nil), "do not account"},
		{"loss gap without its count", rep, func() []map[string]any {
			ev := raceLedger(438, 561, nil)
			return append(ev, map[string]any{"kind": "gap", "why": "ringbuf-full"})
		}(), "without the count"},
		{"run_end past the racer", rep, func() []map[string]any {
			ev := raceLedger(438, 561, map[string]int{"ringbuf-full": 3})
			ev[len(ev)-1]["supervisor"].(map[string]any)["exec_rules"].(map[string]any)["pin_refused"] = float64(439)
			return ev
		}(), "must lie between"},
	}
	// A kill cell (TestPlaneRunExecPinScriptRewrite and the like, through checkPinRace) keeps the exact check: a stated
	// loss that leaves an attempt without its line fails it, as it did before the swap cells' tolerance.
	kill := pinRaceWant{refusedReason: "pin-mismatch", killedReason: "pin-mismatch"}
	killRep := racerReport{attempts: 1000, eacces: 400, ran: 500, other: 100}
	killLedger := func(killed int, gaps map[string]int) []map[string]any {
		ev := raceLedger(400, 500, gaps)
		end := ev[len(ev)-1]
		ev = ev[:len(ev)-1]
		for range killed {
			ev = append(ev, map[string]any{"kind": "exec", "path": "/p/out/l", "verdict": "refused", "rule": "exec.pin",
				"signal": "SIGKILL", "plane_reason": "pin-mismatch"})
		}
		end["supervisor"].(map[string]any)["exec_rules"].(map[string]any)["killed"] = float64(killed)
		return append(ev, end)
	}
	for _, c := range []struct {
		name   string
		events []map[string]any
		fail   string
	}{
		{"kill cell, exact", killLedger(100, nil), ""},
		{"kill cell, stated loss leaving a kill without its line", killLedger(99, map[string]int{"ringbuf-full": 1997}),
			"tolerated only in the two swap cells"},
		{"kill cell, silent loss", killLedger(99, nil), "no gap says a record was lost"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := strings.Join(judgePinRace(killRep, c.events, kill).problems, "\n")
			switch {
			case c.fail == "" && got != "":
				t.Errorf("judged failing, want passing:\n%s", got)
			case c.fail != "" && !strings.Contains(got, c.fail):
				t.Errorf("problems %q, want one that says %q", got, c.fail)
			}
		})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := judgePinRace(c.rep, c.events, swap)
			got := strings.Join(v.problems, "\n")
			switch {
			case c.fail == "" && got != "":
				t.Errorf("judged failing, want passing:\n%s", got)
			case c.fail != "" && !strings.Contains(got, c.fail):
				t.Errorf("problems %q, want one that says %q", got, c.fail)
			case c.fail != "":
				t.Logf("fails, as it must: %.300s", got)
			}
		})
	}
}
