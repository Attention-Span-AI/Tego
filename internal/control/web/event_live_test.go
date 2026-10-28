// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// liveFixture is a ledger root with actRun at tier: run_start, then, when confirmed > 0, the launcher's gap line
// what=enforce why=live-block-added carrying overlay serial confirmed (line #1).
func liveFixture(t *testing.T, tier string, confirmed uint64) (*Server, *ledgerview.Run) {
	t.Helper()
	root := t.TempDir()
	proj := filepath.Join(t.TempDir(), "proj")
	evs := []*record.Event{ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: tier, Capture: "off",
		ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: proj, Kernel: "6", StopGrace: "1s"})}
	if confirmed > 0 {
		evs = append(evs, ledgertest.Event(t, record.KindGap, record.GapPayload{What: record.GapEnforce, Why: record.GapLiveBlockAdded,
			LiveBlock: &record.LiveBlockChange{Op: "add", Kind: "read", Value: "/p/vault", Rule: "live.block[read:/p/vault]",
				By: "uid:1000 pid:9 dashboard", Serial: confirmed, At: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}},
			func(e *record.Event) { e.Source = record.SourceSupervisor }))
	}
	writeLines(t, root, actRun, evs)
	s := newServer(t, root)
	rr, err := ledgerview.LoadRun(root, actRun)
	if err != nil {
		t.Fatal(err)
	}
	return s, rr
}

// TestSavedLiveOutcomeStates: a Saved change's "Also apply now" line says what the block does to its run now, from
// the run's own record, never from the write alone: "Putting it in force on this run…" until the launcher's
// confirming gap line carries the block's serial, "Live now on this run, in force since line #N" once it does, and
// "Recorded only on this run (watched run)" on a tego watch run, which refuses nothing.
func TestSavedLiveOutcomeStates(t *testing.T) {
	for _, c := range []struct {
		name            string
		tier            string
		confirmed       uint64
		serial          uint64
		state, contains string
	}{
		{"before the launcher's line", "landlock", 0, 1, ledgerview.LiveWaiting, "Putting it in force on this run…"},
		{"an older serial confirmed", "landlock", 1, 2, ledgerview.LiveWaiting, "Putting it in force on this run…"},
		{"confirmed", "landlock", 1, 1, ledgerview.LiveInForce, "Live now on this run, in force since line #1"},
		{"a later serial confirmed", "landlock", 3, 1, ledgerview.LiveInForce, "Live now on this run, in force since line #1"},
		{"a watched run", "observe", 1, 1, ledgerview.LiveRecordedOnly, "Recorded only on this run (watched run)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, rr := liveFixture(t, c.tier, c.confirmed)
			v := &actView{Live: []liveOut{{LiveResult: rules.LiveResult{Run: actRun, Block: "read:/p/vault", OK: true, Serial: c.serial},
				This: true, Shown: "read:/p/vault"}}}
			s.settleLive(v, rr)
			o := v.Live[0]
			got := o.Before + "this run" + o.After
			if o.State != c.state || !strings.Contains(got, c.contains) {
				t.Errorf("state %q, line %q; want %q with %q", o.State, got, c.state, c.contains)
			}
			if strings.Contains(got, "Waiting") {
				t.Errorf("the line says Waiting: %q", got)
			}
			if v.Observe != (c.tier == "observe") {
				t.Errorf("Observe = %v", v.Observe)
			}
		})
	}
	// A placement whose serial the page does not know is looked up in the overlay; with no overlay it is never in force.
	s, rr := liveFixture(t, "landlock", 4)
	v := &actView{Live: []liveOut{{LiveResult: rules.LiveResult{Run: actRun, Block: "read:/p/vault", OK: true}, This: true}}}
	s.settleLive(v, rr)
	if v.Live[0].State != ledgerview.LiveWaiting {
		t.Errorf("an unknown serial reads %q, want waiting", v.Live[0].State)
	}
}

// TestWatchedRunMarksRecordedOnly: on a tego watch run the event page's Act panel offers "Also apply now" as
// recorded only and its Block now as "Mark … (recorded only)", and the Saved panel says "Recorded only on this run".
func TestWatchedRunMarksRecordedOnly(t *testing.T) {
	s, c, contract, _ := askServer(t)
	// The ask fixture's run, re-recorded as a watched run.
	b := readFile(t, filepath.Join(s.cfg.Ledger, actRun, "events.jsonl"))
	writeRaw(t, filepath.Join(s.cfg.Ledger, actRun, "events.jsonl"), strings.Replace(b, `"tier":"landlock"`, `"tier":"observe"`, 1))
	holdLock(t, filepath.Join(s.cfg.Ledger, actRun))
	line := "/runs/" + actRun + "/lines/4"
	preview := do(s, "GET", line+"?a=block&level=0", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the watched exec preview", preview, "Also apply now", "recorded only (watched run), nothing is refused")
	page := do(s, "GET", "/runs/"+actRun+"/lines/3?level=0", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the watched read's panel", page, "Mark now, in this watched run", "(recorded only)</span></span></button>")
	if strings.Contains(page, "Block now, in this live run") {
		t.Error("a watched run's panel offers Block now")
	}
	saved := follow(t, s, c, post(s, line, url.Values{"csrf": {s.csrf}, "a": {"block"}, "level": {"0"}, "base": {baseOf(t, preview)}, "now": {actRun}}, own, "", c))
	mustContain(t, "the watched saved state", saved, "Recorded only on", `data-state="recorded_only"`)
	if strings.Contains(saved, "Live now on") {
		t.Error("a watched run's saved state says Live now")
	}
	_ = contract
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeRaw(t *testing.T, p, text string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}
