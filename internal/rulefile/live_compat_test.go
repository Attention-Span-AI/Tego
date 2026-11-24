// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"encoding/json"
	"strings"
	"testing"
)

// olderLive is a live outcome as a tego from before the owner fields reads it: Run, Block, OK, Err and Lift, the rest of
// the line ignored, as encoding/json ignores a field it does not name.
type olderLive struct {
	Run   string `json:"run"`
	Block string `json:"block"`
	OK    bool   `json:"ok"`
	Err   string `json:"err"`
	Lift  bool   `json:"lift"`
}

// placed is how that reader decides a block was placed (Live.Placed before the owner fields); preLiftPlaced is how a
// tego from before the lift field decided it: it ignores Lift too.
func (l olderLive) placed() bool        { return l.OK && !l.Lift && l.Block != "" }
func (l olderLive) preLiftPlaced() bool { return l.OK && l.Block != "" }

// lifted is how that reader says a block was lifted.
func (l olderLive) lifted() bool { return l.OK && l.Lift && l.Block != "" }

// TestOlderReadersNeverReadAnOutcomeAsAllowed: each outcome a writer now journals, read by a tego that knows
// only Run, Block, OK, Err and Lift (every release so far), and by one that does not know Lift either (a build from
// before 2026-10-27, which no release was): none reads a block that is still in force as lifted or as not blocked, and
// only a block really in force is read as placed. The one reading that is not exact is the oldest reader's of a finished
// lift, which it reads as a block placed: it says "blocked" of a block that is gone, the restrictive error, never
// "allowed" for one that holds.
func TestOlderReadersNeverReadAnOutcomeAsAllowed(t *testing.T) {
	const run, block = "r-aaaa-0001-x", "exec:cat"
	for _, tc := range []struct {
		name string
		l    Live
		// inForce: the block refuses on the run after this outcome. liftDone: the line records a lift that took effect.
		inForce, liftDone bool
	}{
		{"placed by a change", Live{OK: true, By: LiveByChange, Serial: 5}, true, false},
		{"held already", Live{Held: true, By: LiveByChange, Serial: 3, Err: "the run already held this block"}, true, false},
		{"placement failed", Live{Err: "the run is not running", By: LiveByChange}, false, false},
		{"lift begun", Live{Lift: true, Pending: true, By: LiveByUndo, Err: "lifted was begun and its end was not recorded"}, true, false},
		{"lift done", Live{OK: true, Lift: true, By: LiveByUndo, Serial: 7}, false, true},
		{"lift failed", Live{Lift: true, By: LiveByUndo, Err: "not lifted: the run's live rules changed"}, true, false},
		{"redo begun", Live{Pending: true, By: LiveByRedo, Err: "put back was begun and its end was not recorded"}, false, false},
		{"redo done", Live{OK: true, By: LiveByRedo, Serial: 9}, true, false},
		{"redo found it held", Live{Held: true, By: LiveByRedo, Err: "the run already held this block"}, true, false},
		{"redo failed", Live{By: LiveByRedo, Err: "not put back: the run is not running"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.l.Run, tc.l.Block = run, block
			b, err := json.Marshal(tc.l)
			if err != nil {
				t.Fatal(err)
			}
			var old olderLive
			if err := json.Unmarshal(b, &old); err != nil {
				t.Fatalf("an older reader cannot read %s: %v", b, err)
			}
			if old.Run != run || old.Block != block {
				t.Errorf("an older reader reads %s as %+v", b, old)
			}
			// A reader that knows Lift: lifted only where a lift took effect; placed only where the block holds.
			if old.lifted() != tc.liftDone {
				t.Errorf("an older reader says lifted=%v of %s", old.lifted(), b)
			}
			if old.placed() && !tc.inForce {
				t.Errorf("an older reader says placed of a block that is not in force: %s", b)
			}
			if tc.l.Placed() && !old.placed() || old.placed() && !tc.l.Placed() && tc.l.By == LiveByChange {
				t.Errorf("this reader and an older one differ on placed for %s: %v and %v", b, tc.l.Placed(), old.placed())
			}
			// A reader that does not know Lift: it may say placed of a finished lift (blocked, the restrictive error), and
			// of nothing else that is not in force.
			if old.preLiftPlaced() && !tc.inForce && !tc.liftDone {
				t.Errorf("the oldest reader says placed of a block that is not in force: %s", b)
			}
			// This reader reads its own line back as written.
			var back Live
			if err := json.Unmarshal(b, &back); err != nil || back != tc.l {
				t.Errorf("read back %+v, %v; want %+v", back, err, tc.l)
			}
			if tc.l.Lifted() != tc.liftDone {
				t.Errorf("Lifted() = %v of %s", tc.l.Lifted(), b)
			}
		})
	}
}

// TestOutcomeLinesFromBeforeTheOwnerFields: a line an older tego wrote reads as before (placed, or lifted), with no owner
// and no serial, and a line with none of the new fields set is the same bytes an older tego wrote.
func TestOutcomeLinesFromBeforeTheOwnerFields(t *testing.T) {
	var placed, lifted, failed Live
	for line, l := range map[string]*Live{
		`{"run":"r","block":"exec:x","ok":true}`:                                    &placed,
		`{"run":"r","block":"exec:x","ok":true,"lift":true}`:                        &lifted,
		`{"run":"r","block":"exec:x","ok":false,"err":"not lifted: x","lift":true}`: &failed,
	} {
		if err := json.Unmarshal([]byte(line), l); err != nil {
			t.Fatal(err)
		}
		if l.By != "" || l.Serial != 0 || l.Held || l.Pending {
			t.Errorf("%s read with owner fields: %+v", line, *l)
		}
		if b, err := json.Marshal(*l); err != nil || string(b) != line {
			t.Errorf("%s written back as %s, %v", line, b, err)
		}
	}
	if !placed.Placed() || placed.Lifted() || lifted.Placed() || !lifted.Lifted() || failed.Placed() || failed.Lifted() {
		t.Errorf("old lines read wrong: placed %+v lifted %+v failed %+v", placed, lifted, failed)
	}
}

// TestFoldSettlesBegunLines: the line written before a lift or a placement is replaced by the line that says how it
// ended; one with nothing after it stays and says the work was begun and its end was not recorded.
func TestFoldSettlesBegunLines(t *testing.T) {
	begun := func(run, block string, lift bool) Live {
		return Live{Run: run, Block: block, Lift: lift, Pending: true, By: LiveByUndo, Err: "begun"}
	}
	es := []Entry{
		{V: 1, ID: "rc-1", Op: OpChange, Contract: "/a.yaml"},
		{V: 1, ID: "rc-2", Op: OpRevert, Contract: "/a.yaml", Reverts: "rc-1"},
		{V: 1, ID: "rc-3", Op: OpLive, Of: "rc-2", Live: []Live{begun("r1", "exec:cat", true), begun("r2", "exec:cat", true)}},
		{V: 1, ID: "rc-4", Op: OpLive, Of: "rc-2", Live: []Live{{Run: "r1", Block: "exec:cat", OK: true, Lift: true, By: LiveByUndo, Serial: 4}}},
		{V: 1, ID: "rc-5", Op: OpLive, Of: "rc-2", Live: []Live{begun("r3", "exec:cat", false)}},
		{V: 1, ID: "rc-6", Op: OpLive, Of: "rc-2", Live: []Live{{Run: "r3", Block: "exec:cat", OK: true, By: LiveByRedo, Serial: 6}}},
	}
	got := Fold(es, nil)[0].Live
	var words []string
	for _, l := range got {
		switch {
		case l.Pending:
			words = append(words, "begun "+l.Run)
		case l.Lift:
			words = append(words, "lift "+l.Run)
		default:
			words = append(words, "placed "+l.Run)
		}
	}
	if want := "begun r2,lift r1,placed r3"; strings.Join(words, ",") != want {
		t.Errorf("settled outcomes %q, want %q", strings.Join(words, ","), want)
	}
	// The lift of r2 was begun, never finished: it does not count as a lift that took effect.
	for _, l := range got {
		if l.Run == "r2" && (l.Lifted() || l.Placed()) {
			t.Errorf("an unfinished lift reads as done: %+v", l)
		}
	}
}
