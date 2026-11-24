// SPDX-License-Identifier: Apache-2.0

package liveblock

import "testing"

// TestPauseWaitingMatchesTheOldRules: PauseWaiting is the one rule tego status and the dashboard shared as two
// copies; over every combination of serials and states it gives what each copy's own expression gave.
func TestPauseWaitingMatchesTheOldRules(t *testing.T) {
	for asked := uint64(0); asked < 4; asked++ {
		for confirmed := uint64(0); confirmed < 4; confirmed++ {
			for _, askedPaused := range []bool{false, true} {
				for _, paused := range []bool{false, true} {
					cliOld := asked > confirmed && askedPaused != paused // tego status
					webOld := asked > confirmed && askedPaused != paused // the dashboard
					got := PauseWaiting(asked, askedPaused, confirmed, paused)
					if got != cliOld || got != webOld {
						t.Errorf("asked %d/%v confirmed %d/%v: %v, old %v %v", asked, askedPaused, confirmed, paused, got, cliOld, webOld)
					}
				}
			}
		}
	}
}

// TestLastControl: the last pause or resume the overlay lists, whatever blocks follow it; none when it lists none.
func TestLastControl(t *testing.T) {
	var o Overlay
	if _, ok := o.LastControl(); ok {
		t.Fatal("an empty overlay lists a control change")
	}
	o.Changes = []Change{{Serial: 1, Op: OpPause}, {Serial: 2, Op: OpResume}, {Serial: 3, Op: OpAdd, Kind: KindExec, Value: "x"}}
	c, ok := o.LastControl()
	if !ok || c.Serial != 2 || c.Op != OpResume {
		t.Errorf("LastControl = %+v %v, want the resume of serial 2", c, ok)
	}
	o.Changes = o.Changes[2:]
	if _, ok := o.LastControl(); ok {
		t.Error("an overlay with only a block lists a control change")
	}
}
