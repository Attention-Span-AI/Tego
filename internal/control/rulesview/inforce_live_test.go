// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/inforce"
	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// addBlocks adds an exec and a path block to the fixture's run (serials 1 and 2).
func addBlocks(t *testing.T, f *fixture) {
	t.Helper()
	_, err := liveblock.Update(context.Background(), f.dir, f.run, func(o *liveblock.Overlay) (bool, error) {
		if _, _, err := o.Add(liveblock.KindExec, "curl", "uid:1000 pid:42 cli", time.Now()); err != nil {
			return false, err
		}
		_, ok, err := o.Add(liveblock.KindPath, "/p/data", "uid:1000 pid:42 cli", time.Now())
		return ok, err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// confirm appends the launcher's gap line confirming serial.
func confirm(f *fixture, kind, value string, serial int) {
	f.add(fmt.Sprintf(`"kind":"gap","source":"launcher","what":"enforce","why":"live-block-added","live_block":{"op":"add","kind":"%s","value":"%s","rule":"live.block[%s:%s]","by":"uid:1000 pid:42 cli","serial":%d,"at":"2026-10-27T12:00:00Z"}`,
		kind, value, kind, value, serial))
}

// liveRules is the view's live group by rule key.
func liveRules(v *InForceView) map[string]inforce.Rule {
	out := map[string]inforce.Rule{}
	for _, r := range v.View.Group(inforce.GroupLive).Rules {
		out[r.RuleKey] = r
	}
	return out
}

// TestInForceLiveStatus: on an enforcing run a block is waiting until the launcher's gap line confirms its serial, then
// in force; a path block on a run that does not see its reads refuses changes only. Nothing says "Refused by tego
// until the run ends".
func TestInForceLiveStatus(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000014-liveb2")
	addBlocks(t, f)
	confirm(f, "exec", "curl", 1)
	v := f.inForce(t)
	got := liveRules(v)
	exec, path := got["live.block[exec:curl]"], got["live.block[path:/p/data]"]
	if exec.EnforcedText != livestatus.SentenceInForce || exec.Sentence != "Blocked now: cannot run curl" {
		t.Errorf("confirmed exec: %q / %q", exec.EnforcedText, exec.Sentence)
	}
	if path.EnforcedText != livestatus.SentenceWaiting || !strings.HasPrefix(path.Sentence, "Blocking: ") {
		t.Errorf("unconfirmed path: %q / %q", path.EnforcedText, path.Sentence)
	}
	confirm(f, "path", "/p/data", 2)
	v = f.inForce(t)
	path = liveRules(v)["live.block[path:/p/data]"]
	if path.EnforcedText != livestatus.SentencePartial || path.Sentence != "Blocked now: cannot change /p/data (reads still go through)" {
		t.Errorf("confirmed path, reads not seen: %q / %q", path.EnforcedText, path.Sentence)
	}
	for _, r := range v.View.Group(inforce.GroupLive).Rules {
		if strings.Contains(r.EnforcedText, "Refused by tego until the run ends") {
			t.Errorf("%s still says the old claim", r.RuleKey)
		}
	}
}

// TestInForceLiveStatusWatched: on a tego watch run every block reads "Recorded, not enforced", confirmed or not.
func TestInForceLiveStatusWatched(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000015-liveb3")
	c, _, err := agent.LoadBytes(f.source, []byte(sourceText), &agent.ProfileChain{})
	if err != nil {
		t.Fatal(err)
	}
	sum, _ := c.Hash()
	f.lines.Reset()
	f.seq = 0
	f.add(fmt.Sprintf(`"kind":"run_start","source":"supervisor","tier":"observe","command":["sh"],"cwd":"%s","contract_hash":"%s","contract_source":{"path":"%s"},"fs_reads":{"reads":"direct","why":"records-only"},"reads_notified":{"notified":false,"why":"records-only"}`,
		f.proj, hex.EncodeToString(sum[:]), f.source))
	addBlocks(t, f)
	confirm(f, "exec", "curl", 1)
	confirm(f, "path", "/p/data", 2)
	v := f.inForce(t)
	for key, r := range liveRules(v) {
		if r.EnforcedText != livestatus.SentenceRecordedOnly || r.State != inforce.StateNotEnforced || !strings.HasPrefix(r.Sentence, "Marked now") {
			t.Errorf("%s on a watched run: %q / %s / %q", key, r.EnforcedText, r.State, r.Sentence)
		}
	}
	if len(liveRules(v)) != 2 {
		t.Fatalf("live rules = %d, want 2", len(liveRules(v)))
	}
}
