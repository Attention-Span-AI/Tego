// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
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

// watchedReads is a watched run's reads as its run_start records them: seen by nobody, the run only records.
const watchedReads = `,"fs_reads":{"reads":"direct","why":"records-only"},"reads_notified":{"notified":false,"why":"records-only"}`

// restart begins the fixture's ledger again with a run_start of tier, the rules file's hash and source, and extra (more
// fields, each after a comma).
func restart(t *testing.T, f *fixture, tier, extra string) {
	t.Helper()
	c, _, err := agent.LoadBytes(f.source, []byte(sourceText), &agent.ProfileChain{})
	if err != nil {
		t.Fatal(err)
	}
	sum, _ := c.Hash()
	f.lines.Reset()
	f.seq = 0
	f.add(fmt.Sprintf(`"kind":"run_start","source":"supervisor","tier":"%s","command":["sh"],"cwd":"%s","contract_hash":"%s","contract_source":{"path":"%s"}%s`,
		tier, f.proj, hex.EncodeToString(sum[:]), f.source, extra))
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
	restart(t, f, "observe", watchedReads)
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

// endedLive is the view's EndedLive by rule key.
func endedLive(v *InForceView) map[string]inforce.Rule {
	out := map[string]inforce.Rule{}
	for _, r := range v.EndedLive {
		out[r.RuleKey] = r
	}
	return out
}

// TestInForceEndedRunSaysWhatEachBlockDid: an ended run's live blocks refuse nothing, so the live group stays empty,
// and each is listed in EndedLive by what it did while the run ran: "Was blocked" only for a block whose add the
// launcher confirmed, with "(reads went through)" for a path block on a run that did not see its reads, "Never put in
// force" for one it never confirmed, and "Was marked (recorded, not refused)" on a watched run, confirmed or not. Each
// is ended with no claim, keeps who added it and the hits of the lines under its key, and the note says only that the
// blocks refuse nothing now (the marks record nothing). While the run runs, EndedLive is empty.
func TestInForceEndedRunSaysWhatEachBlockDid(t *testing.T) {
	line := func(verdict string, n int) string {
		return fmt.Sprintf(`"kind":"exec","source":"seccomp","rule":"live.block[exec:curl]","verdict":"%s","authority":"rule","argv":["curl"],"exec_id":"x/10/%d","path":"/usr/bin/curl"`, verdict, n)
	}
	const blocksNote, marksNote = "The run has ended, so its 2 live blocks refuse nothing now.", "The run has ended, so its 2 live marks record nothing now."
	for _, tc := range []struct {
		name        string
		tier, extra string // "": the fixture's landlock run, which does not see its reads
		confirmed   []int  // the serials the launcher confirmed: 1 adds curl, 2 the path block
		hits        string // the verdict of curl's two lines, "" for none
		curl, path  string
		note        string
	}{
		{"curl in force, the path block never", "", "", []int{1}, "refused",
			"Was blocked: cannot run curl", "Never put in force: cannot open or change /p/data", blocksNote},
		{"nothing confirmed", "", "", nil, "",
			"Never put in force: cannot run curl", "Never put in force: cannot open or change /p/data", blocksNote},
		{"both in force, reads not seen", "", "", []int{1, 2}, "refused",
			"Was blocked: cannot run curl", "Was blocked: cannot change /p/data (reads went through)", blocksNote},
		{"both in force, reads seen", "landlock", `,"fs_reads":{"reads":"held","why":"contract"}`, []int{1, 2}, "refused",
			"Was blocked: cannot run curl", "Was blocked: cannot open or change /p/data", blocksNote},
		{"watched", "observe", watchedReads, []int{1, 2}, "observed",
			"Was marked (recorded, not refused): cannot run curl", "Was marked (recorded, not refused): cannot open or change /p/data", marksNote},
		{"watched, never confirmed", "observe", watchedReads, nil, "",
			"Was marked (recorded, not refused): cannot run curl", "Was marked (recorded, not refused): cannot open or change /p/data", marksNote},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "r-aaaaaaaa-0000000000018-endlb1")
			if tc.tier != "" {
				restart(t, f, tc.tier, tc.extra)
			}
			addBlocks(t, f)
			for _, s := range tc.confirmed {
				if s == 1 {
					confirm(f, "exec", "curl", 1)
				} else {
					confirm(f, "path", "/p/data", 2)
				}
			}
			want := 0
			if tc.hits != "" {
				f.add(line(tc.hits, 2))
				f.add(line(tc.hits, 3))
				want = 2
			}
			if v := f.inForce(t); len(v.EndedLive) != 0 || len(liveRules(v)) != 2 {
				t.Fatalf("running run: ended %d, live %d, want 0 and 2", len(v.EndedLive), len(liveRules(v)))
			}
			f.add(`"kind":"run_end","source":"supervisor","reason":"exited","exit_code":0`)
			v := f.inForce(t)
			if live := v.View.Group(inforce.GroupLive); len(live.Rules) != 0 {
				t.Fatalf("an ended run's live group lists %d blocks, want none", len(live.Rules))
			}
			got := endedLive(v)
			for key, r := range got {
				if r.Live != livestatus.Ended || r.State != inforce.StateNotEnforced || r.Enforced || !strings.HasPrefix(r.EnforcedText, "Ended with the run") {
					t.Errorf("%s on an ended run: live %q state %q enforced %v (%q), want ended and no claim", key, r.Live, r.State, r.Enforced, r.EnforcedText)
				}
				if !strings.Contains(r.Source.Origin, "pid:42 cli") {
					t.Errorf("%s: origin %q, want who added it", key, r.Source.Origin)
				}
			}
			exec, path := got["live.block[exec:curl]"], got["live.block[path:/p/data]"]
			if len(got) != 2 || exec.Sentence != tc.curl || exec.Hits != want {
				t.Errorf("curl: %q, %d hits, want %q, %d", exec.Sentence, exec.Hits, tc.curl, want)
			}
			if path.Sentence != tc.path || path.Hits != 0 {
				t.Errorf("the path block: %q, %d hits, want %q, none", path.Sentence, path.Hits, tc.path)
			}
			notes := strings.Join(v.View.Notes, " ")
			if v.LiveBlocks != 2 || !strings.Contains(notes, tc.note) || strings.Contains(notes, "no longer") {
				t.Errorf("live blocks %d, notes %q, want both counted in %q", v.LiveBlocks, v.View.Notes, tc.note)
			}
		})
	}
}

// TestInForceEndedBlockByTheAddThatMadeIt: an ended run's block is judged by the add that made it, not by its latest
// add. A block the run put in force and then gave a longer time limit, or blocked again after an unblock for a while,
// in a change the run ended before confirming, was in force all the same: "Was blocked". A block removed for good and
// added again after the last change the run confirmed was never in force as the block it is: "Never put in force".
func TestInForceEndedBlockByTheAddThatMadeIt(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		name      string
		changes   func(o *liveblock.Overlay) error
		confirmed int // the last serial the launcher confirmed
		want      string
	}{
		{"a longer time limit", func(o *liveblock.Overlay) error {
			if _, _, err := o.AddUntil(liveblock.KindExec, "curl", "uid:1000 pid:42 cli", at, at.Add(time.Hour)); err != nil {
				return err
			}
			_, _, err := o.AddUntil(liveblock.KindExec, "curl", "uid:1000 pid:42 cli", at, at.Add(2*time.Hour))
			return err
		}, 1, "Was blocked: cannot run curl"},
		{"blocked again after an unblock for a while", func(o *liveblock.Overlay) error {
			if _, _, err := o.Add(liveblock.KindExec, "curl", "uid:1000 pid:42 cli", at); err != nil {
				return err
			}
			if _, _, err := o.RemoveUntil(liveblock.KindExec, "curl", "uid:1000 pid:42 cli", at, at.Add(time.Hour)); err != nil {
				return err
			}
			_, _, err := o.Add(liveblock.KindExec, "curl", "uid:1000 pid:42 cli", at)
			return err
		}, 2, "Was blocked: cannot run curl"},
		{"added again after a removal", func(o *liveblock.Overlay) error {
			if _, _, err := o.Add(liveblock.KindExec, "curl", "uid:1000 pid:42 cli", at); err != nil {
				return err
			}
			if _, _, err := o.Remove(liveblock.KindExec, "curl", "uid:1000 pid:42 cli", at); err != nil {
				return err
			}
			_, _, err := o.Add(liveblock.KindExec, "curl", "uid:1000 pid:42 cli", at)
			return err
		}, 2, "Never put in force: cannot run curl"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "r-aaaaaaaa-0000000000018-endlb2")
			if _, err := liveblock.Update(context.Background(), f.dir, f.run, func(o *liveblock.Overlay) (bool, error) {
				return true, tc.changes(o)
			}); err != nil {
				t.Fatal(err)
			}
			for s := 1; s <= tc.confirmed; s++ {
				confirm(f, "exec", "curl", s)
			}
			f.add(`"kind":"run_end","source":"supervisor","reason":"exited","exit_code":0`)
			v := f.inForce(t)
			if len(v.EndedLive) != 1 || v.EndedLive[0].Sentence != tc.want {
				t.Fatalf("ended blocks %+v, want one: %q", v.EndedLive, tc.want)
			}
		})
	}
}

// TestMadeAtBeforeTheOverlaysOldestChange: a block made before the oldest change the overlay still lists is judged by
// the first add listed of it, or, with none, by the overlay's serial: later serials than the one that made it, so they
// can only call it never put in force, never in force when it was not.
func TestMadeAtBeforeTheOverlaysOldestChange(t *testing.T) {
	at := time.Now().UTC()
	ov := &liveblock.Overlay{Serial: 300, Blocks: []liveblock.Entry{
		{Kind: liveblock.KindExec, Value: "curl", At: at}, {Kind: liveblock.KindNet, Value: "example.com", At: at},
	}, Changes: []liveblock.Change{
		{Serial: 299, Op: liveblock.OpRemove, Kind: liveblock.KindExec, Value: "curl", At: at, Until: at.Add(time.Hour)},
		{Serial: 300, Op: liveblock.OpAdd, Kind: liveblock.KindExec, Value: "curl", At: at},
	}}
	got := madeAt(ov)
	if got["exec:curl"] != 300 || got["net:example.com"] != 300 {
		t.Errorf("madeAt = %v, want curl by its listed add and example.com by the overlay's serial, both 300", got)
	}
}

// TestInForceUnreadableOverlayInWords: an overlay the view cannot read is said in plain words, the file and what is
// wrong with it, never Go's error with its package prefixes, a decoder's words or the run's folder; nothing is listed.
func TestInForceUnreadableOverlayInWords(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000018-badov1")
	overlay := filepath.Join(f.dir, liveblock.FileName)
	for _, tc := range []struct {
		name string
		text string
		mode os.FileMode
		want string
	}{
		{"damaged", "{not json", 0o600, "live-block.json is damaged, or a newer Tego wrote it"},
		{"another run's", `{"v":1,"run":"r-bbbbbbbb-0000000000018-other1","serial":0,"blocks":[],"changes":[]}`, 0o600,
			"live-block.json is damaged, or a newer Tego wrote it"},
		{"writable by others", `{"v":1,"run":"` + f.run + `","serial":0,"blocks":[],"changes":[]}`, 0o666,
			"live-block.json is writable by its group or others, so it is not trusted"},
	} {
		if err := os.WriteFile(overlay, []byte(tc.text), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(overlay, tc.mode); err != nil { // WriteFile's mode passes through the umask
			t.Fatal(err)
		}
		v := f.inForce(t)
		if v.LiveErr != tc.want {
			t.Errorf("%s overlay: LiveErr %q, want %q", tc.name, v.LiveErr, tc.want)
		}
		for _, raw := range []string{"liveblock:", "invalid character", "overlay", f.dir} {
			if strings.Contains(v.LiveErr, raw) {
				t.Errorf("%s overlay: LiveErr %q says %q", tc.name, v.LiveErr, raw)
			}
		}
		if v.LiveBlocks != 0 || len(v.EndedLive) != 0 || len(liveRules(v)) != 0 {
			t.Errorf("%s overlay: %d blocks, %d ended, %d live, want nothing listed", tc.name, v.LiveBlocks, len(v.EndedLive), len(liveRules(v)))
		}
	}
	if err := os.Remove(overlay); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.dir, "elsewhere.json"), overlay); err != nil {
		t.Fatal(err)
	}
	if v := f.inForce(t); v.LiveErr != "live-block.json is a symlink, so it is not trusted" {
		t.Errorf("symlinked overlay: LiveErr %q", v.LiveErr)
	}
	if os.Geteuid() != 0 { // root reads a file whatever its mode says
		if err := os.Remove(overlay); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(overlay, []byte("{}"), 0o200); err != nil {
			t.Fatal(err)
		}
		if v := f.inForce(t); v.LiveErr != "this user may not read live-block.json" {
			t.Errorf("unreadable overlay: LiveErr %q", v.LiveErr)
		}
	}
}
