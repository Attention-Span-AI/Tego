// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// minorRun is a live stand-in run (liveRun) whose run_start says record_minor minor: 25 (record.MinorLiveModes) is a
// launcher that reads time limits, 24 one that does not.
func minorRun(t *testing.T, minor int) (dir, id string) {
	t.Helper()
	dir, id, _ = liveRun(t)
	rewriteStart(t, dir, `"tier":"landlock"`, `"tier":"landlock","record_minor":`+itoa(minor))
	return dir, id
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// TestBlockForWritesUntil: `tego block <run> exec /bin/ls --for 2h` writes the block with its end two hours from now
// (By "cli"), keeps the first line's form for scripts and says the limit on the next one; --until does the same for
// an instant; --list shows the end in both forms.
func TestBlockForWritesUntil(t *testing.T) {
	dir, id := minorRun(t, record.MinorLiveModes)
	before := time.Now()
	code, out, errs := run(t, "block", id, "exec", "/bin/ls", "--for", "2h")
	if code != identity.ExitOK || !strings.HasPrefix(out, id+": blocked live.block[exec:/bin/ls]\nTime limit: until ") ||
		!strings.Contains(out, "(in 2 hours)") || !strings.Contains(out, "live-block-expired") {
		t.Fatalf("block --for: exit %d stdout %q stderr %q", code, out, errs)
	}
	o, err := liveblock.Read(dir, id)
	if err != nil || len(o.Blocks) != 1 {
		t.Fatalf("overlay %+v, %v", o, err)
	}
	b := o.Blocks[0]
	if d := b.Until.Sub(before); d < 2*time.Hour || d > 2*time.Hour+time.Minute || !strings.HasSuffix(b.By, " cli") {
		t.Errorf("block %+v: want an end two hours on, by the cli", b)
	}
	if c := o.Changes[len(o.Changes)-1]; c.Op != liveblock.OpAdd || !c.Until.Equal(b.Until) {
		t.Errorf("last change %+v: want the add with its until", c)
	}

	until := time.Now().Add(3 * time.Hour).Truncate(time.Minute)
	if code, out, errs := run(t, "block", id, "net", "example.com:443", "--until", until.Format(time.RFC3339)); code != identity.ExitOK ||
		!strings.Contains(out, "Time limit: until") {
		t.Fatalf("block --until: exit %d stdout %q stderr %q", code, out, errs)
	}
	if e, ok := mustRead(t, dir, id).Find(liveblock.KindNet, "example.com:443"); !ok || !e.Until.Equal(until.UTC()) {
		t.Errorf("net block %+v: want until %s", e, until.UTC())
	}

	code, out, _ = run(t, "block", "--list", id)
	if code != identity.ExitOK || strings.Count(out, "  ends ") != 2 || strings.Contains(out, "ends until") || !strings.Contains(out, timeCaveat) {
		t.Errorf("list: exit %d stdout %q, want each block's end and the clock caveat", code, out)
	}
	// Once the launcher confirms them, a timed block is in force until its limit, not "until the run ends".
	appendGap(t, dir, id, 1, "net", "example.com:443", 2)
	code, out, _ = run(t, "block", "--list", id)
	if code != identity.ExitOK || strings.Count(out, livestatus.SentenceInForceUntil) != 2 || strings.Contains(out, "until the run ends") {
		t.Errorf("list once confirmed: exit %d stdout %q", code, out)
	}
	code, out, _ = run(t, "block", "--list", "--json", id)
	var got struct {
		Blocks []struct {
			Value string    `json:"value"`
			Until time.Time `json:"until"`
		}
	}
	if err := json.Unmarshal([]byte(out), &got); code != identity.ExitOK || err != nil || len(got.Blocks) != 2 || got.Blocks[0].Until.IsZero() {
		t.Errorf("list --json: exit %d %q: %v", code, out, err)
	}
}

// TestBlockValueAfterDoubleDash: a value that starts with - is read as a flag unless it follows --, the time limit
// before it. The dashboard's terminal twins write one that way (internal/control/web changeWords, static/twin.js), since
// a bare program name may start with - and the Block now form blocks it.
func TestBlockValueAfterDoubleDash(t *testing.T) {
	dir, id := minorRun(t, record.MinorLiveModes)
	if code, out, errs := run(t, "block", id, "exec", "-x"); code != identity.ExitUsage || out != "" || !strings.Contains(errs, "-x") {
		t.Errorf("block exec -x: exit %d stdout %q stderr %q, want a usage error naming -x", code, out, errs)
	}
	code, out, errs := run(t, "block", id, "exec", "--for", "2h", "--", "-x")
	if code != identity.ExitOK || !strings.HasPrefix(out, id+": blocked live.block[exec:-x]\nTime limit: until ") {
		t.Fatalf("block exec --for 2h -- -x: exit %d stdout %q stderr %q", code, out, errs)
	}
	if e, ok := mustRead(t, dir, id).Find(liveblock.KindExec, "-x"); !ok || e.Until.IsZero() {
		t.Errorf("block %+v (found %v): want exec -x with its time limit", e, ok)
	}
}

func mustRead(t *testing.T, dir, id string) *liveblock.Overlay {
	t.Helper()
	o, err := liveblock.Read(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// TestUnblockForAWhile: an unblock with a limit keeps the block dormant until then (From), says so, and --list shows
// "unblocked until" and the dormant state; an unblock past the block's own end removes it for good.
func TestUnblockForAWhile(t *testing.T) {
	dir, id := minorRun(t, record.MinorLiveModes)
	if code, _, errs := run(t, "block", id, "exec", "/bin/ls"); code != identity.ExitOK {
		t.Fatalf("block: %d %q", code, errs)
	}
	code, out, errs := run(t, "unblock", id, "exec", "/bin/ls", "--for", "2h")
	if code != identity.ExitOK || !strings.HasPrefix(out, id+": block removed live.block[exec:/bin/ls]\nUnblocked for a while, until ") ||
		!strings.Contains(out, "live-unblock-expired") {
		t.Fatalf("unblock --for: exit %d stdout %q stderr %q", code, out, errs)
	}
	e, ok := mustRead(t, dir, id).Find(liveblock.KindExec, "/bin/ls")
	if !ok || e.From.Before(time.Now().Add(2*time.Hour-time.Minute)) {
		t.Fatalf("block %+v (held %v): want it kept dormant for two hours", e, ok)
	}
	code, out, _ = run(t, "block", "--list", id)
	if code != identity.ExitOK || !strings.Contains(out, "unblocked until ") || !strings.Contains(out, livestatus.SentenceDormant) {
		t.Errorf("list: exit %d stdout %q", code, out)
	}

	// A block that ends in an hour, unblocked for two: it would never refuse again, so it is removed.
	if code, _, errs := run(t, "block", id, "net", "example.com:443", "--for", "1h"); code != identity.ExitOK {
		t.Fatalf("block net: %d %q", code, errs)
	}
	code, out, _ = run(t, "unblock", id, "net", "example.com:443", "--for", "2h")
	if code != identity.ExitOK || !strings.Contains(out, "removed for the rest of the run") {
		t.Errorf("unblock past the end: exit %d stdout %q", code, out)
	}
	if _, ok := mustRead(t, dir, id).Find(liveblock.KindNet, "example.com:443"); ok {
		t.Error("the block is still held")
	}
}

// TestBlockTimedRefusedOnOlderLauncher: a run at record_minor 24 has a launcher that reads no time limit; it would
// refuse the whole overlay, so a limit is refused with runact.ErrNoTimeLimits' words ([launcher-too-old]) and nothing
// is written. Without a limit the same run is blocked as before.
func TestBlockTimedRefusedOnOlderLauncher(t *testing.T) {
	dir, id := minorRun(t, record.MinorLiveControl)
	for _, name := range []string{"block", "unblock"} {
		code, out, errs := run(t, name, id, "exec", "/bin/ls", "--for", "1h")
		if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "[launcher-too-old]") ||
			!strings.Contains(errs, liveblock.ErrNoTimeLimits.Error()) {
			t.Errorf("%s --for at minor 24: exit %d stdout %q stderr %q", name, code, out, errs)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, liveblock.FileName)); !os.IsNotExist(err) {
		t.Errorf("an overlay was written: %v", err)
	}
	if code, _, errs := run(t, "block", id, "exec", "/bin/ls"); code != identity.ExitOK {
		t.Errorf("untimed block at minor 24: %d %q", code, errs)
	}
}

// TestBlockLimitUsage: a limit that does not parse, both flags, a limit out of bounds, and a limit with --list are
// usage errors, and each names the accepted forms or the bound.
func TestBlockLimitUsage(t *testing.T) {
	_, id := minorRun(t, record.MinorLiveModes)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"block", id, "exec", "/bin/ls", "--for", "soon"}, "45m"},
		{[]string{"block", id, "exec", "/bin/ls", "--for", "1h", "--until", "17:00"}, "--for"},
		{[]string{"block", id, "exec", "/bin/ls", "--for", "30s"}, "minute"},
		{[]string{"unblock", id, "exec", "/bin/ls", "--until", "Funday 17:00"}, "Fri 17:00"},
		{[]string{"block", "--list", id, "--for", "1h"}, "--list"},
	} {
		code, _, errs := run(t, tc.args...)
		if code != identity.ExitUsage || !strings.Contains(errs, tc.want) || !strings.Contains(errs, "[usage]") {
			t.Errorf("%v: exit %d stderr %q, want usage naming %q", tc.args, code, errs, tc.want)
		}
	}
}

// TestBlockUntimedGolden pins an untimed block's and unblock's whole output, byte for byte as before time limits
// existed (testdata/block-untimed.golden was made from the base, 2ae8d3871, with the run id replaced by RUN). The
// golden is that output where /bin/ls is a program of its own: where it is one name of a multi-call program
// (uutils' coreutils), the block adds a note saying so (TestBlockExecNotes), so this machine's /bin/ls is read as a
// lone file.
func TestBlockUntimedGolden(t *testing.T) {
	old := execReach
	execReach = func(value, _ string) liveblock.ExecReach { return liveblock.ExecReach{File: value, Names: 1} }
	t.Cleanup(func() { execReach = old })
	_, id := minorRun(t, record.MinorLiveModes)
	var got strings.Builder
	for _, args := range [][]string{
		{"block", id, "exec", "/bin/ls"},
		{"block", id, "exec", "/bin/ls"},
		{"block", id, "net", "Example.com:443"},
		{"unblock", id, "exec", "/bin/ls"},
		{"unblock", id, "exec", "/bin/ls"},
	} {
		code, out, errs := run(t, args...)
		got.WriteString(strings.Join(args[2:], " ") + " -> " + itoa(code) + "\n" + out + errs + "--\n")
	}
	s := strings.ReplaceAll(got.String(), id, "RUN")
	golden := filepath.Join("testdata", "block-untimed.golden")
	if *updateGolden {
		if err := os.WriteFile(golden, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if s != string(want) {
		t.Errorf("untimed output drifted from %s:\ngot:\n%s\nwant:\n%s", golden, s, want)
	}
}
