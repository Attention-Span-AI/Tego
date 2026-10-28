// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// adjustableRun is a live stand-in run whose run_start says Adjustable at record minor 25 with a fence of a refused
// read, new access to a host and a new program, and whose run key exists (the launcher makes it).
func adjustableRun(t *testing.T) (dir, id string) {
	t.Helper()
	dir, id, _ = liveRun(t)
	fence := record.LiveFence{SHA256: strings.Repeat("0", 64), Entries: []record.LiveFenceEntry{
		{Kind: "read", Value: "/srv/billing", Source: record.LiveFenceSourceDeny, Rule: "live.fence[read:/srv/billing]"},
		{Kind: "net", Value: "api.stripe.com:443", Source: record.LiveFenceSourceNew, Rule: "live.fence[net:api.stripe.com:443]"},
		{Kind: "exec", Value: "/usr/bin/psql", Source: record.LiveFenceSourceNew, Rule: "live.fence[exec:/usr/bin/psql]"},
	}}
	b, err := json.Marshal(fence)
	if err != nil {
		t.Fatal(err)
	}
	rewriteStart(t, dir, `"tier":"landlock"`, fmt.Sprintf(`"tier":"cgroup","record_minor":%d,"live_mode":"adjustable","live_fence":%s`,
		record.MinorLiveModes, b))
	if _, err := liveblock.WriteKey(dir); err != nil {
		t.Fatal(err)
	}
	return dir, id
}

// noTerminal stands in for a standard input that is not a terminal (term false) or is one that types typed.
func noTerminal(t *testing.T, term bool, typed string) {
	t.Helper()
	oldTerm, oldIn, oldWait := stdinIsTerminal, confirmInput, liftWait
	stdinIsTerminal = func() bool { return term }
	confirmInput = strings.NewReader(typed)
	liftWait = 200 * time.Millisecond
	t.Cleanup(func() { stdinIsTerminal, confirmInput, liftWait = oldTerm, oldIn, oldWait })
}

// appendFenceLine appends the launcher's line answering the overlay change numbered serial: why is live-rule-lifted,
// live-rule-restored or live-lift-refused (with refused).
func appendFenceLine(t *testing.T, dir, run string, seq int, why, op, kind, value string, serial uint64, refused string) {
	t.Helper()
	c := record.LiveBlockChange{Op: op, Kind: kind, Value: value, Rule: liveblock.FenceRule(liveblock.Kind(kind), value),
		By: "uid:1000 pid:9 cli", Serial: serial, At: time.Now().UTC(), Refused: refused}
	cb, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	l := fmt.Sprintf(`{"v":1,"seq":%d,"id":"%064x","prev":"%064x","ts":"%s","mono_ns":%d,"run":"%s","agent":"tester","pid":10,"tid":10,"cgroup":1,"kind":"gap","source":"launcher",`+
		`"what":"enforce","why":"%s","live_block":%s}`+"\n", seq, seq+1, seq, time.Now().UTC().Format(time.RFC3339Nano), seq+1, run, why, cb)
	f, err := os.OpenFile(filepath.Join(dir, ledger.EventsFile), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(l); err != nil {
		t.Fatal(err)
	}
}

// TestLiftNeedsConfirmation: without a terminal and without --yes a lift is a usage error and writes nothing; at a
// terminal, anything but the command's word typed is not confirmed.
func TestLiftNeedsConfirmation(t *testing.T) {
	dir, id := adjustableRun(t)
	noTerminal(t, false, "")
	for _, name := range []string{"lift", "grant"} {
		code, out, errs := run(t, name, id, "exec", "/usr/bin/psql")
		if code != identity.ExitUsage || out != "" || !strings.Contains(errs, "--yes") || !strings.Contains(errs, "[usage]") {
			t.Errorf("%s with no terminal: exit %d stdout %q stderr %q", name, code, out, errs)
		}
	}
	noTerminal(t, true, "yes\n")
	code, out, errs := run(t, "grant", id, "exec", "/usr/bin/psql")
	if code != identity.ExitFinding || !strings.Contains(errs, "not confirmed") || !strings.Contains(errs, "[not-confirmed]") ||
		strings.Contains(errs, "[usage]") || !strings.Contains(out, "Enforced by Tego's live layer, not the kernel.") {
		t.Errorf("grant typed \"yes\": exit %d stdout %q stderr %q", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, liveblock.FileName)); !os.IsNotExist(err) {
		t.Errorf("an overlay was written without confirmation: %v", err)
	}
	noTerminal(t, true, "grant\n")
	if code, out, errs := run(t, "grant", id, "exec", "/usr/bin/psql"); code != identity.ExitOK || !strings.Contains(out, "grant asked") {
		t.Errorf("grant typed \"grant\": exit %d stdout %q stderr %q", code, out, errs)
	}
}

// TestLiftLimitAfterConfirm: typing the word takes time, so a lift's limit is read again once confirmed: a --for span
// counts from the confirmation and says its new end, and a --until that passed (or came within a minute) while the
// person typed asks nothing.
func TestLiftLimitAfterConfirm(t *testing.T) {
	dir, id := adjustableRun(t)
	start := time.Now()
	oldClock := liftClock
	t.Cleanup(func() { liftClock = oldClock })
	step := func(wait time.Duration) {
		calls := 0
		liftClock = func() time.Time {
			calls++
			if calls == 1 {
				return start
			}
			return start.Add(wait) // the confirmation came wait later
		}
	}

	step(30 * time.Second)
	noTerminal(t, true, "lift\n")
	code, out, errs := run(t, "lift", id, "read", "/srv/billing", "--for", "1m")
	if code != identity.ExitOK || !strings.Contains(out, "Confirmed; the limit counts from now: until ") {
		t.Fatalf("--for after a 30 s wait: exit %d stdout %q stderr %q", code, out, errs)
	}
	c := mustRead(t, dir, id).Changes
	if got, want := c[len(c)-1].Until, start.Add(90*time.Second); got.Sub(want).Abs() > time.Second {
		t.Errorf("limit %s, want a minute from the confirmation (%s)", got, want)
	}

	step(time.Minute)
	noTerminal(t, true, "grant\n")
	until := start.Add(90 * time.Second).Format(time.RFC3339)
	code, _, errs = run(t, "grant", id, "net", "api.stripe.com:443", "--until", until)
	if code != identity.ExitUsage || !strings.Contains(errs, "while waiting for confirmation") || !strings.Contains(errs, "nothing was asked") {
		t.Errorf("--until that came within a minute: exit %d stderr %q", code, errs)
	}
	if c2 := mustRead(t, dir, id).Changes; len(c2) != len(c) {
		t.Errorf("a lift was asked after its limit passed: %+v", c2[len(c2)-1])
	}
}

// TestFenceLineReadsOnFromTheChange: the wait for the launcher's answer reads only what was appended after the change
// was written, so an older line with the same serial (a reused run directory in a test, or a line before the offset)
// is not taken for the answer, and a weeks-long ledger is not rescanned from byte 0.
func TestFenceLineReadsOnFromTheChange(t *testing.T) {
	dir, id := adjustableRun(t)
	appendFenceLine(t, dir, id, 1, record.GapLiveRuleLifted, record.LiveOpLift, "net", "api.stripe.com:443", 7, "")
	if _, _, ok := findFenceLine(dir, 7, 0); !ok {
		t.Fatal("from byte 0, the answer is found")
	}
	off := ledgerEnd(dir)
	if off == 0 {
		t.Fatal("ledgerEnd = 0")
	}
	if _, _, ok := findFenceLine(dir, 7, off); ok {
		t.Error("a line before the offset was taken for the answer")
	}
	appendFenceLine(t, dir, id, 2, record.GapLiveRuleRestored, record.LiveOpRestore, "net", "api.stripe.com:443", 7, "")
	if why, _, ok := findFenceLine(dir, 7, off); !ok || why != record.GapLiveRuleRestored {
		t.Errorf("the line after the offset: %q %v", why, ok)
	}
}

// TestLiftRefusals: a Locked run is [locked], an entry outside the fence [outside-fence], a run with no key [no-key],
// a time limit on a run at minor 24 [launcher-too-old], a kind no fence holds a usage error, and a lift from inside a
// run [governed]; each exits 1 (usage: 2) and writes no overlay.
func TestLiftRefusals(t *testing.T) {
	noTerminal(t, false, "")
	_, locked := minorRun(t, record.MinorLiveModes)
	code, _, errs := run(t, "lift", locked, "exec", "/usr/bin/psql", "--yes")
	if code != identity.ExitFinding || !strings.Contains(errs, "[locked]") || !strings.Contains(errs, "Locked") || !strings.Contains(errs, "Adjustable") {
		t.Errorf("Locked run: exit %d stderr %q", code, errs)
	}
	dir, id := adjustableRun(t)
	code, _, errs = run(t, "grant", id, "net", "evil.example:443", "--yes")
	if code != identity.ExitFinding || !strings.Contains(errs, "[outside-fence]") || !strings.Contains(errs, "next run") {
		t.Errorf("outside the fence: exit %d stderr %q", code, errs)
	}
	code, _, errs = run(t, "lift", id, "write", "/srv/billing", "--yes")
	if code != identity.ExitUsage || !strings.Contains(errs, "read, net or exec") {
		t.Errorf("a write kind: exit %d stderr %q", code, errs)
	}
	if err := os.Remove(filepath.Join(dir, liveblock.KeyName)); err != nil {
		t.Fatal(err)
	}
	code, _, errs = run(t, "lift", id, "read", "/srv/billing", "--yes")
	if code != identity.ExitFinding || !strings.Contains(errs, "[no-key]") {
		t.Errorf("no key: exit %d stderr %q", code, errs)
	}
	_, old := minorRun(t, record.MinorLiveControl)
	code, _, errs = run(t, "lift", old, "read", "/srv/billing", "--for", "1h", "--yes")
	if code != identity.ExitFinding || !strings.Contains(errs, "[launcher-too-old]") {
		t.Errorf("minor 24 with a limit: exit %d stderr %q", code, errs)
	}
	for _, d := range []string{dir} {
		if _, err := os.Stat(filepath.Join(d, liveblock.FileName)); !os.IsNotExist(err) {
			t.Errorf("an overlay was written: %v", err)
		}
	}
	oldIn := selfInRun
	selfInRun = func() (bool, error) { return true, nil }
	t.Cleanup(func() { selfInRun = oldIn })
	code, _, errs = run(t, "lift", id, "read", "/srv/billing", "--yes")
	if code != identity.ExitFinding || !strings.Contains(errs, "[governed]") {
		t.Errorf("from inside a run: exit %d stderr %q", code, errs)
	}
}

// TestLiftAskedThenAnswered: a lift with --yes writes a MAC'ed lift under the run's key with its time limit, says what
// the run may do and what enforces it, and with no launcher line within the wait says it was asked; with the
// launcher's live-rule-lifted line for its serial it says lifted, and with live-lift-refused it exits 1 with the reason
// in brackets. A restore needs no confirmation and says restored.
func TestLiftAskedThenAnswered(t *testing.T) {
	noTerminal(t, false, "")
	dir, id := adjustableRun(t)
	code, out, errs := run(t, "lift", id, "read", "/srv/billing", "--for", "3d", "--yes")
	if code != identity.ExitOK || !strings.Contains(out, "The run will be able to read /srv/billing and everything beneath it, until ") ||
		!strings.Contains(out, "Enforced by Tego's live layer, not the kernel. A time limit stops new access; what was already read or copied, open files and live connections stay.") ||
		!strings.Contains(out, id+": lift asked live.fence[read:/srv/billing]") || !strings.Contains(out, "the launcher applies it within a second") {
		t.Fatalf("lift: exit %d stdout %q stderr %q", code, out, errs)
	}
	o := mustRead(t, dir, id)
	c := o.Changes[len(o.Changes)-1]
	key, err := liveblock.ReadKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Op != liveblock.OpLift || c.Until.IsZero() || !liveblock.LiftMACOK(key, id, c) || !strings.HasSuffix(c.By, " cli") {
		t.Fatalf("overlay change %+v: want a lift by the cli with its limit and a MAC that checks", c)
	}

	// The launcher answers the next lift: lifted. The line is appended once the overlay holds the change.
	go func() {
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if o, err := liveblock.Read(dir, id); err == nil && o.Serial > c.Serial {
				appendFenceLine(t, dir, id, 2, record.GapLiveRuleLifted, record.LiveOpLift, "net", "api.stripe.com:443", o.Serial, "")
				return
			}
		}
	}()
	liftWait = 3 * time.Second
	code, out, errs = run(t, "grant", id, "net", "api.stripe.com:443", "--yes")
	if code != identity.ExitOK || !strings.Contains(out, id+": granted live.fence[net:api.stripe.com:443]") || !strings.Contains(out, "for the rest of the run") {
		t.Fatalf("grant answered: exit %d stdout %q stderr %q", code, out, errs)
	}

	go func() {
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if o, err := liveblock.Read(dir, id); err == nil && o.Serial > c.Serial+1 {
				appendFenceLine(t, dir, id, 3, record.GapLiveLiftRefused, record.LiveOpLift, "exec", "/usr/bin/psql", o.Serial, record.LiveRefusedMAC)
				return
			}
		}
	}()
	code, _, errs = run(t, "grant", id, "exec", "/usr/bin/psql", "--yes")
	if code != identity.ExitFinding || !strings.Contains(errs, "[mac]") || !strings.Contains(errs, "nothing was loosened") {
		t.Errorf("grant refused by the launcher: exit %d stderr %q", code, errs)
	}

	liftWait = 200 * time.Millisecond
	code, out, errs = run(t, "restore", id, "read", "/srv/billing")
	if code != identity.ExitOK || !strings.Contains(out, id+": restore asked live.fence[read:/srv/billing]") {
		t.Errorf("restore: exit %d stdout %q stderr %q", code, out, errs)
	}
	if c := mustRead(t, dir, id).Changes; c[len(c)-1].Op != liveblock.OpRestore {
		t.Errorf("last change %+v: want the restore", c[len(c)-1])
	}
}

// TestLiftUsageNamesModes pins that the help of lift, grant and restore names both modes.
func TestLiftUsageNamesModes(t *testing.T) {
	for _, name := range []string{"lift", "grant", "restore"} {
		code, _, errs := run(t, name, "-h")
		if code != identity.ExitOK || !strings.Contains(errs, "Adjustable") || !strings.Contains(errs, "Locked") {
			t.Errorf("%s -h: exit %d stderr %q", name, code, errs)
		}
	}
}
