// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Public issue 87: one run of doctor printed the same long reason, why no sudo command is shown, three times (two
// skipped probes and the fix: line). The text report says it once and the later lines refer to it; the Results
// themselves, which the JSON report carries, keep the whole reason.
func TestTextReportSaysALongWithheldReasonOnce(t *testing.T) {
	const why = "cannot establish membership of group tego (gid 1000) for folders /home/tego/.local and /home/tego/.local/bin: " +
		"/etc/nsswitch.conf does not establish files-only passwd and group membership (passwd: files systemd; group: files systemd); " +
		"no command is shown; run chmod g-w /home/tego/.local /home/tego/.local/bin, then run this step again."
	old, oldChecks := namedSelf, machineChecks
	t.Cleanup(func() { namedSelf, machineChecks = old, oldChecks })
	namedSelf = func() (string, string) { return "", why }
	var c calls
	machineChecks = passingChecks(&c)
	machineChecks.programs = func(bool, int, Version, []hook, []hook) (Result, []HookResult) {
		return Result{ID: CheckPrograms, Detail: "requires root to test", Fix: "re-run as root: " + sudoDoctor(), Skipped: true}, nil
	}
	machineChecks.fanotify = func(bool, Version) (Result, FanotifyState) {
		return Result{ID: CheckFanotify, Detail: "requires root to test", Fix: "re-run as root: " + sudoDoctor(), Skipped: true}, FanotifyState{}
	}
	rep, err := Run(context.Background(), &config.Machine{}, "")
	if err != nil {
		t.Fatal(err)
	}
	var text bytes.Buffer
	if err := rep.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	reason := strings.TrimSuffix(why, ".")
	if got := strings.Count(text.String(), reason); got != 1 {
		t.Errorf("the reason is printed %d times, want once:\n%s", got, text.String())
	}
	// The one message carries the one chmod for both folders, inside the fix's parentheses (the full stop is dropped
	// there), on the first line that names the withheld command and not only in a later "fix:" line.
	const chmod = "run chmod g-w /home/tego/.local /home/tego/.local/bin, then run this step again)"
	if first, _, _ := strings.Cut(text.String(), "for the reason given above"); !strings.Contains(first, chmod) {
		t.Errorf("the one chmod for both folders is not printed before the first reference to it:\n%s", text.String())
	}
	lines := 0
	for _, l := range strings.Split(text.String(), "\n") {
		if strings.Contains(l, withheldSudo) {
			lines++
			if !strings.Contains(l, "fix: ") && !strings.HasPrefix(l, "fix:") {
				t.Errorf("a line names the withheld command without a fix: %q", l)
			}
		}
	}
	if lines < 2 {
		t.Fatalf("%d lines name the withheld command, want the skipped probes and more:\n%s", lines, text.String())
	}
	if got := strings.Count(text.String(), "for the reason given above"); got != lines-1 {
		t.Errorf("%d lines refer to the reason, want %d:\n%s", got, lines-1, text.String())
	}
	// The data keeps the whole reason on every line: JSON readers do not read "above".
	for _, r := range rep.Results {
		if r.Skipped && !strings.Contains(r.Fix, reason) {
			t.Errorf("%s: the result's fix lost the reason: %q", r.ID, r.Fix)
		}
	}
}

func TestRepeatFoldLeavesShortReasonsAndOtherFixesAlone(t *testing.T) {
	var f repeatFold
	short := "run this tego as root with sudo (this tego's path cannot be named, so no sudo line is given)"
	for i := 0; i < 2; i++ {
		if got := f.line(short); got != short {
			t.Errorf("short reason folded: %q", got)
		}
	}
	for _, other := range []string{"", "re-run as root: sudo /home/u/.local/bin/tego machine check", "boot a kernel built with CONFIG_BTF"} {
		if got := f.line(other); got != other {
			t.Errorf("fix %q changed to %q", other, got)
		}
	}
	var none *repeatFold
	if got := none.line(short); got != short {
		t.Errorf("nil fold changed %q", got)
	}
}
