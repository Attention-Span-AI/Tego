// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestNoRunRecordIsAnError: an events.jsonl with no run_start — empty, only a torn line, or a first line of
// another kind — is no run to report. events, drift and measure printed it as a complete run that did nothing
// and exited 0; R25 makes it 125 [io] "no run record", as `events --verify` answers.
func TestNoRunRecordIsAnError(t *testing.T) {
	lines := strings.SplitAfter(string(fixtureBytes(t)), "\n")
	for name, content := range map[string]string{
		"empty":                 "",
		"a torn line only":      lines[0][:40],
		"no run_start first":    lines[1] + lines[2],
		"a blank line then EOF": "\n",
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, cmd := range []string{"events", "drift", "measure", "learn"} {
			code, out, errs := run(t, cmd, dir)
			want := identity.ExitError
			code2 := "[io]"
			if name == "a blank line then EOF" {
				code2 = "[ledger-corrupt]" // a line that is not a record, not an absent one
			}
			if code != want || !strings.Contains(errs, code2) {
				t.Errorf("%s, %s: exit %d, want %d %s\nstdout %s\nstderr %s", name, cmd, code, want, code2, out, errs)
				continue
			}
			if code2 == "[io]" && !strings.Contains(errs, "no run record at "+dir) {
				t.Errorf("%s, %s: stderr %q does not say no run record", name, cmd, errs)
			}
		}
	}
}

// TestVerifyNoRunRecord: `events --verify` of a run directory whose events.jsonl holds no line, and which no
// anchor line names, is the same 125 [io] "no run record" as events, drift and measure give it: nothing
// vouches that a run was recorded there, so "verified 0 lines" claimed a check of nothing.
func TestVerifyNoRunRecord(t *testing.T) {
	_, dir := verifiedRun(t)
	var host [32]byte
	id, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(filepath.Dir(dir), string(id))
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(empty, ledger.EventsFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "events", empty, "--verify")
	if code != identity.ExitError || !strings.Contains(errs, "no run record at "+empty) || !strings.Contains(errs, "[io]") {
		t.Fatalf("exit %d, want 125 [io] no run record\nstdout %s\nstderr %s", code, out, errs)
	}
}

// TestTailAfterRunEndIsCorruptInEveryCommand: at the CLI, bytes after run_end that are not a record exit 125
// [ledger-corrupt] naming their offset from events, drift and measure, as `events --verify` refuses them; a
// NUL tail was read as a clean end, and a `garbage` line already failed.
func TestTailAfterRunEndIsCorruptInEveryCommand(t *testing.T) {
	data := fixtureBytes(t)
	for name, tail := range map[string]string{"NUL bytes": "\x00\x00\x00\x00", "a garbage line": "garbage\n"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), append(append([]byte{}, data...), tail...), 0o600); err != nil {
			t.Fatal(err)
		}
		offset := "byte offset " + strconv.Itoa(len(data))
		for _, args := range [][]string{{"events", dir}, {"events", dir, "--json"}, {"drift", dir}, {"measure", dir}, {"learn", dir}} {
			code, _, errs := run(t, args...)
			if code != identity.ExitError || !strings.Contains(errs, "[ledger-corrupt]") || !strings.Contains(errs, offset) {
				t.Errorf("%s, %v: exit %d, want 125 [ledger-corrupt] naming %s\nstderr %s", name, args, code, offset, errs)
			}
		}
	}
}
