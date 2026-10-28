// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"errors"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestNeverReadAgain: a Never allow preview reopened after the change was confirmed says the read is
// already never allowed. The line still names the fs.ask_read entry that decided it, but the file has since moved
// that entry to deny_read; before this the planner called the moved entry "a profile's" and refused.
func TestNeverReadAgain(t *testing.T) {
	tok := ev(t, record.KindFS, record.VerdictRefused, "fs.ask_read[/h/.config/telemetry/]", record.ReasonAskDenied,
		record.FSPayload{Op: "open", Path: "/h/.config/telemetry/token"})
	apply := func(t *testing.T, contract []byte, level int) (*Result, error) {
		t.Helper()
		return Apply(Request{Contract: contract, ContractPath: "/p/proj/agent.yaml", Cwd: "/p/proj", Home: "/h",
			Event: tok, Action: Block, Level: level, Date: "2026-10-27"})
	}
	cases := []struct {
		name         string
		first, again int  // the level confirmed, then the level reopened
		nothing      bool // the reopened preview has nothing to change
	}{
		{"the entry's folder, reopened", 1, 1, true},
		{"the entry's folder, then the file alone", 1, 0, true},
		{"the file alone, reopened", 0, 0, true},
		{"the file alone, then its folder still moves the ask", 0, 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := apply(t, []byte(askBase), c.first)
			if err != nil {
				t.Fatalf("first change: %v", err)
			}
			again, err := apply(t, res.Text, c.again)
			if !c.nothing {
				if err != nil {
					t.Fatalf("a wider never after a narrower one: %v", err)
				}
				if !strings.Contains(again.Effect, "without asking") {
					t.Errorf("effect = %q", again.Effect)
				}
				return
			}
			if !errors.Is(err, ErrNothing) {
				t.Fatalf("err = %v, want ErrNothing", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, "already never allowed") || strings.Contains(msg, "profile") {
				t.Errorf("err = %q, want 'already never allowed' and no 'profile'", msg)
			}
		})
	}
}

// TestNeverReadProfileStillRefused: a profile's ask entry with no deny_read of this file over it is still refused,
// so the r10 check above hides nothing it should not.
func TestNeverReadProfileStillRefused(t *testing.T) {
	profile := ev(t, record.KindFS, record.VerdictRefused, "fs.ask_read[/h/.config/other/]", record.ReasonAskDenied,
		record.FSPayload{Op: "open", Path: "/h/.config/other/f"})
	_, err := Apply(Request{Contract: []byte(askBase), ContractPath: "/p/proj/agent.yaml", Cwd: "/p/proj", Home: "/h",
		Event: profile, Action: Block, Level: 1, Date: "2026-10-27"})
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("err = %v, want the profile refusal", err)
	}
}

// TestNeverReadReopenedByWrite: a deny_read above the path is not "already never allowed" when a
// nearer fs.write entry reopens the path (nearest wins, SEMANTICS §2). Before the fix the planner said the secret
// was protected, showed no Confirm and lost the narrowing; now level 0 adds the deny_read for the file alone, and
// the next run refuses the read.
func TestNeverReadReopenedByWrite(t *testing.T) {
	const reopened = `version: 0
name: demo
fs:
  write: ["./src/", "/h/.config/telemetry/"]
  deny_read: ["/h/.config/"]
exec:
  allow: [sh]
tier: landlock
`
	const token = "/h/.config/telemetry/token"
	tok := ev(t, record.KindFS, record.VerdictRefused, "fs.ask_read[/h/.config/telemetry/]", record.ReasonAskDenied,
		record.FSPayload{Op: "open", Path: token})
	_, top, err := parse([]byte(reopened))
	if err != nil {
		t.Fatal(err)
	}
	if got := newModel(top, resolver{"/p/proj", "/h"}).readAt(token); got != allowed {
		t.Fatalf("fixture: readAt(token) = %v, want allowed (the write entry is nearer than the deny_read)", got)
	}
	for _, level := range []int{0, 1} {
		res, err := Apply(Request{Contract: []byte(reopened), ContractPath: "/p/proj/agent.yaml", Cwd: "/p/proj",
			Home: "/h", Event: tok, Action: Block, Level: level, Date: "2026-10-27"})
		if errors.Is(err, ErrNothing) {
			t.Fatalf("level %d: %v; the write entry reopens the token, so the read is not already never allowed", level, err)
		}
		if level != 0 {
			continue // the wider scopes may be refused or narrowed; only the claim above is under test there
		}
		if err != nil {
			t.Fatalf("level 0: %v", err)
		}
		_, after, err := parse(res.Text)
		if err != nil {
			t.Fatal(err)
		}
		if got := newModel(after, resolver{"/p/proj", "/h"}).readAt(token); got != refusedDeny {
			t.Errorf("level 0: after the change readAt(token) = %v, want refusedDeny; text:\n%s", got, res.Text)
		}
	}
}
