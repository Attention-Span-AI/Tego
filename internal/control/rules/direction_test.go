// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

const directionHead = "version: 0\nname: tester\ncommand: [sh]\ntier: landlock\nexec:\n  allow: [sh, cat]\n"

// realFixture is the fixture with the real compiler and a project holding the folders the tests' entries name.
func realFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.s.Compile = nil
	f.s.Machine = config.Builtin()
	f.s.Machine.Home = f.s.Home
	f.s.PATH = "/usr/bin:/bin"
	f.s.Anchor = filepath.Join(f.dir, "state", "chain.log")
	for _, d := range []string{filepath.Join(f.dir, "state", "vault"), f.s.Home, "out/sub", "docs", "secret", "askme", "a/x", "a/y", "b/x"} {
		if !filepath.IsAbs(d) {
			d = filepath.Join(f.proj, d)
		}
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"a.pem", "a/x/f", "a/y/f", "b/x/f"} {
		writeFile(t, filepath.Join(f.proj, p), "x")
	}
	return f
}

func (f *fixture) plan(t *testing.T, body string, edits ...Edit) *ChangePlan {
	t.Helper()
	writeFile(t, f.contract, directionHead+body)
	c := f.ref(t, f.contract)
	p, err := f.s.PlanChange(t.Context(), ChangeReq{Ref: c.Ref, Base: c.Base, Edits: edits})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The direction a person is told is the compiled comparison's. The lexical model of the file calls a pure
// refusal "mixed" when a compiled family it cannot read changes, asks to confirm a no-op as a widening, and words a
// pattern as "May read ./*.pem, May read ./*.pem".
func TestPlannedDirectionComesFromTheCompiledComparison(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		edits      []Edit
		want       string
		needsAck   bool
		allows     string // a substring of NewlyAllows
	}{
		{"a refusal added", "fs:\n  write: [./out/]\n", []Edit{{"add", "fs.deny_read", "./secret/"}}, "narrows", false, ""},
		{"a write removed", "fs:\n  write: [./out/]\n", []Edit{{"remove", "fs.write", "./out/"}}, "narrows", false, ""},
		{"an ask never", "fs:\n  write: [./out/]\n  ask: [./out/sub/]\n", []Edit{{"never", "fs.ask", "./out/sub/"}}, "narrows", false, ""},
		{"a read ask never", "fs:\n  ask_read: [./docs/]\n", []Edit{{"never", "fs.ask_read", "./docs/"}}, "narrows", false, ""},
		{"a pattern refusal added", "fs:\n  write: [./out/]\n", []Edit{{"add", "fs.deny_read", "./*.pem"}}, "narrows", false, ""},
		{"a refusal removed", "fs:\n  write: [./out/]\n  deny_read: [./secret/]\n", []Edit{{"remove", "fs.deny_read", "./secret/"}}, "widens", true, "it was refused"},
		{"a write added", "fs:\n  write: [./out/]\n", []Edit{{"add", "fs.write", "./more/"}}, "widens", true, "Write "},
		// The lexical model reads "/usr/bin/cat" as a new program beside "cat", a widening; both compile to one grant.
		{"a program spelled twice", "", []Edit{{"add", "exec.allow", "/usr/bin/cat"}}, "narrows", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := realFixture(t)
			if tc.name == "a write added" {
				if err := os.MkdirAll(filepath.Join(f.proj, "more"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			p := f.plan(t, tc.body, tc.edits...)
			if p.Err != "" {
				t.Fatalf("refused: %s", p.Err)
			}
			if p.Direction != tc.want || p.NeedsAck != tc.needsAck {
				t.Fatalf("direction %s (ack %v), want %s (ack %v): %s; review %q", p.Direction, p.NeedsAck, tc.want, tc.needsAck, p.Why, p.ComparisonReview)
			}
			if !strings.HasPrefix(p.Why, "the compiled contract before and after:") {
				t.Fatalf("the direction is not said from the comparison: %q", p.Why)
			}
			if !strings.Contains(strings.Join(p.NewlyAllows, "|"), tc.allows) {
				t.Fatalf("newly allowed %q lacks %q", p.NewlyAllows, tc.allows)
			}
			for _, s := range p.Sentences {
				if s.Direction != tc.want {
					t.Fatalf("sentence %+v is not %s", s, tc.want)
				}
			}
		})
	}
}

// A pattern is worded as what it does, and no more: the compiler expands it over the files there when the agent
// starts, so a match made later is allowed (checked against the decision engine in TestAGlobSentenceIsTrueOfALaterFile).
func TestPatternEntriesAreWordedByTheirEffect(t *testing.T) {
	f := realFixture(t)
	p := f.plan(t, "fs:\n  write: [./out/]\n", Edit{"add", "fs.deny_read", "./*.pem"})
	const limit = " that exist when the agent starts (a file created later is not covered)"
	if len(p.Sentences) != 1 || p.Sentences[0].Before != "May read files matching ./*.pem" || p.Sentences[0].After != "Refuses reads of the files matching ./*.pem"+limit {
		t.Fatalf("sentences %+v", p.Sentences)
	}
	p = f.plan(t, "fs:\n  write: [./out/]\n  deny_read: ['./*.pem']\n", Edit{"remove", "fs.deny_read", "./*.pem"})
	if len(p.Sentences) != 1 || p.Sentences[0].Before != "Refuses reads of the files matching ./*.pem"+limit || p.Sentences[0].After != "May read files matching ./*.pem" {
		t.Fatalf("sentences %+v", p.Sentences)
	}
	// The compiler takes no pattern in fs.ask_read, so only fs.deny_read has a pattern sentence.
	if p = f.plan(t, "fs:\n  write: [./out/]\n", Edit{"add", "fs.ask_read", "./*.pem"}); p.Err == "" {
		t.Fatalf("a pattern in fs.ask_read was proposed: %+v", p.Sentences)
	}
}

// An exec.allow entry with words is a command rule: its sentence is not "No change" while program arguments changed
// and cannot be ordered, and it agrees with the overall direction.
func TestACommandEntrySentenceAgreesWithTheOverallDirection(t *testing.T) {
	f := realFixture(t)
	p := f.plan(t, "", Edit{"add", "exec.allow", "cat status"})
	if p.Err != "" || p.Direction != "mixed" || !p.NeedsAck {
		t.Fatalf("%+v", p)
	}
	for _, s := range p.Sentences {
		if strings.Contains(s.After, "No change") || s.Direction != "mixed" {
			t.Fatalf("the sentence disagrees with the overall direction: %+v", s)
		}
	}
}

// A rule in a profile the contract extends still holds when the contract's own copy goes: the compiled tables are
// the same, so the change is said to be none, not "Cannot change ./out/".
func TestRemovingAnEntryAProfileAlsoGrantsChangesNothing(t *testing.T) {
	f := realFixture(t)
	profiles := filepath.Join(f.dir, "profiles")
	if err := os.MkdirAll(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(profiles, "shared.yaml"), "version: 0\nname: shared\nfs:\n  write: [./out/]\n")
	f.s.Machine.Profiles.Value = profiles
	p := f.plan(t, "extends: shared\nfs:\n  write: [./out/]\n", Edit{"remove", "fs.write", "./out/"})
	if p.Err != "" {
		t.Fatalf("refused: %s", p.Err)
	}
	if p.Direction != "narrows" || p.NeedsAck || len(p.NewlyAllows) != 0 {
		t.Fatalf("%+v", p)
	}
	if len(p.Sentences) != 1 || !strings.Contains(p.Sentences[0].After, "No change") || !strings.Contains(p.Sentences[0].After, "this contract no longer says it") {
		t.Fatalf("the sentence still says the entry is gone: %+v", p.Sentences)
	}
}

func TestNoComparisonProposesNothing(t *testing.T) {
	f := realFixture(t)
	f.s.Machine = nil // no machine config: nothing can be compiled
	writeFile(t, f.contract, directionHead+"fs:\n  write: [./out/]\n")
	c := f.ref(t, f.contract)
	p, err := f.s.PlanChange(t.Context(), ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "fs.write", "./out/"}}})
	if err == nil && (p.Err == "" || p.Ack != "" || p.ReviewID != "") {
		t.Fatalf("a change that cannot be compared was proposed: %+v", p)
	}
}
