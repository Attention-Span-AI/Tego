// SPDX-License-Identifier: Apache-2.0

package result

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestShortTextKeepsSourceRowsVerbose(t *testing.T) {
	s := example(t)
	for _, verbose := range []bool{false, true} {
		var out, errs bytes.Buffer
		if err := Render(&out, &errs, s, false, verbose, nil); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "Source s-1") != verbose {
			t.Fatalf("verbose=%t source rows: %s", verbose, out.String())
		}
		if !strings.Contains(out.String(), "Not looked at:") || !strings.Contains(errs.String(), "Not looked at:") {
			t.Fatal("coverage footer missing")
		}
	}
}

func TestDecodeRejectsNonprintingPaths(t *testing.T) {
	for _, r := range []rune{'\u200e', '\u200f', '\u061c', '\u2028', '\u2029', '\u200b', '\u2060', '\u001b', '\ufffd'} {
		s := example(t)
		s.Project = Path("/home/a" + string(r) + "b")
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(b); err == nil {
			t.Errorf("accepted nonprinting U+%04X", r)
		}
	}
}

func TestUnreadableProgramExitAndContract(t *testing.T) {
	s := example(t)
	s.Check = "unreadable-observed"
	s.Status = "partial"
	s.Counts.Running, s.Counts.Outside = 0, 0
	s.Items = s.Items[1:]
	s.Counts.UnreadablePrograms = 1
	s.UnreadableProgramPIDs = []int{99}
	s.Sources = append(s.Sources, Source{ID: "s-unreadable", Kind: "A", State: "unreadable-program", Reason: "permission", NotRead: 1})
	for _, tc := range []struct {
		check string
		exit  int
	}{
		{"unreadable-observed", 3}, {"none-observed-allow-unreadable", 0}, {"unknown", 125},
	} {
		s.Check = tc.check
		if _, err := Encode(s); err != nil {
			t.Fatalf("%s: %v", tc.check, err)
		}
		if got := s.ExitCode(); got != tc.exit {
			t.Errorf("%s: exit %d, want %d", tc.check, got, tc.exit)
		}
	}
	s.Check = "none-observed"
	if _, err := Encode(s); err == nil {
		t.Fatal("strict negative accepted unreadable programs")
	}
	s.Check = "unreadable-observed"
	s.UnreadableProgramPIDs = []int{99, 99}
	if _, err := Encode(s); err == nil {
		t.Fatal("duplicate pid accepted")
	}
}

func TestLimitedResultsDoNotPrintNegativeMatchStatement(t *testing.T) {
	base := example(t)
	s := New(base.Started, base.As.UID, "dev")
	s.Status = "partial"
	s.Limits = []string{"item-limit"}
	s.Rules = []Rule{{ID: "mcp-claude", Name: "claude", Origin: "catalog"}}
	s.Sources = []Source{{ID: "s-1", Kind: "D", Locator: Path("/home/me/.mcp.json"), State: "read", Read: 1, Reason: "none"}}
	if _, e := Encode(s); e != nil {
		t.Fatal(e)
	}
	var out, errs bytes.Buffer
	if e := Render(&out, &errs, s, false, false, nil); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "No match among") {
		t.Fatal("retention-limited rows became a negative match statement")
	}
}
