// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCompareRunIDsOrdersByMintTimeNotHost(t *testing.T) {
	// Same time component, different hosts: the host is only the last tie-break.
	a := "r-aaaaaaaa-000000000000a-aaaaaa"
	b := "r-00000000-000000000000b-bbbbbb"
	c := "r-ffffffff-000000000000a-aaaaaa"
	if CompareRunIDs(a, b) >= 0 || CompareRunIDs(b, a) <= 0 {
		t.Error("an earlier time sorts first whatever its host")
	}
	if CompareRunIDs(a, c) >= 0 || CompareRunIDs(c, a) <= 0 {
		t.Error("identical time and random part fall back to the whole id")
	}
	if CompareRunIDs(a, a) != 0 {
		t.Error("an id equals itself")
	}
	// Anything that is not a run id sorts before every run id.
	if CompareRunIDs("junk", a) >= 0 || CompareRunIDs(a, "junk") <= 0 {
		t.Error("a non-run sorts before a run")
	}
	if CompareRunIDs("aaa", "bbb") >= 0 {
		t.Error("two non-runs sort by their text")
	}
	ids := []string{b, c, "zzz", a, "abc"}
	slices.SortFunc(ids, CompareRunIDs)
	if want := []string{"abc", "zzz", a, c, b}; !slices.Equal(ids, want) {
		t.Errorf("sorted %v, want %v", ids, want)
	}
}

func TestLiveEntriesListsOnlyRunIDs(t *testing.T) {
	root := t.TempDir()
	if got, err := LiveEntries(filepath.Join(root, "nope")); err != nil || got != nil {
		t.Errorf("a missing root lists none: %v, %v", got, err)
	}
	if got, err := LiveEntries(root); err != nil || len(got) != 0 {
		t.Errorf("a root with no index lists none: %v, %v", got, err)
	}
	const a, b = "r-00000000-000000000000a-aaaaaa", "r-00000000-000000000000b-bbbbbb"
	for _, id := range []string{a, b} {
		if err := MarkLive(root, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := MarkLive(root, a); err != nil {
		t.Errorf("marking twice is not an error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, LiveDir, "stray"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LiveEntries(root)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{a, b}) {
		t.Errorf("got %v, want the two run ids and not the stray name", got)
	}
	if err := MarkLive(root, "not-a-run"); !errors.Is(err, ErrBadRunRef) {
		t.Errorf("a bad id must be refused: %v", err)
	}
}

func TestLiveIndexThatIsALinkIsRefused(t *testing.T) {
	// The index is reached O_NOFOLLOW whoever reads it: a sweep never follows a link a planted name points
	// through, however the launcher's own walk treats the user's directories.
	root, elsewhere := t.TempDir(), t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(root, LiveDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := LiveEntries(root); !errors.Is(err, ErrLinkRefused) {
		t.Errorf("LiveEntries through a link: %v, want ErrLinkRefused", err)
	}
}

func TestAppendTextJoinsAdjacentTextAndKeepsPartsNonEmpty(t *testing.T) {
	var parts []splicePart
	parts = appendText(parts, nil)
	parts = appendText(parts, []byte(""))
	if len(parts) != 0 {
		t.Fatalf("empty text adds nothing: %v", parts)
	}
	parts = appendText(parts, []byte("ab"))
	parts = appendText(parts, []byte("cd"))
	if len(parts) != 1 || parts[0].Text != "abcd" {
		t.Fatalf("adjacent text joins: %+v", parts)
	}
	parts = append(parts, splicePart{Blob: "sha"})
	parts = appendText(parts, []byte("ef"))
	if len(parts) != 3 || parts[1].Blob != "sha" || parts[2].Text != "ef" {
		t.Fatalf("text after a blob part starts its own part: %+v", parts)
	}
}

func TestJSONSkippersStopWhereTheValueEnds(t *testing.T) {
	if got := skipWS([]byte(" \t\r\n x"), 0); got != 5 {
		t.Errorf("skipWS = %d, want 5", got)
	}
	if got := skipWS([]byte("   "), 0); got != 3 {
		t.Errorf("all whitespace skips to the end: %d", got)
	}
	s := []byte(`"a\"b\\" tail`)
	if got := skipString(s, 0); got != 8 {
		t.Errorf("skipString = %d, want 8 (past the closing quote, escapes honoured)", got)
	}
	if got := skipString([]byte(`"unterminated`), 0); got != len(`"unterminated`) {
		t.Errorf("an unterminated string ends at the input's end: %d", got)
	}
}
