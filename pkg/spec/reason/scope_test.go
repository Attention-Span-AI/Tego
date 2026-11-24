// SPDX-License-Identifier: Apache-2.0

package reason

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The delivery event is not evidence that its tool or session caused a refusal.
// Keep that fact in each note, even when SessionStart did not run.
func TestReasonNotesStateTheirRunScope(t *testing.T) {
	const scope = "Scope: whole run, including startup and background work; tool call and session attribution unavailable."
	e := entry(1, "open", "/tool-output", record.ReasonWriteOutsideContract, "fs.write")
	for name, text := range map[string]string{
		"listed":       Render([]Entry{e}, 0),
		"not listed":   Render(nil, 50),
		"instructions": HookInstructions("/run/user/1000/tego/r/last-refusal.json"),
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(text, scope) {
				t.Errorf("refusals have no explicit run scope: %q", text)
			}
		})
	}
}

// Quote bounds the path before it enters setup, including escape expansion. A
// long TEGO_REASON must leave both scope and exact omission accounting intact.
func TestSessionStartAccountsForLongReasonPaths(t *testing.T) {
	var entries []Entry
	for i := range RingSize {
		entries = append(entries, entry(uint64(i+1), "open", fmt.Sprintf("/%d/", i)+strings.Repeat("t", MaxShownBytes),
			record.ReasonWriteOutsideContract, "fs.write"))
	}
	for _, segment := range []string{"a", "<", ">", "\x01", "\xff", "é"} {
		t.Run(fmt.Sprintf("%x", segment), func(t *testing.T) {
			path := "/" + strings.Repeat(segment, 10000) + "/tego/r/last-refusal.json"
			for _, notListed := range []uint64{68, ^uint64(0) - uint64(len(entries))} {
				text := RenderSessionStart(path, entries, notListed)
				if len(text) > MaxRenderBytes || !utf8.ValidString(text) {
					t.Errorf("path %d bytes, count %d: invalid context or %d-byte output", len(path), notListed, len(text))
				}
				if strings.ContainsAny(text, "<>\x00\x01") || !strings.Contains(text, scopeNote) {
					t.Errorf("unsafe or missing scope: %q", text)
				}
				var accounted uint64
				for _, line := range strings.Split(text, "\n") {
					switch {
					case strings.HasPrefix(line, "- x"):
						n, err := strconv.ParseUint(strings.Fields(line)[1][1:], 10, 64)
						if err != nil {
							t.Fatal(err)
						}
						accounted += n
					case strings.HasPrefix(line, "- "):
						accounted++
					case strings.HasSuffix(line, " more not listed."):
						n, err := strconv.ParseUint(strings.Fields(line)[0], 10, 64)
						if err != nil {
							t.Fatal(err)
						}
						accounted += n
					}
				}
				if want := uint64(len(entries)) + notListed; accounted != want {
					t.Errorf("accounted %d, want %d: %q", accounted, want, text)
				}
			}
		})
	}
}

// The setup already states the scope. Keep it once even when a start also
// previews pending refusals, leaving the rest of the budget for refusal facts.
func TestSessionStartStatesScopeOnce(t *testing.T) {
	e := entry(1, "open", "/tool-output", record.ReasonWriteOutsideContract, "fs.write")
	for _, entries := range [][]Entry{nil, {e}} {
		text := RenderSessionStart("/run/user/1000/tego/r/last-refusal.json", entries, 0)
		if n := strings.Count(text, scopeNote); n != 1 {
			t.Errorf("scope repeated %d times: %q", n, text)
		}
	}
}
