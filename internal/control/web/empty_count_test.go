// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"golang.org/x/net/html"
)

// TestIncompletePagesHaveNoUnqualifiedEmptyClaims: an empty state is a count of zero, so an incomplete source cannot
// say "none". Truncated windows and malformed lines say what is not fully known; a run that could not be read makes
// the Overview say it could not read, and it never claims that nothing runs.
func TestIncompletePagesHaveNoUnqualifiedEmptyClaims(t *testing.T) {
	old := ledgerview.MaxLines
	ledgerview.MaxLines = 4
	t.Cleanup(func() { ledgerview.MaxLines = old })
	for _, mode := range []string{"truncated", "malformed", "unlisted"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			id := secondRequestRun
			dir := filepath.Join(root, id)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			at := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
			var events strings.Builder
			events.WriteString(line(id, "Agent", 0, at, "run_start", `"tier":"observe","command":["agent"]`))
			if mode == "truncated" {
				events.WriteString(line(id, "Agent", 1, at, "refused", `"rule":"fs.deny_read","op":"read","target":"/home/u/.ssh/id_rsa"`))
			}
			for seq := 2; seq < 20; seq++ {
				events.WriteString(line(id, "Agent", seq, at.Add(time.Duration(seq)*time.Second), "exec", `"rule":"exec.allow","verdict":"allow","path":"/bin/true"`))
			}
			if mode == "malformed" {
				events.WriteString("{not a record}\n")
			}
			if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(events.String()), 0600); err != nil {
				t.Fatal(err)
			}
			paths := []string{"/", "/runs/" + id, "/runs/" + id + "/refusals"}
			if mode == "unlisted" {
				// A second run whose events file cannot be read as a file: the scan cannot list it.
				if err := os.MkdirAll(filepath.Join(root, "r-aaaaaaaa-0000000000099-unlist", "events.jsonl"), 0700); err != nil {
					t.Fatal(err)
				}
				paths = []string{"/"}
			}
			r, err := ledgerview.LoadRun(root, id)
			if err != nil {
				t.Fatal(err)
			}
			if !r.Cut || (r.Bad > 0) != (mode == "malformed") {
				t.Fatalf("fixture scope cut=%v bad=%d", r.Cut, r.Bad)
			}
			s := newServer(t, root)
			c := login(t, s)
			for _, path := range paths {
				t.Run(path, func(t *testing.T) {
					body := get(t, s, c, path)
					doc := parseHTML(t, path, body)
					checked := 0
					walk(doc, func(n *html.Node) {
						class, _ := attr(n, "class")
						isHighlight := class == "hl-none"
						parentClass := ""
						if n.Parent != nil {
							parentClass, _ = attr(n.Parent, "class")
						}
						isRefusalEmpty := n.Data == "h3" && hasClass(parentClass, "empty")
						isDetectionEmpty := n.Data == "p" && strings.Contains(text(n), "High and Medium detections")
						if !isHighlight && !isRefusalEmpty && !isDetectionEmpty {
							return
						}
						checked++
						words := text(n)
						if mode == "unlisted" {
							if !strings.Contains(words, "could not be read") {
								t.Errorf("reader failure leaves empty claim %q", words)
							}
						} else if !strings.Contains(words, "not fully known") {
							t.Errorf("%s leaves empty claim %q", mode, words)
						}
					})
					if checked == 0 {
						t.Fatal("no incomplete empty-state claim was checked")
					}
					for _, claim := range []string{"No secrets touched", "No connections", "Nothing High or Medium", "Nothing was refused"} {
						if strings.Contains(body, claim) {
							t.Errorf("incomplete page claims %q", claim)
						}
					}
					if mode == "unlisted" && (strings.Contains(body, "Nothing running") || !strings.Contains(body, "Running runs could not be read")) {
						t.Error("a run that could not be listed leaves an exact running absence")
					}
				})
			}
		})
	}
}
