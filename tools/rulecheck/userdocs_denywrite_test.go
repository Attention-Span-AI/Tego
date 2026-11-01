// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// A contract's own fs.deny_write list (ADR 0071) refuses writes inside a write grant race-free only where a kernel
// decision plane decides the run; at tier landlock, the tier a user without root gets, the supervisor refuses on the
// copied pathname, which a racing agent can pass. A page that says "deny_write blocks writes" without that tells a user
// a guarantee the no-root tier does not give, so every paragraph of docs/user that names it carries the label
// (agent.UserDenyWriteLabel, word for word).

const labelDenyWrite = "blocked for ordinary commands; not race-free at the no-root tier"

// denyWriteRe matches the words that name the list: deny_write, deny-write, "deny write", in any case, with markup
// around them.
var denyWriteRe = regexp.MustCompile(`(?i)\bdeny[_ -]write\b`)

// denyWriteFindings reports each paragraph of pages that names deny_write and does not say the label.
func denyWriteFindings(pages map[string]string) []string {
	var out []string
	for _, p := range userDocPages(pages) {
		for _, para := range paragraphs(visibleText(pages[p])) {
			m := denyWriteRe.FindString(para.text)
			if m == "" || strings.Contains(strings.ToLower(para.text), labelDenyWrite) {
				continue
			}
			out = append(out, fmt.Sprintf("%s:%d: names %q without %q in the same paragraph", p, para.line, m, labelDenyWrite))
		}
	}
	return out
}

// TestUserDocsLabelDenyWrite holds docs/user to ADR 0071's sentence.
func TestUserDocsLabelDenyWrite(t *testing.T) {
	for _, f := range denyWriteFindings(loadUserDocs(t)) {
		t.Error(f)
	}
}

// TestUserDocsDenyWriteCheckFindsPlantedBreakage: a paragraph naming the list in any spelling without the label is
// found, and one with it, or with the name only in a code block of a labelled paragraph, is not.
func TestUserDocsDenyWriteCheckFindsPlantedBreakage(t *testing.T) {
	bad := map[string]string{"docs/user/a.md": "# A\n\nList CI files in `fs.deny_write`.\n\n" +
		"Deny-write keeps them.\n\n" + "The deny write list blocks writes.\n\n"}
	if got := denyWriteFindings(bad); len(got) != 3 {
		t.Errorf("want three findings, got %v", got)
	}
	good := map[string]string{"docs/user/b.md": "# B\n\nList CI files in `fs.deny_write`: " + labelDenyWrite + ".\n\n" +
		"Blocked for ordinary commands; not race-free at the no-root tier. Deny-write keeps them.\n\n" +
		"The default tier needs no privilege.\n\n"}
	if got := denyWriteFindings(good); len(got) != 0 {
		t.Errorf("labelled paragraphs gave %v", got)
	}
}
