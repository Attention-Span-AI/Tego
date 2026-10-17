// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The stale-status check: docs/p0/TIER3-PLAN.md §10 is where a tier-3 ticket is marked built ("**Done ...**" or
// "**Built ...**" in its row); FEATURES.md and spec/backend/CAPABILITIES.md carry prose that says what is not built.
// A ticket the plan marks built and one of those files still lists in a "not built" clause is a stale note, and
// the check fails it. A mechanism built but not enabled ("**Mechanism built ..., not enabled**") is not marked built.

// ticketPlan and ticketNotes are the files the check reads, relative to the root.
const ticketPlan = "docs/p0/TIER3-PLAN.md"

var ticketNotes = []string{"docs/FEATURES.md", "spec/backend/CAPABILITIES.md"}

var (
	ticketRowRe   = regexp.MustCompile(`^\|\s*(T\d+[a-z]?)\s*\|`)
	ticketBuiltRe = regexp.MustCompile(`\*\*(Done|Built)\b`)
	notBuiltRe    = regexp.MustCompile(`(?i)\bnot built\b|\bunbuilt\b`)
	ticketRangeRe = regexp.MustCompile(`\bT(\d+)\s+to\s+T(\d+)\b`)
	ticketIDRe    = regexp.MustCompile(`\bT(\d+[a-z]?)\b`)
)

// BuiltTickets returns the tickets TIER3-PLAN's table marks built.
func BuiltTickets(plan string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(plan, "\n") {
		m := ticketRowRe.FindStringSubmatch(line)
		if m != nil && ticketBuiltRe.MatchString(line) {
			out[m[1]] = true
		}
	}
	return out
}

// notBuiltTicketIDs returns the tickets a line names in the clause that follows a "not built" (to the end of the
// sentence: a full stop before a space, or the line's end), a range "T13 to T15" expanded.
func notBuiltTicketIDs(line string) []string {
	seen := map[string]bool{}
	for _, loc := range notBuiltRe.FindAllStringIndex(line, -1) {
		clause := line[loc[1]:]
		if i := strings.Index(clause, ". "); i >= 0 {
			clause = clause[:i]
		}
		for _, r := range ticketRangeRe.FindAllStringSubmatch(clause, -1) {
			lo, _ := strconv.Atoi(r[1])
			hi, _ := strconv.Atoi(r[2])
			for n := lo; n <= hi && n-lo < 64; n++ {
				seen["T"+strconv.Itoa(n)] = true
			}
		}
		for _, id := range ticketIDRe.FindAllStringSubmatch(clause, -1) {
			seen["T"+id[1]] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// CheckTicketStatus returns a finding for each ticket TIER3-PLAN marks built that a note file lists as not built.
// notes maps a file's path to its text.
func CheckTicketStatus(plan string, notes map[string]string) []Finding {
	built := BuiltTickets(plan)
	paths := make([]string, 0, len(notes))
	for p := range notes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var out []Finding
	for _, p := range paths {
		for i, line := range strings.Split(notes[p], "\n") {
			for _, id := range notBuiltTicketIDs(line) {
				if built[id] {
					out = append(out, Finding{Doc: p, Line: i + 1,
						What: fmt.Sprintf("says %s is not built, and %s marks it built", id, ticketPlan)})
				}
			}
		}
	}
	return out
}

// loadTicketStatus reads the plan and the note files under root; a tree without the plan (a test fixture) has
// nothing to check.
func loadTicketStatus(root string) (string, map[string]string) {
	b, err := os.ReadFile(filepath.Join(root, ticketPlan))
	if err != nil {
		return "", nil
	}
	notes := map[string]string{}
	for _, n := range ticketNotes {
		if nb, err := os.ReadFile(filepath.Join(root, n)); err == nil {
			notes[n] = string(nb)
		}
	}
	return string(b), notes
}
