// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// NotKnownFact is what a step whose source could not be read says in place of a fact: the NotKnown lines say which.
const NotKnownFact = "not known (see below)"

// Words is the object as a person reads it, the one form `tego setup` prints and the dashboard's guide shows (the
// same steps, facts and not-known lines on both surfaces): each text written with paths under the user's home as ~/
// and every character that does not print as itself made visible (record.Printable). Next is the object's, unchanged:
// its text is fixed words and its command is built by this package (next.go), never from a file's text.
type Words struct {
	Steps    []StepWords
	NotKnown []string
}

// StepWords is one step in words: its number (1 to 6), id, title and state as the object has them, then the fact
// that decided it (NotKnownFact for a step whose source could not be read), where it was read, the run it is about and
// why that run or contract was taken ("" for none).
type StepWords struct {
	N                 int
	ID, Title, State  string
	Fact              string
	Source, Run, Link string
}

// Words is s in words for a person whose home is home.
func (s *State) Words(home string) Words {
	w := Words{Steps: make([]StepWords, 0, len(s.Steps))}
	for i, st := range s.Steps {
		fact := NotKnownFact
		if st.Fact != nil {
			fact = tilde(*st.Fact, home)
		}
		w.Steps = append(w.Steps, StepWords{N: i + 1, ID: st.ID, Title: st.Title, State: st.State,
			Fact: record.Printable(fact), Source: record.Printable(tilde(st.Source, home)),
			Run: record.Printable(st.Run), Link: record.Printable(tilde(st.Link, home))})
	}
	for _, n := range s.NotKnown {
		w.NotKnown = append(w.NotKnown, record.Printable(tilde(n, home)))
	}
	return w
}

// tilde is s with home written as ~ where it starts a path.
func tilde(s, home string) string {
	if home == "" || home == "/" {
		return s
	}
	return strings.ReplaceAll(s, home+"/", "~/")
}
