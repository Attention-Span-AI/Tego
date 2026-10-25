// SPDX-License-Identifier: Apache-2.0

package handoff

// Noun is one command tego hands to tego-control, with the summary both binaries' usage gives it, and whether this
// build has its command (Built) or only a registration that says it is not there yet.
type Noun struct {
	Name    string
	Summary string
	Built   bool
}

// nouns is ADR 0100 (2)'s list of tego-control's nouns, one line per noun, sorted. A package that adds a noun adds
// its line here and its command to internal/control/cli; TestHandoffNounsMatchControlCommands holds the two
// equal, and TestNoNounInBothBinaries keeps every noun out of the engine's own commands. A file of a build's own may
// add nouns from its init and keep the list sorted. A noun is Built once its command is more than a registration that
// says it is not there yet (TestNotBuiltNounSaysSo holds the two equal): both binaries' help lists only the built
// nouns as commands and names the others on one "planned" line, so help offers nothing that would only answer that it
// is not there yet.
var nouns = []Noun{
	{"serve", "start the control service and its dashboard", true},
}

// Nouns returns the nouns tego hands to tego-control, sorted by name.
func Nouns() []Noun { return append([]Noun(nil), nouns...) }

// Planned returns the names of the nouns this build does not have yet, sorted.
func Planned() []string {
	var out []string
	for _, n := range nouns {
		if !n.Built {
			out = append(out, n.Name)
		}
	}
	return out
}

// IsNoun reports whether name is one of them.
func IsNoun(name string) bool {
	for _, n := range nouns {
		if n.Name == name {
			return true
		}
	}
	return false
}
