// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestRecordOffIsNotedWhereTheContractSetsIt: a contract's own record: off cuts its runs' ledgers to their refusals,
// and no finding named it (R29 warns of the --record off flag alone). It is what the author wrote and weakens no rule,
// so it is a note: compile prints it at the record: key that set it, a profile's when the contract extends it, and a
// run only under -v (limits-check-doctor-cli.md, "A quiet start"). A record mode the run gives (WithRecord) is the
// launching user's: --record off has its own warning, and a --record that raises the record leaves the contract's off
// unused, so neither is noted; nor is a contract that records.
func TestRecordOffIsNotedWhereTheContractSetsIt(t *testing.T) {
	const base = "version: 0\nname: quiet\ncommand: [\"/bin/sh\"]\ntier: landlock\n"
	notes := func(ds []Diagnostic) []Diagnostic {
		var got []Diagnostic
		for _, d := range ds {
			if d.Code == CodeRecordOff {
				got = append(got, d)
			}
		}
		return got
	}
	for _, tc := range []struct {
		name, record string
		opts         []CompileOption
		want         bool
	}{
		{"record: off", "record: off\n", nil, true},
		{"record: off under --record off", "record: off\n", []CompileOption{WithRecord(RecordOff)}, false},
		{"record: off under --record summary", "record: off\n", []CompileOption{WithRecord(RecordSummary)}, false},
		{"record: summary under --record off", "record: summary\n", []CompileOption{WithRecord(RecordOff)}, false},
		{"record: summary", "record: summary\n", nil, false},
		{"record: full", "record: full\n", nil, false},
		{"no record:", "", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			_, ds := f.compile(f.load(base+tc.record), tc.opts...)
			got := notes(ds)
			if !tc.want {
				if len(got) != 0 {
					t.Fatalf("noted:\n%s", render(got))
				}
				return
			}
			contract := filepath.Join(f.project, "agent.yaml")
			if len(got) != 1 {
				t.Fatalf("%d record-off notes, want 1:\n%s", len(got), render(ds))
			}
			if d := got[0]; !d.Informational() || d.Severity != SeverityWarning || d.File != contract || d.Line != 5 ||
				!strings.Contains(d.Message, "record: off keeps only a run's refusals") || !strings.Contains(d.Fix, "record: summary") {
				t.Fatalf("the note %+v: want an informational warning at %s:5 saying what record: off keeps, with its fix", d, contract)
			}
		})
	}

	// A profile's record: off, which the contract extends without writing record: itself, is noted at the profile's
	// line: record is contract-wins, so the profile set it for the contract.
	f := newFixture(t)
	f.profiles() // the fixture's profiles directory, which the contract below resolves its extends in
	profile := filepath.Join(f.root, "profiles", "quiet.yaml")
	f.file(profile, "# the team's runs that keep no record\nrecord: off\n", 0o644)
	_, ds := f.compile(f.load(base + "extends: quiet\n"))
	if got := notes(ds); len(got) != 1 || got[0].File != profile || got[0].Line != 2 || !got[0].Informational() {
		t.Fatalf("a profile's record: off:\n%s\nwant one note at %s:2", render(got), profile)
	}
}
