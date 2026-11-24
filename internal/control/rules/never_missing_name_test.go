// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
)

// "Never allow" for a read an ask entry asked about offers the file's own name. The fixture's asked read is
// docs/token, which does not exist: the compiler refuses a refusal of a name that is not there (path-missing), so the
// choice offered an effect nobody could have, and a person who found it refused at the confirm was left with the
// looser choices. The choice now says so before it is picked, in words, and the folder that holds the file stays
// offered.
func TestNeverForAMissingNameIsNotOfferedAsAnEffect(t *testing.T) {
	f := realFixture(t)
	writeFile(t, f.contract, directionHead+"fs:\n  ask_read: [./docs/]\n")
	f.ref(t, f.contract)
	p, err := f.s.ActOn(t.Context(), ActReq{Run: runA, Seq: 1})
	if err != nil {
		t.Fatal(err)
	}
	var file, folder *Choice
	for i, c := range p.Choices {
		if c.Action == "block" && c.Scope == (Scope{Level: 0}) {
			file = &p.Choices[i]
		}
		if c.Action == "block" && c.Scope == (Scope{Level: 1}) {
			folder = &p.Choices[i]
		}
	}
	if file == nil || folder == nil {
		t.Fatalf("no block choices: %+v", p.Choices)
	}
	if file.OK || !strings.Contains(file.Why, "does not exist yet") || !strings.Contains(file.Why, "leave it asking") {
		t.Fatalf("a refusal of a missing name is offered as an effect: %+v", *file)
	}
	if !folder.OK || folder.Direction != "narrows" {
		t.Fatalf("the folder that holds it is not offered: %+v", *folder)
	}
	// Picking it anyway says the same, and writes nothing.
	pick, err := f.s.ActOn(t.Context(), ActReq{Run: runA, Seq: 1, Action: "block", Scope: Scope{Level: 0}})
	if err != nil {
		t.Fatal(err)
	}
	if pick.PickErr == "" || !strings.Contains(pick.PickErr, "does not exist yet") || pick.Diff != "" {
		t.Fatalf("%+v", pick)
	}
}
