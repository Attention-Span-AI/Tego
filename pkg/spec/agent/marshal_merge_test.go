// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestEmptyFormCanonicalLoadsBack pins that the `deny_read: []` and `pass: []` forms, built by re-parsing
// the section's own encoding through a yaml.Node, write a literal "<<" quoted, never `!!merge <<`: Load
// refuses every explicit tag, so the tagged form made the run's contract.yaml unloadable for tego drift
// (R13). Canonical must be a fixed point of LoadBytes.
func TestEmptyFormCanonicalLoadsBack(t *testing.T) {
	for _, src := range []string{
		"version: 0\nname: a\ncommand: [x]\nfs: {write: [\"<<\"], deny_read: []}\n",
		"version: 0\nname: a\ncommand: [x]\nenv: {pass: [], set: {A: \"<<\"}}\n",
	} {
		c, _, err := LoadBytes("a.yaml", []byte(src), nil)
		if err != nil {
			t.Fatalf("%q: %v", src, err)
		}
		b, err := c.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "!!") {
			t.Errorf("%q: Canonical = %q, want no explicit tag", src, b)
		}
		c2, _, err := LoadBytes("b.yaml", b, nil)
		if err != nil {
			t.Fatalf("%q: Canonical %q does not load back: %v", src, b, err)
		}
		b2, err := c2.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if string(b2) != string(b) {
			t.Errorf("%q: Canonical is not a fixed point: %q then %q", src, b, b2)
		}
	}
	withEmpty, err := yaml.Marshal(FSSection{Write: []string{"<<"}, DenyRead: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	var back FSSection
	if err := yaml.Unmarshal(withEmpty, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Write) != 1 || back.Write[0] != "<<" || back.DenyRead == nil || len(back.DenyRead) != 0 {
		t.Errorf("%q loads back as %+v, want write [\"<<\"] and deny_read []", withEmpty, back)
	}
}
