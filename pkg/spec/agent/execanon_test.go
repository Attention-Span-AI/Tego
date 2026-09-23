// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"strings"
	"testing"
)

// TestExecAnonymousOptIn is the contract half of the anonymous-image opt-out: `exec.anonymous: true` is a P0-consumed
// scalar under exec: that loads, merges like a scalar (contract wins if set, else the profile's), changes
// contract_hash only when set, and rejects anything but a boolean. Prepare reads it off the merged
// contract to skip the memfd_create arm, and the supervisor reads it to allow an anonymous image
// (SEMANTICS §4).
func TestExecAnonymousOptIn(t *testing.T) {
	base := "version: 0\nname: a\ncommand: [x]\n"
	c, ds, err := LoadBytes("a.yaml", []byte(base+"exec:\n  allow: [/bin/x]\n  anonymous: true\n"), nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	if c.Exec == nil || !c.Exec.Anonymous {
		t.Error("exec.anonymous: true did not load")
	}
	off, _, err := LoadBytes("a.yaml", []byte(base+"exec:\n  allow: [/bin/x]\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if off.Exec == nil || off.Exec.Anonymous {
		t.Error("an absent exec.anonymous loaded as true; the default refuses anonymous images")
	}
	on, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := off.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(on) == string(plain) || !strings.Contains(string(on), "anonymous: true") {
		t.Errorf("contract_hash must see the opt-out:\n%s", on)
	}

	// A profile's opt-out is inherited; a contract's explicit false wins over it.
	profiles := mapSource{"p": "exec:\n  anonymous: true\n"}
	inherited, ds, err := LoadBytes("a.yaml", []byte(base+"extends: p\nexec:\n  allow: [/bin/x]\n"), profiles)
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	if inherited.Exec == nil || !inherited.Exec.Anonymous {
		t.Error("the profile's exec.anonymous: true was not inherited")
	}
	overridden, _, err := LoadBytes("a.yaml", []byte(base+"extends: p\nexec:\n  allow: [/bin/x]\n  anonymous: false\n"), profiles)
	if err != nil {
		t.Fatal(err)
	}
	if overridden.Exec != nil && overridden.Exec.Anonymous {
		t.Error("the contract's exec.anonymous: false did not win over the profile's true")
	}

	if _, _, err := LoadBytes("a.yaml", []byte(base+"exec:\n  anonymous: sometimes\n"), nil); !errors.Is(err, ErrInvalidContract) {
		t.Errorf("exec.anonymous: sometimes loaded (%v); only true or false is a value", err)
	}
}

// TestExecAnonymousOptOutWarns is the opt-out made explicit at compile (SEMANTICS §4): a contract
// that sets exec.anonymous: true gets one unenforced warning, positioned at the key, saying exec.allow no
// longer bounds what runs; one that leaves it out, or sets it false, gets none.
func TestExecAnonymousOptOutWarns(t *testing.T) {
	f := newFixture(t)
	warned := func(ds []Diagnostic) []Diagnostic {
		var out []Diagnostic
		for _, d := range ds {
			if d.Code == CodeUnenforced && strings.Contains(d.Message, "exec.anonymous") {
				out = append(out, d)
			}
		}
		return out
	}
	_, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [python]\n  anonymous: true\n"))
	got := warned(ds)
	if len(got) != 1 || got[0].Severity != SeverityWarning || got[0].Line != 6 ||
		!strings.Contains(got[0].Message, "exec.allow no longer bounds what runs") {
		t.Fatalf("want one positioned warning at exec.anonymous:\n%s", render(ds))
	}
	for _, body := range []string{
		"version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [python]\n",
		"version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [python]\n  anonymous: false\n",
	} {
		if _, ds := f.compile(f.load(body)); len(warned(ds)) != 0 {
			t.Errorf("no opt-out, yet a warning:\n%s", render(ds))
		}
	}
}
