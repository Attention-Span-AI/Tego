// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"strings"
	"testing"
)

// TestRevisionIsTheContractsOwn is agent-contract.md R28: revision is an optional
// ^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$ the loaded contract keeps, refused when empty, too long or with another character.
func TestRevisionIsTheContractsOwn(t *testing.T) {
	const head = "version: 0\nname: a\ncommand: [x]\n"
	for _, rev := range []string{"1", "2026.10.25+1", "v1.2.3-rc_1", "A" + strings.Repeat("b", 63)} {
		c, ds, err := LoadBytes("a.yaml", []byte(head+"revision: "+quoteYAML(rev)+"\n"), nil)
		if err != nil || c.Revision != rev {
			t.Errorf("revision %q: loaded %v, err %v\n%s", rev, c, err, render(ds))
		}
	}
	c, _, err := LoadBytes("a.yaml", []byte(head), nil)
	if err != nil || c.Revision != "" {
		t.Fatalf("a contract with no revision: %v %v", c, err)
	}
	for _, rev := range []string{"", "A" + strings.Repeat("b", 64), "a b", "-1", ".1", "+1", "_1", "1/2", "1:2", "é1", "1\u202e"} {
		_, ds, err := LoadBytes("a.yaml", []byte(head+"revision: "+quoteYAML(rev)+"\n"), nil)
		if err == nil {
			t.Errorf("revision %q loaded", rev)
			continue
		}
		if len(ds) == 0 || ds[0].Code != CodeSchema || ds[0].Line != 4 || !strings.Contains(ds[0].Message, "revision") {
			t.Errorf("revision %q: %s, want a [schema] error at line 4 naming revision", rev, render(ds))
		}
	}
}

// TestRevisionIsAYAMLString is agent-contract.md R28's spellings: revision is a YAML string in Go as in
// agent.schema.json ({"type": "string"}), so an unquoted value YAML reads as a number or a boolean is a [schema] error
// with the fix to quote it, and a null one (the key with nothing after it, ~ or null) is a [schema] error, never read
// as no revision. A plain spelling YAML reads as a string (1.4.0, v1, 2026.10.25) loads as written.
func TestRevisionIsAYAMLString(t *testing.T) {
	const head = "version: 0\nname: a\ncommand: [x]\n"
	for _, tc := range []struct{ spelling, want string }{
		{"1.4.0", "1.4.0"}, {"v1", "v1"}, {"2026.10.25", "2026.10.25"}, {"2026.10.25+1", "2026.10.25+1"},
		{`"1"`, "1"}, {`'1.50'`, "1.50"}, {`"true"`, "true"},
	} {
		c, ds, err := LoadBytes("a.yaml", []byte(head+"revision: "+tc.spelling+"\n"), nil)
		if err != nil || c.Revision != tc.want {
			t.Errorf("revision: %s loaded %v (%v), want %q\n%s", tc.spelling, c, err, tc.want, render(ds))
		}
	}
	for _, tc := range []struct{ spelling, want string }{
		{"1", "quote"}, {"1.50", "quote"}, {"true", "quote"}, {"0x1F", "quote"}, {"1e3", "quote"}, {"-1", "must match"},
		{"", "no value"}, {"~", "no value"}, {"null", "no value"},
	} {
		_, ds, err := LoadBytes("a.yaml", []byte(head+"revision: "+tc.spelling+"\n"), nil)
		if err == nil || len(ds) == 0 || ds[0].Code != CodeSchema || ds[0].Line != 4 ||
			!strings.Contains(ds[0].Message, "revision") || !strings.Contains(ds[0].Message+ds[0].Fix, tc.want) {
			t.Errorf("revision: %s loaded (%v) with %s, want a [schema] error at line 4 saying %q", tc.spelling, err,
				render(ds), tc.want)
		}
	}
	// So in a profile: a null revision there is no value either, never read as the profile setting none.
	_, ds, err := LoadBytes("child.yaml", []byte("version: 0\nname: a\nextends: p\ncommand: [x]\n"),
		mapSource{"p": "version: 0\nrevision:\n"})
	if err == nil {
		t.Fatalf("a profile with a null revision loaded\n%s", render(ds))
	}
}

func quoteYAML(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// TestRevisionIsRefusedInAProfile is agent-contract.md R28 and R5's refused-in-profile class: a profile reached by
// extends that sets revision is a [schema] error at its line, fix "set revision in the top-level contract", and the
// top-level contract's own revision is kept beside a profile's other keys.
func TestRevisionIsRefusedInAProfile(t *testing.T) {
	_, ds, err := LoadBytes("child.yaml", []byte("version: 0\nname: a\nextends: p\ncommand: [x]\n"),
		mapSource{"p": "version: 0\nrevision: \"3\"\n"})
	if err == nil {
		t.Fatalf("a profile setting revision loaded\n%s", render(ds))
	}
	var hit bool
	for _, d := range ds {
		if d.Severity == "error" && d.Code == CodeSchema && strings.HasSuffix(d.File, "p.yaml") && d.Line == 2 &&
			d.Fix == "set revision in the top-level contract" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("no [schema] error at p.yaml:2 with the fix to set revision in the top-level contract\n%s", render(ds))
	}
	c, ds, err := LoadBytes("child.yaml", []byte("version: 0\nname: a\nextends: p\ncommand: [x]\nrevision: \"7\"\n"),
		mapSource{"p": "version: 0\nrecord: full\n"})
	if err != nil || c.Revision != "7" || c.Record != RecordFull {
		t.Fatalf("the top-level contract's revision over a profile: %+v %v\n%s", c, err, render(ds))
	}
}

// TestRevisionIsInTheCanonicalBytes is agent-contract.md R28 and R13: revision is part of the canonical bytes, so two
// contracts that differ only in it hash differently, and a contract without one writes no revision key.
func TestRevisionIsInTheCanonicalBytes(t *testing.T) {
	const head = "version: 0\nname: a\ncommand: [x]\n"
	hash := func(src string) ([32]byte, []byte) {
		t.Helper()
		c, ds, err := LoadBytes("a.yaml", []byte(src), nil)
		if err != nil {
			t.Fatalf("%v\n%s", err, render(ds))
		}
		b, err := c.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		h, err := c.Hash()
		if err != nil {
			t.Fatal(err)
		}
		return h, b
	}
	none, noneBytes := hash(head)
	one, oneBytes := hash(head + "revision: \"1\"\n")
	two, _ := hash(head + "revision: \"2\"\n")
	if none == one || one == two || none == two {
		t.Fatal("contracts that differ only in revision hash alike")
	}
	if bytes.Contains(noneBytes, []byte("revision")) {
		t.Fatalf("a contract with no revision writes one:\n%s", noneBytes)
	}
	if !bytes.Contains(oneBytes, []byte("revision: \"1\"\n")) {
		t.Fatalf("the canonical bytes do not keep the revision:\n%s", oneBytes)
	}
	// The canonical bytes load back to the same contract and hash (R13's round trip).
	if again, _ := hash(string(oneBytes)); again != one {
		t.Fatal("the canonical bytes of a contract with a revision do not hash as the contract")
	}
}

// TestNamesAreYAMLStrings is the same agreement for the contract's other identifier keys agent.schema.json types as
// strings: an unquoted all-digit name or mcp server name is an integer to YAML and to a JSON Schema validator, so Go
// refuses it with the fix to quote it, and the quoted spelling loads.
func TestNamesAreYAMLStrings(t *testing.T) {
	for _, tc := range []struct {
		doc  string
		ok   bool
		line int
	}{
		{"version: 0\nname: 123\ncommand: [x]\n", false, 2},
		{"version: 0\nname: \"123\"\ncommand: [x]\n", true, 0},
		{"version: 0\nname: a\ncommand: [x]\nmcp:\n  - name: 7\n    command: [srv]\n", false, 5},
		{"version: 0\nname: a\ncommand: [x]\nmcp:\n  - name: \"7\"\n    command: [srv]\n", true, 0},
	} {
		_, ds, err := LoadBytes("a.yaml", []byte(tc.doc), nil)
		if tc.ok {
			if err != nil {
				t.Errorf("%q: %v\n%s", tc.doc, err, render(ds))
			}
			continue
		}
		if err == nil || len(ds) == 0 || ds[0].Code != CodeSchema || ds[0].Line != tc.line ||
			!strings.Contains(ds[0].Fix, "quote it") {
			t.Errorf("%q loaded (%v) with %s, want a [schema] error at line %d with the fix to quote it", tc.doc, err,
				render(ds), tc.line)
		}
	}
}
