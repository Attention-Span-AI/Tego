// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const goodTable = `version: 2
name: t
contract: |
  version: 0
  name: t
  env:
    pass: ["PATH"]
  record: full
model:
  write: [out]
variants: [held]
cells:
  - name: c
    op: read
    path: a
    want:
      landlock: 'allow fs.deny_read[./x/] (unenforced: parent writable)'
      root: {verdict: refused, rule: 'fs.deny_read[./x/]', errno: EACCES}
    source: SEMANTICS §2
deferred:
  - name: later
    why: a later space
`

// TestParseTableIsStrict: a v2 table loads as written, and each way a table can be wrong is refused rather than
// read as some other expectation.
func TestParseTableIsStrict(t *testing.T) {
	fx, variants, deferred, err := parseTable([]byte(goodTable))
	if err != nil {
		t.Fatal(err)
	}
	c := fx.Cells[0]
	if w := c.Want[Key{TierLandlock, ModeNone}]; w.Verdict != Allow || w.Rule != "fs.deny_read[./x/] (unenforced: parent writable)" {
		t.Errorf("landlock %+v: the rule is the rest of the line", w)
	}
	for _, k := range []Key{{TierCgroup, ModeFanotify}, {TierBPFLSM, ModeLSM}} {
		if w := c.Want[k]; w.Verdict != Refused || w.Errno != int(unix.EACCES) || w.Rule != "fs.deny_read[./x/]" {
			t.Errorf("%v %+v: root sets the listener and the plane column", k, w)
		}
	}
	if len(c.Want) != 3 || len(variants) != 1 || len(deferred) != 1 || deferred[0].Name != "t/later" {
		t.Errorf("want %v variants %v deferred %v", c.Want, variants, deferred)
	}
	bad := map[string][2]string{
		"version 1":           {"version: 2", "version: 1"},
		"unknown field":       {"    source:", "    sauce: x\n    source:"},
		"unknown want field":  {"errno: EACCES}", "errno: EACCES, why: x}"},
		"no source":           {"    source: SEMANTICS §2\n", ""},
		"unknown op":          {"op: read", "op: reed"},
		"unknown column":      {"      root:", "      cgroup:"},
		"column set twice":    {"      root:", "      plane: allow\n      root:"},
		"bad verdict":         {"'allow fs.deny", "'allowed fs.deny"},
		"unknown errno":       {"errno: EACCES", "errno: ENOENT"},
		"unknown variant":     {"variants: [held]", "variants: [hold]"},
		"finding without at":  {"    source:", "    finding: x\n    source:"},
		"exception at nobody": {"    source:", "    exception: x\n    exception_at: tier9\n    source:"},
		"deferred is a cell":  {"  - name: later", "  - name: c"},
		"target on a path op": {"    path: a\n", "    path: a\n    target: child\n"},
		"ptrace, no target":   {"op: read\n    path: a\n", "op: ptrace-attach\n"},
		"ptrace with a path":  {"op: read\n", "op: ptrace-attach\n    target: child\n"},
		"traceme of a child":  {"op: read\n    path: a\n", "op: ptrace-traceme\n    target: child\n"},
		"keyring unmodelled":  {"  record: full\n", "  keyring: true\n  record: full\n"},
		"keyring unsaid":      {"  write: [out]\n", "  write: [out]\n  keyring: true\n"},
		"duplicate cell":      {"deferred:", "  - name: c\n    op: read\n    want: {all: allow}\n    source: s\ndeferred:"},
	}
	for name, edit := range bad {
		src := strings.Replace(goodTable, edit[0], edit[1], 1)
		if src == goodTable {
			t.Fatalf("%s: the edit does not apply", name)
		}
		if _, _, _, err := parseTable([]byte(src)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// TestVariantsKeepEveryExpectation: a variant changes how a run is carried out, never what it decides, and its
// cells are its own copies.
func TestVariantsKeepEveryExpectation(t *testing.T) {
	fx, _, _, err := parseTable([]byte(goodTable))
	if err != nil {
		t.Fatal(err)
	}
	h, err := variantOf(fx, "held")
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != "t-held" || !h.Model.HeldOpens || !strings.Contains(h.Contract, "completion: held") || !strings.HasSuffix(h.Contract, footer) {
		t.Errorf("held variant %+v", h)
	}
	h.Cells[0].Want[Key{TierLandlock, ModeNone}] = Want{Verdict: Refused}
	if fx.Cells[0].Want[Key{TierLandlock, ModeNone}].Verdict != Allow {
		t.Error("a variant's cells share their wants with the fixture's")
	}
	if _, err := variantOf(fx, "assurance-kernel"); err == nil {
		t.Error("assurance-kernel took a contract with no fs.write line")
	}
}
