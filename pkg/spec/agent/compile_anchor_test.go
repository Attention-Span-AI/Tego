// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteEntryContainingTheChainAnchor is R10 for the chain anchor. Every run's head is checked
// against chain.log, so an agent that can rewrite it can make a truncated or swapped ledger verify.
// The anchor used to sit beside the ledger root, where any entry covering it covered the ledger root
// too; since it moved to ~/.tego, a ledger_root anywhere else let `fs.write: ["~"]` compile and hand
// the agent chain.log.
func TestWriteEntryContainingTheChainAnchor(t *testing.T) {
	f := newFixture(t)
	m := *f.machine
	m.LedgerRoot.Value = filepath.Join(f.root, "srv", "runs") // outside the home: the ledger root is not the guard
	anchor := filepath.Join(f.home, ".tego", "chain.log")

	for _, entry := range []string{"~", "~/.tego", "~/.tego/chain.log"} {
		c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"" + entry + "\"]\n")
		if entry == "~/.tego" || entry == "~/.tego/chain.log" {
			if err := os.MkdirAll(filepath.Join(f.home, ".tego"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for name, opts := range map[string][]CompileOption{
			"the default anchor under the home": f.opts(),
			"the anchor the launcher names":     f.opts(WithChainAnchor(anchor)),
		} {
			_, ds, err := Compile(c, &m, opts...)
			if !errors.Is(err, ErrContractOverlap) || !hasCode(ds, CodeContradiction) {
				t.Fatalf("fs.write %q, %s: err = %v, want ErrContractOverlap\n%s", entry, name, err, render(ds))
			}
			if msg := render(ds); !strings.Contains(msg, "the chain anchor "+anchor) {
				t.Errorf("fs.write %q, %s: the diagnostic does not name the anchor:\n%s", entry, name, msg)
			}
		}
	}

	// An anchor the launcher puts elsewhere — beside the ledger root, for an account with no home —
	// is the one R10 guards, and the home is then an ordinary write entry.
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"~\"]\n")
	elsewhere := filepath.Join(f.root, "srv", "chain.log")
	if _, ds, err := Compile(c, &m, f.opts(WithChainAnchor(elsewhere))...); err != nil {
		t.Fatalf("fs.write [~] with the anchor outside the home: %v\n%s", err, render(ds))
	}
	c = f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"" + filepath.Join(f.root, "srv") + "\"]\n")
	if _, ds, err := Compile(c, &m, f.opts(WithChainAnchor(elsewhere))...); !errors.Is(err, ErrContractOverlap) {
		t.Fatalf("an entry containing the anchor beside the ledger root: err = %v\n%s", err, render(ds))
	}
}
