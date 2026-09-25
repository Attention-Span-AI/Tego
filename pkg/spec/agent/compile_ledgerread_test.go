// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestTegosOwnFilesAreReadDenied: R10 kept the agent from writing tego's own files and nothing kept it
// from reading them, so any run could read every run's events.jsonl and blobs (argv, headers, under
// record: full model bodies), chain.log and tego.log. The denies hold
// whatever deny_read says, `deny_read: []` included, in every enforcing tier.
func TestTegosOwnFilesAreReadDenied(t *testing.T) {
	f := newFixture(t)
	other := filepath.Join(f.ledger, "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(other, "events.jsonl"), "{}\n", 0o600)
	f.file(filepath.Join(f.home, ".tego", "chain.log"), "", 0o600)
	for _, fsSection := range []string{"", "fs:\n  write: [\"./out/\"]\n", "fs:\n  write: [\"./out/\"]\n  deny_read: []\n"} {
		c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\n" + fsSection)
		rt, _ := f.compile(c)
		for _, p := range []string{filepath.Join(other, "events.jsonl"), filepath.Join(f.home, ".tego", "chain.log")} {
			for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
				got := rt.Evaluate(Action{Kind: ActionFSRead, Path: p}, tier)
				if got.Verdict != VerdictRefused {
					t.Errorf("%q, tier %s: reading %s = %+v, want refused", fsSection, tier, p, got)
				}
			}
		}
		for _, r := range rt.FS {
			if r.Kind == FSDenyRead && r.Unenforced && r.Path == filepath.Join(f.home, ".tego") {
				t.Errorf("%q: the deny on ~/.tego is unenforced", fsSection)
			}
		}
	}
}

// TestTheHomesTegoIsReadDeniedWhenTheAnchorIsElsewhere: R6a for a table compiled against a home whose ~/.tego does
// not hold the chain anchor: an adoption compiles against the agent owner's home while the ledger and the anchor are
// the adopter's (ADR 0055 Decision 5). The owner's own records in its ~/.tego (its earlier runs' events and blobs)
// stay read-denied, as its own launched run denies them, beside the adopter's anchor directory and ledger root.
func TestTheHomesTegoIsReadDeniedWhenTheAnchorIsElsewhere(t *testing.T) {
	f := newFixture(t)
	adopter := filepath.Join(f.root, "root", ".tego")
	m := *f.machine
	m.LedgerRoot.Value = filepath.Join(adopter, "runs")
	if err := os.MkdirAll(m.LedgerRoot.Value, 0o700); err != nil {
		t.Fatal(err)
	}
	anchor := filepath.Join(adopter, "chain.log")
	f.file(anchor, "", 0o600)
	ownerRun := filepath.Join(f.home, ".tego", "runs", "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	if err := os.MkdirAll(ownerRun, 0o700); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(ownerRun, "events.jsonl"), "{}\n", 0o600)
	for _, fsSection := range []string{"", "fs:\n  write: [\"./out/\"]\n  deny_read: []\n"} {
		c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\n" + fsSection)
		rt, ds, err := Compile(c, &m, f.opts(WithChainAnchor(anchor))...)
		if err != nil {
			t.Fatalf("%q: %v\n%s", fsSection, err, render(ds))
		}
		for _, p := range []string{filepath.Join(ownerRun, "events.jsonl"), anchor, filepath.Join(m.LedgerRoot.Value, "x")} {
			for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
				if got := rt.Evaluate(Action{Kind: ActionFSRead, Path: p}, tier); got.Verdict != VerdictRefused {
					t.Errorf("%q, tier %s: reading %s = %+v, want refused", fsSection, tier, p, got)
				}
			}
		}
	}
	// A write entry at or inside the owner's ~/.tego would drop that deny (a directory a write entry needs is not
	// denied) and give the agent those records to read and write, where the owner's own launched run refuses the
	// entry for its anchor directory: it is a contradiction here too, named. One above
	// it, the home, keeps the deny nested, as the home is an ordinary write entry when the anchor is elsewhere.
	ownerTego := filepath.Join(f.home, ".tego")
	for _, entry := range []string{ownerTego, filepath.Join(ownerTego, "x"), filepath.Join(ownerTego, "runs")} {
		c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"" + entry + "\"]\n")
		_, ds, err := Compile(c, &m, f.opts(WithChainAnchor(anchor))...)
		if !errors.Is(err, ErrContractOverlap) || !hasCode(ds, CodeContradiction) ||
			!strings.Contains(render(ds), "the agent owner's tego directory "+ownerTego) {
			t.Errorf("fs.write [%s] with the anchor elsewhere: err = %v, want a contradiction naming %s\n%s", entry, err,
				ownerTego, render(ds))
		}
	}
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"~\"]\n")
	rt, ds, err := Compile(c, &m, f.opts(WithChainAnchor(anchor))...)
	if err != nil {
		t.Fatalf("fs.write [~] with the anchor elsewhere: %v\n%s", err, render(ds))
	}
	for _, kind := range []ActionKind{ActionFSRead, ActionFSWrite} {
		if got := rt.Evaluate(Action{Kind: kind, Path: filepath.Join(ownerRun, "events.jsonl")}, backend.TierCgroup); got.Verdict != VerdictRefused {
			t.Errorf("fs.write [~]: %s of the owner's records at tier cgroup = %+v, want refused", kind, got)
		}
	}
	// Nor can the agent replace the directory the deny is on, so that the owner's next run writes into a new one no
	// deny covers (ADR 0055 Decision 5: an adoption keeps its table while it runs): removing ~/.tego and renaming it
	// away are refused, though the home around it is writable.
	for _, act := range []Action{
		{Kind: ActionFSDelete, Path: ownerTego, Dir: true},
		{Kind: ActionFSRename, Path: ownerTego, DestPath: ownerTego + ".old", Dir: true},
	} {
		if got := rt.Evaluate(act, backend.TierCgroup); got.Verdict != VerdictRefused {
			t.Errorf("fs.write [~]: %s of the owner's ~/.tego at tier cgroup = %+v, want refused", act.Kind, got)
		}
	}
	if got := rt.Evaluate(Action{Kind: ActionFSWrite, Path: filepath.Join(f.home, "notes")}, backend.TierCgroup); got.Verdict != VerdictAllow {
		t.Errorf("fs.write [~]: a write in the home at tier cgroup = %+v, want allowed", got)
	}
}

// TestASharedLedgerRootIsNotDeniedButSaysSo: a ledger root that also holds the project (a data disk, /tmp)
// cannot be read-denied without denying the agent its own files; compile says the ledger stays readable.
func TestASharedLedgerRootIsNotDeniedButSaysSo(t *testing.T) {
	f := newFixture(t)
	f.machine = machineWith(f.root, 8, 32<<30, 4096, 10_000_000, 200, 0, 0, 20) // the root holds the project
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet: {}\nfs:\n  write: [\"./out/\"]\n")
	rt, ds := f.compile(c)
	if !hasCode(ds, CodeLedgerReadable) {
		t.Errorf("no ledger-readable warning: %v", codes(ds))
	}
	if got := rt.Evaluate(Action{Kind: ActionFSRead, Path: filepath.Join(f.project, "config")}, backend.TierLandlock); got.Verdict != VerdictAllow {
		t.Errorf("the project became unreadable: %+v", got)
	}
}
