// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestBaselineEmptyReplayRetainsSource(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: empty-replay\ncommand: [python]\nhost_sockets: true\n")
	effective, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	m := baselineMachine(t, f, "  exec: {deny: [python]}\n")
	for _, applied := range []bool{false, true} {
		t.Run(map[bool]string{false: "not applied", true: "applied"}[applied], func(t *testing.T) {
			snapshot := &BaselineTable{Applied: applied, Owner: config.BaselineOwner{UID: os.Getuid(), Home: f.home}}
			replay, err := VerifyBaselineReplay(c, snapshot, hash, hash, effective)
			if err != nil {
				t.Fatal(err)
			}
			rt, ds, err := replay.Compile(c, m, f.opts()...)
			if err != nil {
				t.Fatalf("empty recorded baseline borrowed current refusals: %v %s", err, render(ds))
			}
			got, err := rt.EffectiveContract.Canonical()
			if err != nil || !bytes.Equal(got, effective) || rt.Hash != hash || rt.EffectiveHash != hash || rt.Baseline.Applied != applied || len(rt.Baseline.Entries) != 0 {
				t.Fatalf("empty recorded baseline changed source: %v", err)
			}
		})
	}
}

func TestBaselineMaterializerDetachesChangedFields(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: detached\ncommand: [python]\nfs: {deny_read: [/contract/read], deny_write: [/contract/write]}\nexec: {deny: ['git status']}\nenv: {deny: [CONTRACT_TOKEN]}\n")
	before, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	table := &BaselineTable{Applied: true}
	for _, entry := range []struct {
		key   config.BaselineKey
		value string
	}{{config.BaselineDenyRead, "/machine/read"}, {config.BaselineDenyWrite, "/machine/write"}, {config.BaselineDenyExec, "git push"}, {config.BaselineDenyEnv, "MACHINE_TOKEN"}} {
		table.Entries = append(table.Entries, BaselineRule{ResolvedBaselineEntry: config.ResolvedBaselineEntry{BaselineEntry: config.BaselineEntry{Key: entry.key, Value: entry.value, Sources: []config.Provenance{{File: "machine.yaml", Line: 2, Layer: config.LayerEtc}}}, Expanded: entry.value}})
	}
	cp, err := prependBaseline(c, table)
	if err != nil {
		t.Fatal(err)
	}
	// These are precisely the fields insertion changes. Mutating the resulting
	// copy must not write through its section pointers or origin map to source.
	cp.FS.DenyRead[0], cp.FS.DenyWrite[0] = "/changed/read", "/changed/write"
	cp.Exec.Deny[0], cp.Env.Deny[0] = "git commit", "CHANGED_TOKEN"
	cp.origins["command.0"] = Pos{File: "changed.yaml", Line: 99}
	after, err := c.Canonical()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("effective copy changed source canonical bytes: %v", err)
	}
	if got := c.origins["command.0"].File; got == "changed.yaml" {
		t.Fatal("effective copy changed source origins")
	}
}

func TestBaselineReplaySnapshotDetachedAndSourceBound(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: sealed-replay\ncommand: [python]\n")
	m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n")
	rt, ds, err := Compile(c, m, f.opts()...)
	if err != nil {
		t.Fatalf("%v %s", err, render(ds))
	}
	if len(rt.Baseline.Entries) != 1 || len(rt.Baseline.Entries[0].Rules) != 1 {
		t.Fatal("compiled baseline lost its exact contributed command rule")
	}
	recordedSource := rt.Baseline.Entries[0].Sources[0].File
	recordedRule := rt.Baseline.Entries[0].Rules[0]
	effective, err := rt.EffectiveContract.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"entry", "source", "rule", "coverage", "operation", "condition", "limit"} {
		t.Run(field, func(t *testing.T) {
			snapshot := cloneBaseline(rt.Baseline)
			snapshot.Entries[0].Coverage = []BaselineCoverage{{Plane: "recorded", Operations: []string{"exec"}, Conditions: []string{"pinned"}, Limits: []string{"finite"}}}
			replay, err := VerifyBaselineReplay(c, snapshot, rt.Hash, rt.EffectiveHash, effective)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "entry":
				snapshot.Entries[0].Expanded = "git commit"
			case "source":
				snapshot.Entries[0].Sources[0].File = "changed.yaml"
			case "rule":
				snapshot.Entries[0].Rules[0] = "changed rule"
			case "coverage":
				snapshot.Entries[0].Coverage[0].Plane = "changed"
			case "operation":
				snapshot.Entries[0].Coverage[0].Operations[0] = "changed"
			case "condition":
				snapshot.Entries[0].Coverage[0].Conditions[0] = "changed"
			case "limit":
				snapshot.Entries[0].Coverage[0].Limits[0] = "changed"
			}
			got, ds, err := replay.Compile(c, f.machine, f.opts(WithHome(filepath.Join(f.root, "current-home")))...)
			if err != nil {
				t.Fatalf("caller snapshot mutation changed verified replay: %v %s", err, render(ds))
			}
			e := got.Baseline.Entries[0]
			coverage := e.Coverage[0]
			if e.Expanded != "git push" || e.Sources[0].File != recordedSource || e.Rules[0] != recordedRule || coverage.Plane != "recorded" || coverage.Operations[0] != "exec" || coverage.Conditions[0] != "pinned" || coverage.Limits[0] != "finite" {
				t.Fatalf("caller snapshot mutation leaked into replay: %+v %+v", e, coverage)
			}
		})
	}
	replay, err := VerifyBaselineReplay(c, rt.Baseline, rt.Hash, rt.EffectiveHash, effective)
	if err != nil {
		t.Fatal(err)
	}
	other := f.load("version: 0\nname: different-source\ncommand: [python]\n")
	if _, _, err := replay.Compile(other, f.machine, f.opts()...); err == nil {
		t.Fatal("verified replay authorized a different source contract")
	}
	if _, err := VerifyBaselineReplay(other, rt.Baseline, rt.Hash, rt.EffectiveHash, effective); err == nil {
		t.Fatal("source bytes were not checked against recorded contract hash")
	}
	badContractHash := rt.Hash
	badContractHash[0] ^= 1
	if _, err := VerifyBaselineReplay(c, rt.Baseline, badContractHash, rt.EffectiveHash, effective); err == nil {
		t.Fatal("incorrect recorded contract hash verified")
	}
}
