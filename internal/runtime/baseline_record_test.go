// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestRunStartRecordsBaselineAndEffectiveCopy(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(path, []byte("baseline: {env: {deny: [TOKEN]}}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m, _, err := config.LoadSources(config.Sources{User: path}, home, os.Getuid(), config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	m.LedgerRoot.Value = filepath.Join(home, "runs")
	c, _, err := agent.LoadBytes(filepath.Join(home, "agent.yaml"), []byte("version: 0\nname: recorded\ncommand: [/bin/true]\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	rt, ds, err := agent.Compile(c, m, agent.WithHome(home), agent.WithOwnBinaries(""), agent.WithMountInfo(""), agent.WithObserve(), agent.Offline())
	if err != nil {
		t.Fatalf("%v %v", err, ds)
	}
	r := newTestRunner(Deps{Config: m, Enforce: tierBackend{tier: backend.TierObserve}})
	r.rt = rt
	r.deps.Config = m
	r.deps.Enforce = tierBackend{tier: backend.TierObserve}
	dir := filepath.Join(home, "run")
	w, err := ledger.Open(dir, record.RunRef{ID: "r-00000000-000000000000a-extra0", Agent: "recorded"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	r.writer = w
	t.Cleanup(func() { _ = w.Abandon() })
	if err := r.writeRunStart(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	e, err := record.Decode(bytes.TrimSpace(data))
	if err != nil {
		t.Fatal(err)
	}
	var p record.RunStartPayload
	if err := e.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.RecordMinor != record.MinorEveryLaunch || p.Baseline == nil || p.Baseline.Mode != "not-applied" {
		t.Fatalf("missing baseline record: %+v", p)
	}
	effective, err := os.ReadFile(filepath.Join(dir, "effective.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(effective, p.Baseline.EffectiveContract) || p.ContractHash != p.EffectiveHash {
		t.Fatal("record-only effective bytes/hash differ")
	}
	if _, err := agent.ReplayRecordedBaseline(c, p); err != nil {
		t.Fatal(err)
	}
}
