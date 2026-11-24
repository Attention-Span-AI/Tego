// SPDX-License-Identifier: Apache-2.0

package runstart

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func contractsStart(t *testing.T, root, id string) string {
	t.Helper()
	f, err := os.Open("../../../spec/record/v1/fixtures/run-fixture.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := bufio.NewReader(f).ReadBytes('\n')
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	event, err := record.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	var start record.RunStartPayload
	if err := event.DecodePayload(&start); err != nil {
		t.Fatal(err)
	}
	start.ContractSource = &record.ContractSource{Path: "/project/agent.yaml"}
	uid := uint32(os.Getuid())
	start.LauncherUID = &uid
	dir := filepath.Join(root, id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "retriever"}, ledger.WithAnchor(ledger.NewFileChainAnchor(filepath.Join(root, "..", "chain.log"))))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestContractsLoadStartsReadsOnlyMetadata(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	id := "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	dir := contractsStart(t, root, id)
	// Malformed action history must not be read by metadata discovery.
	f, err := os.OpenFile(filepath.Join(dir, ledger.EventsFile), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(strings.Repeat("x", ledger.MaxLineBytes+1) + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	s, problems := Load(context.Background(), root)
	if len(problems) != 0 || len(s.Runs) != 1 {
		t.Fatalf("snapshot %+v problems %v", s, problems)
	}
	r := s.Runs[0]
	if r.Contract != "/project/agent.yaml" || r.Tier != "landlock" || r.ContractHash == "" || r.Cwd != "/home/u/proj" || r.UID != os.Getuid() {
		t.Fatalf("metadata %+v", r)
	}
}

func TestContractsLoadStartsReportsUnreadableRecords(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	good := "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	bad := "r-3f9c2a1b-0dllq06ts7400-k7m2pr"
	dir := contractsStart(t, root, good)
	badDir := filepath.Join(root, bad)
	if err := os.Mkdir(badDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, ledger.EventsFile), filepath.Join(badDir, ledger.EventsFile)); err != nil {
		t.Fatal(err)
	}
	s, problems := Load(context.Background(), root)
	if len(s.Runs) != 1 || len(problems) == 0 {
		t.Fatalf("symlink hidden: snapshot %+v problems %v", s, problems)
	}
	if err := os.Remove(filepath.Join(badDir, ledger.EventsFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badDir, ledger.EventsFile), []byte("{not-json}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, problems = Load(context.Background(), root)
	if len(s.Runs) != 1 || len(problems) == 0 {
		t.Fatalf("bad header hidden: snapshot %+v problems %v", s, problems)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, problems = Load(ctx, root)
	if len(problems) == 0 {
		t.Fatal("cancelled discovery succeeded")
	}
	s, _ = load(context.Background(), root, 1, 32<<20)
	if !s.RunsCut {
		t.Fatal("bound was not disclosed")
	}
}

func TestContractsLoadStartsBoundsMetadata(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	contractsStart(t, root, "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
	snapshot, problems := load(context.Background(), root, 100_000, 1)
	if !snapshot.RunsCut || len(snapshot.Runs) != 0 || len(problems) == 0 {
		t.Fatalf("metadata limit hidden: %+v %v", snapshot, problems)
	}
}

func TestProjectPreservesOwnerKnowledge(t *testing.T) {
	for _, tt := range []struct {
		name, payload string
		uid           int
		known         bool
	}{
		{"missing", `{}`, 0, false},
		{"root", `{"launcher_uid":0}`, 0, true},
		{"user", `{"launcher_uid":1001}`, 1001, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Project([]byte(tt.payload))
			if err != nil || r.UID != tt.uid || r.UIDKnown != tt.known {
				t.Fatalf("owner knowledge lost: %+v, %v", r, err)
			}
		})
	}
}

func TestBaselineProjectRequiresValidEvidence(t *testing.T) {
	data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	event, err := record.Decode([]byte(strings.SplitN(string(data), "\n", 2)[0]))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Project(event.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.EffectiveHash == "" || got.BaselineSHA256 == "" {
		t.Fatalf("lost baseline metadata: %+v", got)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	delete(payload, "baseline")
	data, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Project(data); err == nil || !strings.Contains(err.Error(), "baseline") {
		t.Fatalf("missing baseline accepted: %v", err)
	}
}
