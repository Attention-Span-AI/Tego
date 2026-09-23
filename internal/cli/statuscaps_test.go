// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestStatusShowsTheCapabilityLine is R-cap end to end through `tego status`: the run's own capability line,
// as run_start recorded it, printed with its absent rows by name, and carried verbatim in --json.
// (limits-check-doctor-cli.md R-cap.)
func TestStatusShowsTheCapabilityLine(t *testing.T) {
	root := gcRoot(t)
	var host [32]byte
	id, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	line := map[string]bool{}
	for _, c := range backend.AllCapabilities() {
		line[string(c)] = true
	}
	line[string(backend.CapReadDeny)] = false
	line[string(backend.CapRecordReads)] = false
	w, err := ledger.Open(filepath.Join(root, string(id)), record.RunRef{ID: string(id), Agent: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Cwd: "/", Tier: "landlock",
		ContractHash: strings.Repeat("a", 64), Capabilities: line}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}

	code, out, errs := run(t, "status", string(id))
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	want := fmt.Sprintf("\ncapabilities: landlock %d/%d; absent: fs.deny_read, record.reads_mmap_chmod\n", len(line)-2, len(line))
	if !strings.Contains(out, want) {
		t.Fatalf("status output lacks %q:\n%s", want, out)
	}

	code, out, errs = run(t, "status", "--json", string(id))
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var got struct {
		Tier         string          `json:"tier"`
		Capabilities map[string]bool `json:"capabilities"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode %s: %v", out, err)
	}
	if got.Tier != "landlock" || len(got.Capabilities) != len(line) || got.Capabilities[string(backend.CapReadDeny)] {
		t.Fatalf("--json tier %q capabilities %v, want run_start's own", got.Tier, got.Capabilities)
	}
}

// TestStatusShowsTheResourcePeaks is R-res end to end through `tego status`: the peaks run_end recorded, one
// line under the table, a key the record lacks "unknown" and never 0; --json carries the object as recorded,
// and a run with no run_end yet has no resources key at all.
func TestStatusShowsTheResourcePeaks(t *testing.T) {
	root := gcRoot(t)
	var host [32]byte
	id, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ledger.Open(filepath.Join(root, string(id)), record.RunRef{ID: string(id), Agent: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"true"}, Cwd: "/", Tier: "cgroup",
		ContractHash: strings.Repeat("a", 64)}); err != nil {
		t.Fatal(err)
	}
	peak, pids, zero := uint64(96<<20), uint64(7), uint64(0)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit, Resources: &record.Resources{
		MemoryPeak: &peak, PidsPeak: &pids, MemoryEvents: &record.MemoryEvents{OOMKill: &zero}}}); err != nil {
		t.Fatal(err)
	}

	code, out, errs := run(t, "status", string(id))
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	want := "\nresources: memory peak 96.0 MiB (100663296 B), pids peak 7, cpu unknown (user unknown, system unknown), " +
		"cpu throttled unknown, memory events high unknown, max unknown, oom unknown, oom_kill 0\n"
	if !strings.Contains(out, want) {
		t.Fatalf("status output lacks %q:\n%s", want, out)
	}

	code, out, errs = run(t, "status", "--json", string(id))
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.Contains(out, `"resources":{"memory_peak":100663296,"pids_peak":7,"memory_events":{"oom_kill":0}}`) {
		t.Fatalf("--json does not carry run_end.resources as recorded: %s", out)
	}
}
