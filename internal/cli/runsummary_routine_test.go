// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestWatchFooterNeverNamesARoutineSocket: the first tego watch of a Python fetch on AlmaLinux 9.8 said "seen: 16
// connections to 10 places (most: unspec)" (guest kit/acc2): glibc's connect(AF_UNSPEC) resets and its netlink socket
// were places, and the most used one. They name no place, so the footer's counts and "most:" are the network's alone,
// as the receipt's (receipt.RoutineSockets) and the dashboard's are; a vsock (family 40) is still a place.
func TestWatchFooterNeverNamesARoutineSocket(t *testing.T) {
	root, anchor := summaryHarness(t)
	var host [32]byte
	rid, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := string(rid)
	w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: "watch"}, ledger.WithAnchor(ledger.NewFileChainAnchor(anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"python3", "fetch.py"}, Cwd: "/w/proj", Tier: "observe",
		Capture: "off", Capabilities: map[string]bool{string(backend.CapRecordExecOpenNet): true, string(backend.CapRecordReads): true}}); err != nil {
		t.Fatal(err)
	}
	conn := func(dst, rule string, verdict record.Verdict, n int) {
		for range n {
			e := &record.Event{Kind: record.KindNet, Source: record.SourceSupervisor, PID: 1, TID: 1, Verdict: verdict,
				Rule: rule, Attr: record.Unattributed(), Authority: record.AuthorityRule}
			if err := e.SetPayload(record.NetPayload{Proto: "udp", Dst: dst}); err != nil {
				t.Fatal(err)
			}
			if err := w.Append(e); err != nil {
				t.Fatal(err)
			}
		}
	}
	conn("unspec", "net.unspec", record.VerdictObserved, 6)
	conn("family(16)", "route-query", record.VerdictAllow, 1)
	conn("151.101.0.223:443", "unmatched", record.VerdictObserved, 3)
	conn("family(40)", "unmatched", record.VerdictObserved, 1)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	prevRoot := ledgerRootOf
	t.Cleanup(func() { ledgerRootOf = prevRoot })
	ledgerRootOf = func(*config.Machine) (string, error) { return root, nil }
	res := tegoruntime.Result{RunID: id, Reason: record.RunEndExit}
	sum := summarizeRun(t.Context(), &config.Machine{}, anchor, res, agent.RecordFull)
	got := watchFooter(res, sum)
	if want := "\n  seen: 4 connections to 2 places (most: 151.101.0.223:443) · no sensitive file read\n"; !strings.Contains(got, want) {
		t.Errorf("footer lacks %q:\n%s", want, got)
	}
	code, out, _ := run(t, "receipt", id)
	if code != identity.ExitOK {
		t.Fatalf("receipt exit %d", code)
	}
	for _, want := range []string{"\nConnections\n  4 connections to 2 places.\n", "    family(40)  1  recorded, not blocked\n",
		"  Also 7 routine socket calls that name no place (disconnects with AF_UNSPEC, the kernel's netlink socket), not counted above.\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("receipt lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(got+out, "unspec  ") || strings.Contains(got+out, "family(16)") || strings.Contains(got, "most: unspec") {
		t.Errorf("the footer or the receipt names a routine socket as a place:\n%s\n%s", got, out)
	}
}
