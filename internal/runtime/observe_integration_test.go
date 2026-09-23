// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationObserveRecordsWithoutRefusing end to end: `tego run --observe` used to install
// no seccomp filter, so no supervisor ran and the ledger held run_start, run_end and nothing the agent did.
// The agent here does three things its contract does not allow — execs a binary no entry grants, writes
// outside every write entry, and connects to a destination no net entry names — and each of them must both
// happen and be recorded, verdict observed, rule the entry that matched (none), no reason.
func TestIntegrationObserveRecordsWithoutRefusing(t *testing.T) {
	for _, bin := range []string{"/bin/sh", "/bin/echo", "/bin/bash"} {
		if _, err := os.Stat(bin); err != nil {
			t.Skipf("%s is not available: %v", bin, err)
		}
	}
	f := newFixture(t, contractFor("iobserve", []string{"/bin/sh"}, []string{"/bin/sh"}))
	f.backend = enforce.Observe()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
		accepted <- struct{}{}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	// Outside every write entry, but writable by the agent's own uid: the one thing between the write and
	// the file must be the contract, which an observe run records and does not enforce. Under sudo the
	// agent is dropped to the invoking user, so the directory and the script are handed to that user.
	outsideDir := t.TempDir()
	agentReaches(t, outsideDir)
	agentOwns(t, outsideDir)
	outside := filepath.Join(outsideDir, "outside.txt")
	script := filepath.Join(f.dir, "observe.sh")
	body := fmt.Sprintf(`#!/bin/sh
/bin/echo exec-ok || exit 10
echo written > %q || exit 11
/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/%d' || exit 12
exit 0
`, outside, port)
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script)
	res, err := Run(context.Background(), f.rt, []string{"/bin/sh", script}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit %d (reason %s): an observe run refused something its agent did", res.ExitCode, res.Reason)
	}
	if b, err := os.ReadFile(outside); err != nil || strings.TrimSpace(string(b)) != "written" {
		t.Errorf("the write outside the contract did not land: %q, %v", b, err)
	}
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Errorf("the undeclared connect never reached the listener")
	}

	evs := events(t, runDirs(t, f.root)[0])
	var start record.RunStartPayload
	if err := evs[0].DecodePayload(&start); err != nil || start.Tier != string(backend.TierObserve) {
		t.Fatalf("run_start tier %q (%v), want observe", start.Tier, err)
	}
	var sawExec, sawFS, sawNet bool
	for _, e := range evs {
		if e.Kind == record.KindRefused {
			t.Errorf("an observe run wrote a refused event: %+v", e)
		}
		switch e.Kind {
		case record.KindExec, record.KindFS, record.KindNet:
		default:
			continue
		}
		if e.Verdict != record.VerdictObserved || e.Reason != "" {
			t.Errorf("%s %s rule %q reason %q, want every action observed with no reason (R30)",
				e.Kind, e.Verdict, e.Rule, e.Reason)
		}
		switch e.Kind {
		case record.KindExec:
			var p record.ExecPayload
			if err := e.DecodePayload(&p); err == nil && p.Path == "/bin/echo" {
				sawExec = true
				if e.Rule != "unmatched" {
					t.Errorf("undeclared exec rule %q, want unmatched", e.Rule)
				}
			}
		case record.KindFS:
			var p record.FSPayload
			if err := e.DecodePayload(&p); err == nil && p.Path == outside {
				sawFS = true
			}
		case record.KindNet:
			var p record.NetPayload
			if err := e.DecodePayload(&p); err == nil && p.Dst == fmt.Sprintf("127.0.0.1:%d", port) {
				sawNet = true
				if e.Rule != "unmatched" {
					t.Errorf("undeclared connect rule %q, want unmatched", e.Rule)
				}
			}
		}
	}
	if !sawExec || !sawFS || !sawNet {
		t.Fatalf("the ledger lacks an observed action: exec %v fs %v net %v; kinds %v", sawExec, sawFS, sawNet, kinds(evs))
	}
}
