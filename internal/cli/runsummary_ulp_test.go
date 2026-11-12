// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRefusedClauseNamesTheKernelTLSRefusalBuiltIn: on Ubuntu 24.04 every enforced HTTPS run of Python ended "refused 1
// (not allowed by any rule 1)" (guest kit/acc2): OpenSSL's setsockopt(TCP_ULP, "tls"), which tego refuses under every
// net: section and no rule can allow, so a newcomer looked for a rule to add. The count stays the record's; the clause
// names the refusal built in, from the supervisor's line and the root tiers' (mechanism cgroup) alike, and a
// default-deny connect keeps its words.
func TestRefusedClauseNamesTheKernelTLSRefusalBuiltIn(t *testing.T) {
	base := t.TempDir()
	var host [32]byte
	rid, err := identity.NewRunID(host, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := string(rid)
	dir := filepath.Join(base, id)
	w, err := ledger.Open(dir, record.RunRef{ID: id, Agent: "svc"}, ledger.WithAnchor(ledger.NewFileChainAnchor(filepath.Join(base, "chain.log"))))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"python3", "fetch.py"}, Cwd: "/w/proj", Tier: "landlock", Capture: "off"}); err != nil {
		t.Fatal(err)
	}
	refuse := func(op, target, mech string) {
		e := &record.Event{Kind: record.KindRefused, Source: record.SourceSupervisor, PID: 1, TID: 1, Rule: "unmatched",
			Reason: record.ReasonNetNotAllowed}
		if err := e.SetPayload(record.RefusedPayload{Op: op, Target: target, Reason: record.ReasonNetNotAllowed, Rule: "unmatched",
			Mechanism: mech}); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	refuse("setsockopt", `TCP_ULP "tls"`, "")
	refuse("net", "203.0.113.9:443", "")
	refuse("net", "203.0.113.10:443", "")
	refuse("setsockopt", `TCP_ULP "tls"`, record.MechanismCgroup)
	refuse("setsockopt", `TCP_ULP "tls"`, "")
	refuse("setsockopt", `TCP_ULP "smc"`, "")
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	rc, err := receiptOf(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if rc.Refusals.Total != 6 {
		t.Errorf("total %d, want 6: the built-in refusals still count", rc.Refusals.Total)
	}
	if got, want := refusedClause(rc), "refused 6 (built in: kernel TLS 3, not allowed by any rule 2, built in: TCP upper-layer protocol 1)"; got != want {
		t.Errorf("refusedClause = %q, want %q", got, want)
	}
}
