// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRunSummarySaysASameFileRefusal: a live block on /bin/ls refused /bin/sleep, another name of the same program file
// on a multi-call host, and the summary's "refused N (live.block N)" named only the block's rule, so a person read it as
// a block on the wrong program. The summary now says, under its line, which program was refused and why, read from
// each refused line's rule and path (liveblock.SameFileNote); a refusal of /bin/ls itself says nothing more.
func TestRunSummarySaysASameFileRefusal(t *testing.T) {
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
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"sh", "rules.sh"}, Cwd: "/w/proj", Tier: "landlock", Capture: "off"}); err != nil {
		t.Fatal(err)
	}
	refuse := func(path string) {
		e := &record.Event{Kind: record.KindExec, Source: record.SourceSupervisor, PID: 1, TID: 1, Rule: "live.block[exec:/bin/ls]",
			Verdict: record.VerdictRefused, Reason: record.ReasonExecNotAllowed, Authority: record.AuthorityRule, Attr: record.Unattributed()}
		if err := e.SetPayload(record.ExecPayload{Path: path, Argv: []string{path}, ExecID: "x"}); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	refuse("/bin/ls")
	refuse("/bin/sleep")
	refuse("/bin/sleep")
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	rc, err := receiptOf(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	s := &endSummary{run: id, rc: rc, chain: "chain verified"}
	text := s.text()
	if !strings.Contains(text, " · refused 3 (live.block 3) · ") {
		t.Errorf("the summary line changed:\n%s", text)
	}
	if want := "\n  /bin/sleep: refused, same program file as /bin/ls, which is blocked (2 times)\n  more: tego receipt "; !strings.Contains(text, want) {
		t.Errorf("summary:\n%s\nwant it to hold %q", text, want)
	}
	if strings.Contains(text, "/bin/ls: refused") {
		t.Errorf("the refusal of /bin/ls itself is said as a same-file one:\n%s", text)
	}
}
