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

// TestRunSummarySaysADevNullRefusal (N14): a run whose first rules file had no fs.write entry for /dev/null was refused
// the device by the default deny; the summary names the cause and the fix under its line. A refusal that an entry of the
// contract made, a refusal of another file and a run with none say nothing of it.
func TestRunSummarySaysADevNullRefusal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rule  string
		path  string
		times int
		want  string
	}{
		{"default deny", "unmatched", "/dev/null", 2, "\n  /dev/null: refused, no fs.write entry covers it (2 times); it holds no file: add /dev/null to fs.write so `> /dev/null` works\n"},
		{"once", "unmatched", "/dev/null", 1, "(1 time);"},
		{"a deny_write of the contract", "fs.deny_write[/dev/null]", "/dev/null", 2, ""},
		{"another file", "unmatched", "/etc/passwd", 2, ""},
		{"none", "unmatched", "/dev/null", 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"sh", "x.sh"}, Cwd: "/w/proj", Tier: "landlock", Capture: "off"}); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < tc.times; i++ {
				e := &record.Event{Kind: record.KindFS, Source: record.SourceSupervisor, PID: 1, TID: 1, Rule: tc.rule,
					Verdict: record.VerdictRefused, Reason: record.ReasonWriteOutsideContract, Authority: record.AuthorityRule, Attr: record.Unattributed()}
				if err := e.SetPayload(record.FSPayload{Op: "open", Path: tc.path, Flags: 1}); err != nil {
					t.Fatal(err)
				}
				if err := w.Append(e); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			rc, err := receiptOf(t.Context(), dir)
			if err != nil {
				t.Fatal(err)
			}
			zero := 0
			rc.Ended, rc.EndReason, rc.ExitCode = true, record.RunEndExit, &zero
			rc.ReadsNotified = &record.ReadsNotified{Notified: true}
			s := &endSummary{run: id, rc: rc, chain: "chain verified"}
			text := s.text()
			if got := strings.Contains(text, "/dev/null: refused"); got != (tc.want != "") || tc.want != "" && !strings.Contains(text, tc.want) {
				t.Errorf("summary:\n%s\nwant it to hold %q (empty: no /dev/null line)", text, tc.want)
			}
		})
	}
}
