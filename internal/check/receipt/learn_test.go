// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestReceiptExplainsLearnWithholding(t *testing.T) {
	var p record.RunStartPayload
	if err := json.Unmarshal([]byte(`{"tier":"landlock","record_minor":31,"contract_source":{"path":"/edited.yaml","learn":{"run":"r-12345678-0aaaaaaaaaaaa-abcdef","withheld":["tcp://203.0.113.9:443"]}}}`), &p); err != nil {
		t.Fatal(err)
	}
	ls := []line{{kind: record.KindRunStart, payload: p}, {kind: record.KindNet, verdict: record.VerdictRefused, rule: "unmatched", reason: "net-not-allowed", payload: record.NetPayload{Op: "connect", Proto: "tcp", Dst: "203.0.113.9:443"}}}
	rc := compute(t, ls, Options{})
	var b bytes.Buffer
	if err := rc.Text(&b); err != nil {
		t.Fatal(err)
	}
	const want = "This run's contract says tego learn withheld this destination"
	if !strings.Contains(b.String(), want) || !strings.Contains(b.String(), "tego rule r-3f9c2a1b-0dllq06ts7400-k7m2pq 1 --allow") {
		t.Fatalf("no bounded explanation or command: %s", b.String())
	}
	var js bytes.Buffer
	if err := rc.JSON(&js); err != nil || !strings.Contains(js.String(), `"learn_withheld_run"`) {
		t.Fatalf("JSON lost the history beside its refusal: %v %s", err, js.String())
	}
	if rc.Refusals.Total != 1 {
		t.Fatalf("history changed the count: %+v", rc.Refusals)
	}
	ls[1].payload = record.NetPayload{Op: "connect", Proto: "tcp", Dst: "[::ffff:203.0.113.9]:443"}
	mapped := compute(t, ls, Options{})
	b.Reset()
	if err := mapped.Text(&b); err != nil || !strings.Contains(b.String(), want) {
		t.Fatalf("equivalent mapped address lost its history: %v %s", err, b.String())
	}
	for _, tc := range []struct{ name, proto, dst, rule, reason string }{
		{"other destination", "tcp", "203.0.113.10:443", "unmatched", "net-not-allowed"},
		{"other protocol", "udp", "203.0.113.9:443", "unmatched", "net-not-allowed"},
		{"other reason", "tcp", "203.0.113.9:443", "unmatched", "read-denied"},
		{"live block", "tcp", "203.0.113.9:443", "live.block[net:203.0.113.9:443]", "net-not-allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ls[1].rule, ls[1].reason = tc.rule, record.Reason(tc.reason)
			ls[1].payload = record.NetPayload{Op: "connect", Proto: tc.proto, Dst: tc.dst}
			other := compute(t, ls, Options{})
			b.Reset()
			if err := other.Text(&b); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(b.String(), want) {
				t.Fatalf("claimed withholding explains %s: %s", tc.name, b.String())
			}
		})
	}
}

func TestLearnWithholdingRequiresConnect(t *testing.T) {
	start := record.RunStartPayload{RecordMinor: record.MinorLearn, ContractSource: &record.ContractSource{
		Path: "/agent.yaml", Learn: &record.LearnNote{Run: "r-12345678-0aaaaaaaaaaaa-abcdef",
			Withheld: []string{"tcp://203.0.113.9:443", "udp://203.0.113.9:443"}},
	}}
	for _, proto := range []string{"tcp", "udp"} {
		for _, op := range []string{"connect", "", "bind", "listen", "accept", "sendmsg"} {
			t.Run(proto+"/"+op, func(t *testing.T) {
				rc := compute(t, []line{{kind: record.KindRunStart, payload: start}, {
					kind: record.KindNet, verdict: record.VerdictRefused, rule: "unmatched", reason: "net-not-allowed",
					payload: record.NetPayload{Op: op, Proto: proto, Dst: "203.0.113.9:443"},
				}}, Options{})
				if rc.Refusals.Total != 1 || len(rc.Refusals.List) != 1 {
					t.Fatalf("operation changed refusal count: %+v", rc.Refusals)
				}
				r := rc.Refusals.List[0]
				want := op == "connect" || op == ""
				if got := r.LearnWithheldRun != ""; got != want {
					t.Errorf("history on %s: %t, want %t", op, got, want)
				}
				var out bytes.Buffer
				if err := rc.Text(&out); err != nil {
					t.Fatal(err)
				}
				if got := strings.Contains(out.String(), "This run's contract says tego learn withheld"); got != want {
					t.Errorf("sentence on %s: %t, want %t: %s", op, got, want, out.String())
				}
				if !want && (rc.LearnWords(r) != "" || strings.Contains(out.String(), " --allow")) {
					t.Fatalf("offered a connect allowance for %s: %s", op, out.String())
				}
			})
		}
	}
}
