// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestRedactHTTPRequestAndCompanionTargets(t *testing.T) {
	for _, tc := range []struct {
		kind    record.Kind
		payload string
	}{
		{record.KindNet, `{"op":"http_request","path":"/v1/messages/private-credential","proto":"http","dst":"h:443"}`},
		{record.KindNet, `{"o\u0070":"http_request","PATH":"/secret-token","path":"/other-token","proto":"http","dst":"h:443"}`},
		{record.KindNet, `{"op":"http_request","op":"other","path":{"credential":"private-credential"}}`},
		{record.KindRefused, `{"op":"http_request","target":"/secret-token"}`},
		{record.KindRefused, `{"OP":"http\u005frequest","TARGET":"/secret-token","target":"/other-token"}`},
	} {
		e := &record.Event{Kind: tc.kind, Payload: json.RawMessage(tc.payload)}
		if err := Redact(e); err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"private-credential", "secret-token", "other-token"} {
			if strings.Contains(string(e.Payload), secret) {
				t.Fatalf("HTTP target survived redaction: %s", e.Payload)
			}
		}
	}
	// These bytes are socket/filesystem evidence, not HTTP resource paths.
	for _, kind := range []record.Kind{record.KindFS, record.KindExec, record.KindNet, record.KindRefused} {
		e := &record.Event{Kind: kind, Payload: json.RawMessage(`{"op":"open","path":"/secret-token","target":"/secret-token","proto":"unix","dst":"unix:/secret-token"}`)}
		before := string(e.Payload)
		if err := Redact(e); err != nil {
			t.Fatal(err)
		}
		if string(e.Payload) != before {
			t.Fatalf("non-HTTP evidence rewritten: %s", e.Payload)
		}
	}
}

func TestHTTPRequestPrivacyAtWriterUnderSummaryAndOff(t *testing.T) {
	for _, mode := range []string{"summary", "off"} {
		t.Run(mode, func(t *testing.T) {
			w, dir, anchor := openTestWriter(t, WithContract([]byte("record: "+mode+"\n")))
			startRun(t, w, 0)
			write := w.RedactStage(w.Append)
			if mode == "summary" {
				e := &record.Event{Kind: record.KindNet, Source: record.SourceForwarder, PID: 123, Rule: "net.http[0]", Verdict: record.VerdictAllow, Authority: record.AuthorityRule, Attr: record.Unattributed()}
				_ = e.SetPayload(record.NetPayload{Op: "http_request", Proto: "http", Dst: "h:443", HTTPAuthority: "h:443", Method: "POST", Path: "/v1/messages/private-credential"})
				if err := write(e); err != nil {
					t.Fatal(err)
				}
			}
			e := &record.Event{Kind: record.KindNet, Source: record.SourceForwarder, PID: 123, Rule: "unmatched", Verdict: record.VerdictRefused, Reason: record.ReasonNetHTTP, Authority: record.AuthorityRule, Attr: record.Unattributed()}
			_ = e.SetPayload(record.NetPayload{Op: "http_request", Proto: "http", Dst: "h:443", HTTPAuthority: "h:443", Method: "POST", Path: "/secret-token"})
			if err := write(e); err != nil {
				t.Fatal(err)
			}
			refusal := &record.Event{Kind: record.KindRefused, Source: record.SourceForwarder, PID: 123, Rule: "unmatched", Reason: record.ReasonNetHTTP}
			_ = refusal.SetPayload(record.RefusedPayload{Op: "http_request", Target: "/secret-token"})
			if err := write(refusal); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{EventsFile, LastRefusalFile} {
				raw, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(raw), "secret-token") || strings.Contains(string(raw), "private-credential") {
					t.Fatalf("%s persisted HTTP path credential: %s", name, raw)
				}
			}
			verify(t, dir, anchor)
		})
	}
}
