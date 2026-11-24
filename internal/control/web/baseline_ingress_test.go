// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/drift"
	"github.com/attention-span-ai/tego/internal/check/events"
	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/ledger/runstart"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Each entry exercises a consumer, rather than merely testing the shared validator.
// The fixture commitments stay unchanged. A reader must refuse the original raw
// shape even when encoding/json would restore a committed zero value.
func TestBaselineRawEvidenceIngresses(t *testing.T) {
	data, err := os.ReadFile("../../../spec/record/v1/fixtures/baseline/applied.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	line := bytes.Split(data, []byte{'\n'})[0]
	event, err := record.Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dir := filepath.Join(root, event.Run)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	withReader := func(f func(*ledger.Reader) error) error {
		r, err := ledger.OpenReader(dir)
		if err != nil {
			return err
		}
		defer r.Close()
		return f(r)
	}
	ingresses := []struct {
		name string
		read func(*record.Event) error
	}{
		{"record-decoder-and-exporters", func(_ *record.Event) error {
			raw, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
			if err != nil {
				return err
			}
			_, err = record.Decode(raw)
			return err
		}},
		{"json-event-export", func(_ *record.Event) error {
			return withReader(func(r *ledger.Reader) error {
				var out bytes.Buffer
				_, err := events.JSONOf(context.Background(), &out, r, r.Entries(), events.Filter{})
				return err
			})
		}},
		{"metadata-catalog", func(_ *record.Event) error {
			_, problems := runstart.Load(context.Background(), root)
			return errors.Join(problems...)
		}},
		{"event-validation", func(e *record.Event) error { return e.ValidateAt(record.MinorBaseline) }},
		{"typed-json", func(e *record.Event) error { var p record.RunStartPayload; return json.Unmarshal(e.Payload, &p) }},
		{"sealed-replay", func(e *record.Event) error {
			var p record.RunStartPayload
			if err := e.DecodePayload(&p); err != nil {
				return err
			}
			if p.Baseline == nil {
				_, err := agent.ReplayRecordedBaseline(nil, p)
				return err
			}
			c, _, err := agent.LoadBytes("/srv/agent.yaml", p.Baseline.SourceContract, nil)
			if err != nil {
				return err
			}
			_, err = agent.ReplayRecordedBaseline(c, p)
			return err
		}},
		{"receipt-and-json-export", func(_ *record.Event) error {
			return withReader(func(r *ledger.Reader) error {
				_, err := receipt.Compute(context.Background(), r, receipt.Options{})
				return err
			})
		}},
		{"drift", func(_ *record.Event) error {
			return withReader(func(r *ledger.Reader) error { _, err := drift.ComputeCtx(context.Background(), r, nil); return err })
		}},
		{"rulesview-run-start", func(_ *record.Event) error { _, err := rulesview.RunStart(root, event.Run); return err }},
		{"historical-rulesview", func(_ *record.Event) error {
			c := rulesview.Load(context.Background(), root, event.Run, rulesview.Options{})
			return errors.New(c.Err)
		}},
		{"builder-learn", func(_ *record.Event) error {
			return errors.New(rulesview.Learn(context.Background(), root, "", event.Run).Err)
		}},
		{"in-force-comparison", func(_ *record.Event) error {
			v := rulesview.InForce(context.Background(), root, event.Run, rulesview.Options{})
			return errors.New(v.Err)
		}},
		{"in-force-cached-run", func(_ *record.Event) error {
			v := rulesview.InForce(context.Background(), root, event.Run, rulesview.Options{Run: &ledgerview.Run{ID: event.Run}})
			return errors.New(v.Err)
		}},
		{"metadata-projection", func(e *record.Event) error { _, err := runstart.Project(e.Payload); return err }},
		{"dashboard-receipt", func(_ *record.Event) error {
			v := loadReceipt(context.Background(), root, event.Run, ledgerview.Sensitive{}, ledgerview.Pricing{})
			if v.Err == "" {
				return nil
			}
			return errors.New(v.Err)
		}},
		{"dashboard-receipt-loader", func(_ *record.Event) error {
			_, err := ledgerview.LoadReceipt(context.Background(), root, event.Run)
			return err
		}},
	}

	cases, err := testutil.BaselineCases(line)
	if err != nil {
		t.Fatal(err)
	}
	subset := 0
	if raceEnabled {
		subset = testutil.ShuffleOffset(t, 4) // which fourth: the -shuffle seed's, so a few runs cover all of them
	}
	for i, tc := range cases {
		// Every case reads the line through several readers, three of them with a helper process each; a race build starts
		// that helper race-instrumented (about a second), so every fourth case runs there and all of them everywhere else.
		if raceEnabled && i%4 != subset {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), append(tc.Line, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			for _, ingress := range ingresses {
				if err := ingress.read(tc.Event); err == nil || !strings.Contains(err.Error(), tc.Fact[strings.LastIndex(tc.Fact, ".")+1:]) {
					t.Errorf("%s accepted invalid evidence or lost refusal reason for %s: %v", ingress.name, tc.Fact, err)
				}
			}
		})
	}
}

func TestBaselineUnsupportedRevisionReaders(t *testing.T) {
	for _, minor := range []int{36, 38, record.Minor + 1} {
		t.Run(fmt.Sprint(minor), func(t *testing.T) {
			payload := []byte(fmt.Sprintf(`{"record_minor":%d,"tier":"landlock"}`, minor))
			var p record.RunStartPayload
			if err := json.Unmarshal(payload, &p); err == nil || !strings.Contains(err.Error(), "unsupported revision") {
				t.Fatalf("typed reader: %v", err)
			}
			if _, err := runstart.Project(payload); err == nil || !strings.Contains(err.Error(), "unsupported revision") {
				t.Fatalf("metadata: %v", err)
			}
			p.RecordMinor = minor
			if _, err := agent.ReplayRecordedBaseline(nil, p); err == nil || !strings.Contains(err.Error(), "unsupported revision") {
				t.Fatalf("replay: %v", err)
			}
		})
	}
}
