// SPDX-License-Identifier: Apache-2.0

package record

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func baselineStartFixture(t *testing.T) (*Event, RunStartPayload) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixturesDir, "baseline", "applied.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := Decode(bytes.Split(data, []byte{'\n'})[0])
	if err != nil {
		t.Fatal(err)
	}
	var p RunStartPayload
	if err := e.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	return e, p
}
func TestBaselineRecordShapeAndRevision(t *testing.T) {
	e, p := baselineStartFixture(t)
	if p.RecordMinor != MinorBaseline {
		t.Fatalf("fixture revision %d, want %d", p.RecordMinor, MinorBaseline)
	}
	if err := e.ValidateAt(MinorBaseline); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"baseline", "effective_hash", "contract_hash"} {
		t.Run("missing-"+name, func(t *testing.T) {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(e.Payload, &m); err != nil {
				t.Fatal(err)
			}
			delete(m, name)
			q := *e
			var err error
			q.Payload, err = json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := q.ValidateAt(MinorBaseline); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("missing %s: %v", name, err)
			}
		})
	}
	p.RecordMinor = MinorLearn
	if err := p.ValidateBaseline(); err == nil || !strings.Contains(err.Error(), "below-minor") {
		t.Fatalf("below revision accepted: %v", err)
	}
	p.RecordMinor = MinorBaseline
	p.Baseline = nil
	if err := p.ValidateBaseline(); err == nil {
		t.Fatal("new revision missing block accepted")
	}
	for _, key := range fieldChildren["run_start.baseline"] {
		name := strings.TrimPrefix(key, "run_start.baseline.")
		t.Run("fact-"+name, func(t *testing.T) {
			_, q := baselineStartFixture(t)
			raw, err := json.Marshal(q.Baseline)
			if err != nil {
				t.Fatal(err)
			}
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw, &obj); err != nil {
				t.Fatal(err)
			}
			delete(obj, name)
			raw, err = json.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			if err := baselineRequiredShape(raw); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("missing fact %s: %v", name, err)
			}
		})
	}
}
func TestBaselineDigestFixedEncoding(t *testing.T) {
	rules := []BaselineRule{{Key: "env.deny", Expanded: "Z"}, {Key: "env.deny", Expanded: "A<&"}, {Key: "env.deny", Expanded: "Z"}}
	digest, err := BaselineDigest(rules)
	if err != nil {
		t.Fatal(err)
	}
	want := baselineHash([]byte("{\"v\":1,\"fs.deny_read\":[],\"fs.deny_write\":[],\"exec.deny\":[],\"env.deny\":[\"A<&\",\"Z\"]}\n"))
	if digest != want {
		t.Fatalf("normalized digest %s, want %s", digest, want)
	}
	if _, err := BaselineDigest([]BaselineRule{{Key: "env.deny", Expanded: string([]byte{0xff})}}); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestEarlierRecordFixturesHaveNoBaselineClaim(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(fixturesDir, "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(data, []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			e, err := Decode(line)
			if err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			if e.Kind != KindRunStart {
				continue
			}
			var p RunStartPayload
			if err := e.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.RecordMinor >= MinorBaseline {
				continue
			}
			seen[p.RecordMinor] = true
			if err := e.ValidateAt(p.RecordMinor); err != nil {
				t.Fatalf("%s: %v", file, err)
			}
			if p.Baseline != nil || p.EffectiveHash != "" {
				t.Fatalf("old fixture %s claims baseline", file)
			}
			encoded, err := e.MarshalLineAt(p.RecordMinor)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(line, encoded) {
				t.Fatalf("old fixture %s bytes changed", file)
			}
		}
	}
	if len(seen) < 10 {
		t.Fatalf("only %d fixture revisions exercised", len(seen))
	}
}

func TestPrincipalReservationDoesNotGainAWriter(t *testing.T) {
	raw := []byte(`"person:p-0123456789abcdef"`)
	if err := validateAnswerPrincipal(MinorPrincipal, raw); err != nil {
		t.Fatal(err)
	}
	if err := validateAnswerPrincipal(MinorPrincipal-1, raw); err == nil || !strings.Contains(err.Error(), "below-minor") {
		t.Fatalf("below revision: %v", err)
	}
	if err := validateAnswerPrincipal(MinorPrincipal, []byte(`"root"`)); err == nil {
		t.Fatal("invalid reserved principal accepted")
	}
}

func TestBaselineRecordRejectsLossyFactStrings(t *testing.T) {
	for _, field := range []string{"home", "source", "replay"} {
		t.Run(field, func(t *testing.T) {
			_, p := baselineStartFixture(t)
			switch field {
			case "home":
				p.Baseline.Home = string([]byte{'/', 'h', 0xff})
			case "source":
				p.Baseline.Sources[1].File = string([]byte{'/', 'f', 0xff})
			case "replay":
				p.Baseline.Replay = append(append([]byte(`{"path":"`), 0xff), []byte(`"}`)...)
			}
			if err := p.Baseline.SealEvidence(); err == nil {
				t.Fatal("lossy fact string was silently repaired")
			}
		})
	}
}

func TestBaselineOptionalMetadataRemainsIgnorable(t *testing.T) {
	e, _ := baselineStartFixture(t)
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(e.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	var block map[string]json.RawMessage
	if err := json.Unmarshal(payload["baseline"], &block); err != nil {
		t.Fatal(err)
	}
	block["extension"] = json.RawMessage(`{"note":"metadata"}`)
	for _, key := range []string{"rules", "sources"} {
		var rows []map[string]json.RawMessage
		if err := json.Unmarshal(block[key], &rows); err != nil {
			t.Fatal(err)
		}
		rows[0]["extension"] = json.RawMessage(`"metadata"`)
		var err error
		block[key], err = json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
	}
	var err error
	payload["baseline"], err = json.Marshal(block)
	if err != nil {
		t.Fatal(err)
	}
	e.Payload, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ValidateAt(MinorBaseline); err != nil {
		t.Fatalf("optional metadata became a refusal: %v", err)
	}
}

func TestBaselineAbsenceDocumentation(t *testing.T) {
	const sentence = "A record without the baseline block proves nothing about a baseline, neither that one applied nor that none did."
	for _, path := range []string{"../../../spec/record/v1/README.md", "../../../docs/development/baseline.md"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(data), sentence) != 1 {
			t.Errorf("%s must state baseline absence meaning once", path)
		}
	}

}

func TestBaselineRawDecodeClearsPreviousEvidence(t *testing.T) {
	_, p := baselineStartFixture(t)
	if err := json.Unmarshal([]byte(`{"record_minor":null}`), &p); err == nil {
		t.Fatal("malformed revision accepted")
	}
	if p.Baseline != nil || p.EffectiveHash != "" {
		t.Fatal("refused decode retained previous evidence")
	}
}

// Baseline revision 39 must not imply support for the reserved business journal,
// or change the already declared 32..35 reader profiles.
func TestDeclaredMinorsAndUnsupportedBusinessRevision(t *testing.T) {
	e, p := baselineStartFixture(t)
	p.Baseline, p.EffectiveHash = nil, ""
	for _, minor := range []int{32, 33, 34, 35, 38} {
		t.Run(strconv.Itoa(minor), func(t *testing.T) {
			p.RecordMinor = minor
			if err := e.SetPayload(p); err != nil {
				t.Fatal(err)
			}
			if minor == 38 {
				if SupportsMinor(minor) {
					t.Fatal("business revision became supported")
				}
				if err := e.ValidateAt(minor); FieldCode(err) != "record-minor" || !strings.Contains(err.Error(), "unsupported") {
					t.Fatalf("business revision not explicitly refused: %v", err)
				}
				raw, err := e.MarshalLine()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Decode(raw); FieldCode(err) != "record-minor" || !strings.Contains(err.Error(), "unsupported") {
					t.Fatalf("business line not refused by decoder: %v", err)
				}
				return
			}
			if !SupportsMinor(minor) {
				t.Fatal("declared reader profile lost support")
			}
			raw, err := e.MarshalLineAt(minor)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(raw); err != nil {
				t.Fatal(err)
			}
		})
	}
	if MinorDeployment != 32 || MinorSecrets != 33 || MinorShares != 34 || MinorStoppedBy != 35 || MinorBaseline != 39 {
		t.Fatal("revision allocation moved")
	}
}
