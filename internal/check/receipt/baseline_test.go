// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestBaselineReceiptWordsAndBinding(t *testing.T) {
	for _, mode := range []string{"applied", "not-applied", "zero"} {
		t.Run(mode, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "baseline", mode+".jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0600); err != nil {
				t.Fatal(err)
			}
			r, err := ledger.OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			rc, err := Compute(context.Background(), r, Options{Bind: &MadeBy{TegoVersion: "test", Commit: "abc"}, BinarySHA256: strings.Repeat("a", 64)})
			if err != nil {
				t.Fatal(err)
			}
			if rc.Baseline == nil || rc.Binding.V != BaselineBindingVersion || rc.Binding.EffectiveHash != rc.Baseline.EffectiveHash {
				t.Fatalf("missing evidence/binding: %+v", rc.Binding)
			}
			text := rc.BaselineText()
			want := "A machine baseline was in force"
			if mode != "applied" {
				want = "Recording alone held nothing"
			}
			if !strings.Contains(text, want) || !strings.Contains(text, "Contract SHA-256") || !strings.Contains(text, "Effective SHA-256") || !strings.Contains(text, "not authenticate") {
				t.Fatal(text)
			}
			var out bytes.Buffer
			if err := rc.Text(&out); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), text) {
				t.Fatal("terminal and shared baseline words differ")
			}
		})
	}
	legacy := compute(t, []line{start("off", true), end(1, 0)}, Options{})
	if legacy.Baseline != nil || legacy.BaselineText() != "" {
		t.Fatal("old receipt acquired baseline claim")
	}
}

func TestBaselineReceiptCheckPreservesBothHashes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "baseline", "applied.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	recordPath := filepath.Join(dir, ledger.EventsFile)
	if err := os.WriteFile(recordPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	by := MadeBy{TegoVersion: "0.2.0-test", Commit: "b123"}
	rc, err := Compute(context.Background(), r, Options{Bind: &by, BinarySHA256: strings.Repeat("a", 64)})
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "receipt.json")
	var out bytes.Buffer
	if err := rc.JSON(&out); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	got := Check(context.Background(), CheckInput{Receipt: path, Record: recordPath, By: by})
	if got.Result != CheckMatch {
		t.Fatalf("bound baseline receipt does not check: %+v", got)
	}
	rc.Binding.EffectiveHash = strings.Repeat("f", 64)
	if err := rc.seal(); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := rc.JSON(&out); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	got = Check(context.Background(), CheckInput{Receipt: path, Record: recordPath, By: by})
	if got.Result != CheckMismatch {
		t.Fatalf("edited effective hash accepted: %+v", got)
	}
}

func TestBaselineReceiptCountsRecordedMembership(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "baseline", "applied.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := record.Decode(bytes.Split(data, []byte{'\n'})[0])
	if err != nil {
		t.Fatal(err)
	}
	var p record.RunStartPayload
	if err := e.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	rc := compute(t, []line{{kind: record.KindRunStart, payload: p}, {kind: record.KindExec, verdict: record.VerdictRefused, rule: "exec.deny[git push]", reason: record.ReasonExecNotAllowed, payload: record.ExecPayload{Argv: []string{"git", "push"}}}, end(2, 0)}, Options{})
	if len(rc.Baseline.Refusals) != 2 || rc.Baseline.Refusals[0].Count != 1 || rc.Baseline.Refusals[1].Count != 0 {
		t.Fatalf("baseline attribution or env count: %+v", rc.Baseline.Refusals)
	}
	if !strings.Contains(rc.BaselineText(), "1 recorded refusals") {
		t.Fatal(rc.BaselineText())
	}
}

func TestBaselineEarlierFixtureReceiptsHaveNoClaim(t *testing.T) {
	files, err := filepath.Glob("../../../spec/record/v1/fixtures/*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			event, err := record.Decode(bytes.SplitN(data, []byte{'\n'}, 2)[0])
			if err != nil {
				t.Fatal(err)
			}
			var start record.RunStartPayload
			if err := event.DecodePayload(&start); err != nil {
				t.Fatal(err)
			}
			if start.RecordMinor >= record.MinorBaseline {
				t.Fatal("earlier fixture moved to baseline revision")
			}
			seen[start.RecordMinor] = true
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0600); err != nil {
				t.Fatal(err)
			}
			r, err := ledger.OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			rc, err := Compute(context.Background(), r, Options{Bind: &MadeBy{TegoVersion: "test", Commit: "abc"}, BindVersion: 1})
			if err != nil {
				t.Fatal(err)
			}
			if rc.Binding.Chain == nil || rc.Binding.Error != "" {
				t.Fatalf("old chain no longer verifies: %+v", rc.Binding)
			}
			if rc.Baseline != nil || rc.BaselineText() != "" || rc.Binding.EffectiveHash != "" || rc.Binding.BaselineSHA256 != "" {
				t.Fatal("old receipt acquired a baseline claim")
			}
		})
	}
	if len(seen) < 10 {
		t.Fatalf("only %d earlier fixture minors exercised", len(seen))
	}
}

// TestReceiptHomeIsTheRecordedOne: "~" in the text layout stands for the home the run recorded (its baseline evidence's
// owner home), never for the caller's; a record with none leaves every path whole and, when asked, says so.
func TestReceiptHomeIsTheRecordedOne(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "baseline", "applied.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	rc, err := Compute(context.Background(), r, Options{SayNoHome: true})
	if err != nil {
		t.Fatal(err)
	}
	b := rc.Baseline.Evidence
	if !b.OwnerKnown || b.Home == "" {
		t.Fatalf("the fixture records no owner home: %+v", b)
	}
	if got := rc.ShortPath(b.Home + "/.ssh/id_rsa"); got != "~/.ssh/id_rsa" {
		t.Errorf("a path under the recorded home prints %q", got)
	}
	var out bytes.Buffer
	if err := rc.Text(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "does not name one") {
		t.Errorf("a record with a home says it has none:\n%s", out.String())
	}

	none := compute(t, []line{start("off", true), end(1, 0)}, Options{SayNoHome: true})
	if got := none.ShortPath("/home/u/.ssh/id_rsa"); got != "/home/u/.ssh/id_rsa" {
		t.Errorf("a run with no recorded home folded a path: %q", got)
	}
	out.Reset()
	if err := none.Text(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "this run's record does not name one") {
		t.Errorf("a record with no home does not say so:\n%s", out.String())
	}
	quiet := compute(t, []line{start("off", true), end(1, 0)}, Options{})
	out.Reset()
	_ = quiet.Text(&out)
	if strings.Contains(out.String(), "does not name one") {
		t.Errorf("the line appears without being asked for:\n%s", out.String())
	}
}
