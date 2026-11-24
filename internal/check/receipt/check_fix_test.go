// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func forBindingVersions(t *testing.T, test func(*testing.T, int)) {
	t.Helper()
	for _, version := range []struct {
		name string
		v    int
	}{{"binding1", 1}, {"binding2", 0}} {
		t.Run(version.name, func(t *testing.T) { test(t, version.v) })
	}
}

// Old tests that deliberately target version 1 keep that default. Facts and
// ended suites request both versions, including the production default, zero.
func receiptBindingVersion(versions []int) int {
	if len(versions) > 0 {
		return versions[0]
	}
	return 1
}

func editFactsReceipt(t *testing.T, path string, edit func(map[string]any)) {
	t.Helper()
	editReceipt(t, path, func(m map[string]any) {
		edit(m)
		resealTestReceipt(t, m)
	})
}

func TestCheckHelpersUseRequestedBindingVersion(t *testing.T) {
	forBindingVersions(t, func(t *testing.T, bindVersion int) {
		r := ledgerOf(t, boundRun())
		for _, path := range []string{
			receiptAt(t, r.Dir(), testBy, 0, bindVersion),
			receiptPriced(t, r.Dir(), flatPrices{}, 0, bindVersion),
			boundPair(t, boundRun(), bindVersion).receipt,
		} {
			res := Check(context.Background(), CheckInput{Receipt: path, Record: r.Dir(), By: testBy})
			want := bindVersion
			if want == 0 {
				want = BindingVersion
			}
			if res.BindingVersion != want {
				t.Errorf("helper made binding %d, requested %d", res.BindingVersion, want)
			}
		}
	})
}

func TestRequireEndedUnreadableRecordCannotCheck(t *testing.T) {
	for _, kind := range []string{"missing directory", "missing named directory", "missing events", "missing named events", "events directory", "events symlink", "events FIFO"} {
		t.Run(kind, func(t *testing.T) {
			p := v2Pair(t)
			switch kind {
			case "missing directory":
				p.dir = filepath.Join(t.TempDir(), "missing")
			case "missing named directory":
				p.dir = filepath.Join(t.TempDir(), "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
			case "missing named events":
				p.dir = filepath.Join(t.TempDir(), "r-3f9c2a1b-0dllq06ts7400-k7m2pq")
				if err := os.Mkdir(p.dir, 0700); err != nil {
					t.Fatal(err)
				}
			case "missing events", "events directory", "events symlink", "events FIFO":
				path := filepath.Join(p.dir, ledger.EventsFile)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "events directory":
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				case "events symlink":
					if err := os.Symlink(p.receipt, path); err != nil {
						t.Fatal(err)
					}
				case "events FIFO":
					if err := syscall.Mkfifo(path, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, require := range []bool{false, true} {
				res := Check(context.Background(), CheckInput{Receipt: p.receipt, Record: p.dir, By: testBy, RequireEnded: require})
				wantResult(t, res, CheckCannot, identity.ExitError)
				if require {
					for _, name := range []string{"ended", "teardown"} {
						if s := step(res, name); s.Result != StepNotChecked || !strings.Contains(s.Why, "record could not be read") {
							t.Errorf("%s: %+v", name, s)
						}
					}
				}
			}
		})
	}
}

func TestRequireEndedBrokenChainDoesNotAssertAnEnd(t *testing.T) {
	p := v2Pair(t)
	path := filepath.Join(p.dir, ledger.EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Replace(data, []byte("/home/u/.bashrc"), []byte("/home/u/.zshrc_"), 1), 0600); err != nil {
		t.Fatal(err)
	}
	res := Check(context.Background(), CheckInput{Receipt: p.receipt, Record: p.dir, By: testBy, RequireEnded: true})
	wantResult(t, res, CheckMismatch, identity.ExitFinding)
	for _, name := range []string{"ended", "teardown"} {
		if s := step(res, name); s.Result != StepNotChecked || !strings.Contains(s.Why, "chain and head") {
			t.Errorf("%s: %+v", name, s)
		}
	}
}

func TestRequireEndedUnreadableStatusCannotCheck(t *testing.T) {
	for _, kind := range []string{"missing", "directory", "symlink", "FIFO"} {
		t.Run(kind, func(t *testing.T) {
			p := v2Pair(t)
			path := filepath.Join(t.TempDir(), "run-status.json")
			switch kind {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(p.receipt, path); err != nil {
					t.Fatal(err)
				}
			case "FIFO":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			res := Check(context.Background(), CheckInput{Receipt: p.receipt, Record: p.dir, By: testBy, RequireEnded: true, StatusFile: path})
			wantResult(t, res, CheckCannot, identity.ExitError)
			if s := step(res, "teardown"); s.Result != StepNotChecked {
				t.Errorf("teardown: %+v", s)
			}
		})
	}
}

func TestBindingResealedMismatchNamesEditedField(t *testing.T) {
	for _, field := range []string{"refusals.total", "time_taken.seconds"} {
		t.Run(field, func(t *testing.T) {
			p := v2Pair(t)
			editReceiptNumbers(t, p.receipt, func(m map[string]any) {
				if field == "refusals.total" {
					obj(m, "refusals")["total"] = json.Number("999")
				} else {
					obj(m, "time_taken")["seconds"] = json.Number("4.0")
				}
				resealTestReceipt(t, m)
			})
			res := checked(t, p, testBy)
			wantResult(t, res, CheckMismatch, identity.ExitFinding)
			if s := step(res, "facts"); s.Result != StepFail || !strings.HasPrefix(s.Why, field+": ") {
				t.Errorf("facts: %+v, want %s", s, field)
			}
		})
	}
}

func TestBindingPassSaysReceiptAloneCanBeResealed(t *testing.T) {
	res := checked(t, v2Pair(t), testBy)
	const want = "binding.receipt_sha256 matches the receipt's other values; anyone who edits the receipt can recompute it"
	if got := step(res, "binding"); got.Result != StepPass || got.Why != want {
		t.Fatalf("binding: %+v", got)
	}
}

func TestCheckDoesNotClaimProducerIdentityWasChecked(t *testing.T) {
	res := checked(t, v2Pair(t), testBy)
	var text, data bytes.Buffer
	if err := res.Text(&text); err != nil {
		t.Fatal(err)
	}
	if err := res.JSON(&data); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{text.String(), data.String()} {
		if !strings.Contains(output, "producer image identity must be checked against release checksums separately") ||
			strings.Contains(output, "producer image identity is checked") {
			t.Fatal(output)
		}
	}
}

func TestCheckTextUnreadableReceiptMakesNoCoverageClaim(t *testing.T) {
	res := Check(context.Background(), CheckInput{Receipt: filepath.Join(t.TempDir(), "missing"), Record: "missing", By: testBy})
	var b bytes.Buffer
	if err := res.Text(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), "Could not check the receipt") || strings.Contains(b.String(), "Incomplete:") || strings.Contains(b.String(), "Binding version:") {
		t.Fatal(b.String())
	}
}

func TestCheckTextBindingV1ExplainsMissingChecksum(t *testing.T) {
	res := checked(t, boundPair(t, boundRun()), testBy)
	var b bytes.Buffer
	if err := res.Text(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Binding version: 1; no receipt checksum; totals are compared only by facts.") {
		t.Fatal(b.String())
	}
}

// resealTestReceipt lets facts tests model an editor who knows the unkeyed checksum.
func resealTestReceipt(t *testing.T, m map[string]any) {
	t.Helper()
	b, ok := m["binding"].(map[string]any)
	if !ok || (b["v"] != float64(2) && b["v"] != json.Number("2")) {
		return
	}
	h, err := payloadDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	b["receipt_sha256"] = h
}
