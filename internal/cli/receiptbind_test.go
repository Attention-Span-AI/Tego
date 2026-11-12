// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// releasedStamp is the build these tests make and check receipts as: a released tego, which a test binary is not.
var releasedStamp = receipt.MadeBy{TegoVersion: "v0.1.2", Commit: "0123456789abcdef0123456789abcdef01234567"}

// useStamp makes the commands a test runs name themselves by.
func useStamp(t *testing.T, by receipt.MadeBy) {
	t.Helper()
	prev := receiptStamp
	receiptStamp = func() receipt.MadeBy { return by }
	t.Cleanup(func() { receiptStamp = prev })
}

// savedReceipt runs `tego receipt <dir> --json` and saves its stdout as a file.
func savedReceipt(t *testing.T, dir string) (string, map[string]any) {
	t.Helper()
	code, out, errs := run(t, "receipt", dir, "--json")
	if code != identity.ExitOK {
		t.Fatalf("receipt --json: exit %d (stderr %q)", code, errs)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("--json: %v\n%s", err, out)
	}
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, m
}

// TestReceiptJSONIsBound: `tego receipt --json` binds the receipt to the record it read, names the tego that made it,
// and lists its limits; the text receipt does not change.
func TestReceiptJSONIsBound(t *testing.T) {
	useStamp(t, releasedStamp)
	dir := fixtureRun(t)
	_, m := savedReceipt(t, dir)
	b, ok := m["binding"].(map[string]any)
	if !ok {
		t.Fatalf("no binding in %v", m)
	}
	data, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	chain, _ := b["chain"].(map[string]any)
	by, _ := b["receipt_by"].(map[string]any)
	if chain["sha256"] != hex.EncodeToString(sum[:]) || chain["bytes"] != float64(len(data)) || chain["ended"] != true ||
		by["tego_version"] != releasedStamp.TegoVersion || by["commit"] != releasedStamp.Commit {
		t.Errorf("binding %v", b)
	}
	code, text, _ := run(t, "receipt", dir)
	if code != identity.ExitOK || strings.Contains(text, "binding") || strings.Contains(text, hex.EncodeToString(sum[:])) {
		t.Errorf("the text receipt changed: exit %d\n%s", code, text)
	}
}

// TestReceiptBrokenChainStillPrintsAndSays: a record whose chain breaks still gets its receipt, exit 0 as before; the
// binding says why it binds no head, and one stderr line says so to a person at a terminal.
func TestReceiptBrokenChainStillPrintsAndSays(t *testing.T) {
	useStamp(t, releasedStamp)
	dir := fixtureRun(t)
	path := filepath.Join(dir, ledger.EventsFile)
	data, _ := os.ReadFile(path)
	lines := bytes.SplitN(data, []byte("\n"), 4)
	lines[2] = bytes.Replace(lines[2], []byte(`"ts":"`), []byte(`"ts": "`), 1)
	if err := os.WriteFile(path, bytes.Join(lines, []byte("\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := run(t, "receipt", dir, "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d (stderr %q)", code, errs)
	}
	var m struct {
		Binding struct {
			Chain any    `json:"chain"`
			Error string `json:"error"`
		} `json:"binding"`
	}
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	if m.Binding.Chain != nil || !strings.Contains(m.Binding.Error, "line 2") {
		t.Errorf("binding %+v", m.Binding)
	}
	if !strings.Contains(errs, "not bound to its record") {
		t.Errorf("stderr %q", errs)
	}
}
