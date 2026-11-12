// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/receipt"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// noAnchor makes any read of the chain anchor fail the test: --check must work from the two files alone.
func noAnchor(t *testing.T) {
	t.Helper()
	prev := anchorPath
	anchorPath = func(*config.Machine) (string, error) {
		t.Error("the check resolved the chain anchor")
		return "", os.ErrNotExist
	}
	t.Cleanup(func() { anchorPath = prev })
}

// copyRun copies the run folder dir to a folder named name elsewhere, as an evidence upload keeps it.
func copyRun(t *testing.T, dir, name string) string {
	t.Helper()
	to := filepath.Join(t.TempDir(), name)
	if err := os.Mkdir(to, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(to, ledger.EventsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return to
}

// TestReceiptCheckAwayFromItsAnchor is the bound receipt's purpose: a closed run's receipt and its folder, copied
// under another name, match from the two files alone (no chain.log is read), on the run the test wrote and on the frozen
// recorded fixture; one changed byte in the record is a mismatch, exit 1.
func TestReceiptCheckAwayFromItsAnchor(t *testing.T) {
	useStamp(t, releasedStamp)
	_, written := verifiedRun(t)
	for name, dir := range map[string]string{"written": written, "fixture": fixtureRun(t)} {
		t.Run(name, func(t *testing.T) {
			saved, _ := savedReceipt(t, dir)
			evidence := copyRun(t, dir, "evidence")
			noAnchor(t)
			code, out, errs := run(t, "receipt", "--check", saved, evidence)
			if code != identity.ExitOK || !strings.HasPrefix(out, "The receipt matches the record: run ") ||
				!strings.Contains(out, "no chain.log was read") {
				t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
			}
			code, out, _ = run(t, "receipt", "--check", saved, filepath.Join(evidence, ledger.EventsFile), "--json")
			var res receipt.CheckResult
			if code != identity.ExitOK || json.Unmarshal([]byte(out), &res) != nil || res.Result != receipt.CheckMatch {
				t.Fatalf("events.jsonl as the record, --json: exit %d\n%s", code, out)
			}

			path := filepath.Join(evidence, ledger.EventsFile)
			data, _ := os.ReadFile(path)
			data[len(data)/2] ^= 0x01
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if code, out, errs := run(t, "receipt", "--check", saved, evidence); code != identity.ExitFinding ||
				!strings.HasPrefix(out, "The receipt does not match the record") {
				t.Errorf("a changed byte: exit %d\nstdout %s\nstderr %s", code, out, errs)
			}
		})
	}
}

// TestReceiptCheckCannotCheckExits125: a receipt made by another tego, and a check by a build that names no commit,
// cannot be checked: exit 125, never 0.
func TestReceiptCheckCannotCheckExits125(t *testing.T) {
	useStamp(t, releasedStamp)
	dir := fixtureRun(t)
	saved, _ := savedReceipt(t, dir)
	useStamp(t, receipt.MadeBy{TegoVersion: "v0.1.3", Commit: strings.Repeat("f", 40)})
	code, out, _ := run(t, "receipt", "--check", saved, dir, "--json")
	var res receipt.CheckResult
	if code != identity.ExitError || json.Unmarshal([]byte(out), &res) != nil || res.Result != receipt.CheckCannot {
		t.Errorf("another tego: exit %d\n%s", code, out)
	}
	useStamp(t, receipt.MadeBy{TegoVersion: "dev", Commit: "none"})
	if code, out, _ := run(t, "receipt", "--check", saved, dir); code != identity.ExitError ||
		!strings.HasPrefix(out, "Could not check the receipt against the record") {
		t.Errorf("a dev build: exit %d\n%s", code, out)
	}
}

// TestReceiptCheckUsage: --check takes a receipt file and one record; beside --verify, --last, a second record or none,
// or with an empty file name, it is a usage error. `tego receipt check` still names a run by its id's end
// (TestReceiptCheckWordStillNamesARun).
func TestReceiptCheckUsage(t *testing.T) {
	for _, args := range [][]string{
		{"receipt", "--check", "r.json"},
		{"receipt", "--check", "r.json", "a", "b"},
		{"receipt", "--check", "r.json", "a", "--verify"},
		{"receipt", "--check", "r.json", "--last"},
		{"receipt", "--check", "", "a"},
	} {
		if code, _, errs := run(t, args...); code != identity.ExitUsage {
			t.Errorf("%v exited %d, want %d (stderr %q)", args, code, identity.ExitUsage, errs)
		}
	}
}

// TestReceiptCheckWordsAvoidOverclaims: whatever the result, the check's text and JSON never say proof, signed or
// tamper-proof.
func TestReceiptCheckWordsAvoidOverclaims(t *testing.T) {
	useStamp(t, releasedStamp)
	dir := fixtureRun(t)
	saved, _ := savedReceipt(t, dir)
	other := filepath.Join(t.TempDir(), "other.json")
	if err := os.WriteFile(other, []byte(`{"receipt_v":1,"run":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"receipt", "--check", saved, dir}, {"receipt", "--check", saved, dir, "--json"},
		{"receipt", "--check", other, dir}, {"receipt", "--check", other, dir, "--json"},
		{"receipt", "--check", saved, t.TempDir()}, {"receipt", "--check", saved, t.TempDir(), "--json"},
	} {
		_, out, errs := run(t, args...)
		l := strings.ToLower(out + errs)
		for _, w := range []string{"proof", "signed", "tamper"} {
			if strings.Contains(l, w) {
				t.Errorf("%v says %q:\n%s%s", args, w, out, errs)
			}
		}
	}
}

// TestReceiptCheckWordStillNamesARun: --check is a flag, so `tego receipt check` is still the run whose id ends in
// "check", resolved as any end of an id is.
func TestReceiptCheckWordStillNamesARun(t *testing.T) {
	root := gcRoot(t)
	const alphabet = "0123456789abcdefghjkmnpqrstvwxyz" // the run id's random end, base32 (identity.NewRunID)
	var rand30 uint32
	for _, c := range "0check" {
		rand30 = rand30<<5 | uint32(strings.IndexRune(alphabet, c))
	}
	id := mintedRun(t, root, time.Now(), rand30<<2)
	if !strings.HasSuffix(id, "check") {
		t.Fatalf("minted %s", id)
	}
	useAnchor(t, ledger.DefaultAnchorPath(filepath.Join(root, id)))
	t.Chdir(t.TempDir())
	if code, out, errs := run(t, "receipt", "check"); code != identity.ExitOK || !strings.HasPrefix(out, "Receipt for run "+id+" ") {
		t.Errorf("receipt check: exit %d, want run %s's receipt\nstdout %s\nstderr %s", code, id, out, errs)
	}
}
