// SPDX-License-Identifier: Apache-2.0

//go:build integration

package selftest

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// buildTego builds cmd/tego with tegotesthooks, whose chain anchor and own log go where testutil.TegoEnv says.
func buildTego(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tego")
	cmd := exec.Command("go", "build", "-tags", "tegotesthooks", "-o", bin, "github.com/attention-span-ai/tego/cmd/tego")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	return bin
}

// isolated is the environment of a tego process of this test: TegoEnv's isolation, a machine config layer whose
// ledger_root is the test's own, and TMPDIR, where tego test makes its tree, a directory the test then checks.
func isolated(t *testing.T) (env []string, tmp string) {
	t.Helper()
	dir := t.TempDir()
	tmp = filepath.Join(dir, "tmp")
	ledger := filepath.Join(dir, "tego", "ledger")
	for _, d := range []string{tmp, ledger} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	layer := filepath.Join(dir, "tego", "tego.yaml")
	if err := os.WriteFile(layer, []byte("ledger_root: "+ledger+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return testutil.TegoEnv(t, dir, "TEGO_CONFIG="+layer, "TMPDIR="+tmp), tmp
}

// TestSelftestTierLandlockEndToEnd runs the built `tego test --json --tier landlock` with no root: every action
// works directly and is refused under tego run with its rule and reason read from the run's ledger, exit 0, and
// the temporary tree is gone afterwards, nothing else left in TMPDIR (TestSelftestTouchesNothingOutsideItsTree's
// half that a whole run can show).
func TestSelftestTierLandlockEndToEnd(t *testing.T) {
	bin := buildTego(t)
	env, tmp := isolated(t)
	doctor := exec.Command(bin, "doctor", "--require", "landlock")
	doctor.Env = env
	testutil.RequireTier(t, doctor, "landlock")

	cmd := exec.Command(bin, "test", "--json", "--tier", "landlock")
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("tego test: %v\nstdout %s\nstderr %s", err, out, stderr.String())
	}
	var rep Report
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if rep.Schema != Schema || rep.Tier != "landlock" || rep.Verdict != VerdictPass || rep.Actions != 4 || rep.Refused != 4 {
		t.Fatalf("report %s", out)
	}
	want := map[string]string{
		CheckReadSecret: "read-denied", CheckWriteOutside: "write-outside-contract",
		CheckRunUnlisted: "exec-not-allowed", CheckConnect: "net-not-allowed",
	}
	for i, row := range rep.Checks {
		if row.Name != Names()[i] {
			t.Errorf("row %d is %s, want %s", i, row.Name, Names()[i])
		}
		if row.Baseline.Result != ResultSucceeded {
			t.Errorf("%s: baseline %+v", row.Name, row.Baseline)
		}
		u := row.UnderTego
		if u.Result != ResultRefused || u.Reason != want[row.Name] || u.Rule == "" || !strings.HasPrefix(u.Run, "r-") {
			t.Errorf("%s: under tego %+v, want refused %s", row.Name, u, want[row.Name])
		}
	}
	if !strings.HasPrefix(rep.Checks[0].UnderTego.Rule, "fs.deny_read[") {
		t.Errorf("the key's refusal names %q, not the contract's deny_read", rep.Checks[0].UnderTego.Rule)
	}
	left, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("tego test left %d entries in TMPDIR, the first %s", len(left), left[0].Name())
	}
}

// TestSelftestExitCodes: a usage error is 2, before any tree is made; the text report's headline is the one line the
// demo shows.
func TestSelftestExitCodes(t *testing.T) {
	bin := buildTego(t)
	env, tmp := isolated(t)
	for _, args := range [][]string{{"test", "extra"}, {"test", "--tier", "nope"}, {"test", "--bogus"}} {
		cmd := exec.Command(bin, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != identity.ExitUsage {
			t.Errorf("tego %s: %v, want exit %d: %s", strings.Join(args, " "), err, identity.ExitUsage, out)
		}
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("a usage error made a tree")
	}

	doctor := exec.Command(bin, "doctor", "--require", "landlock")
	doctor.Env = env
	testutil.RequireTier(t, doctor, "landlock")
	cmd := exec.Command(bin, "test", "--tier", "landlock")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tego test: %v: %s", err, out)
	}
	if first, _, _ := strings.Cut(string(out), "\n"); first != "Tego self-check: 4 actions, 4 refused at tier landlock" {
		t.Errorf("headline %q", first)
	}
}
