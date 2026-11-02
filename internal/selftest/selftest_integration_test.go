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

// envTestContract is contract_testhook.go's EnvTestContract, spelled here because this file builds without the
// tegotesthooks tag (only the binary it builds has it). A misspelling runs the embedded contract, which exits 0, so
// TestSelftestExitsOneOnAWeakenedContract fails on it.
const envTestContract = "TEGO_TEST_SELFTEST_CONTRACT"

// changed is the embedded contract template with from, which must occur in it once, replaced by to.
func changed(t *testing.T, from, to string) string {
	t.Helper()
	if n := strings.Count(contractText, from); n != 1 {
		t.Fatalf("the embedded contract holds %q %d times, want once", from, n)
	}
	return strings.Replace(contractText, from, to, 1)
}

// runSelftest runs the built `tego test --tier landlock` with args and env, and returns its stdout and exit code;
// any other failure to run it ends the test.
func runSelftest(t *testing.T, bin string, env []string, args ...string) (stdout []byte, code int) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"test", "--tier", "landlock"}, args...)...)
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err == nil {
		return out, identity.ExitOK
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("tego %s: %v\nstderr %s", strings.Join(cmd.Args[1:], " "), err, stderr.String())
	}
	t.Logf("tego %s: %v\nstderr %s", strings.Join(cmd.Args[1:], " "), err, stderr.String())
	return out, ee.ExitCode()
}

// TestSelftestExitsOneOnAWeakenedContract is exit 1 end to end (ADR 0074 (7)): the built binary's tego test, under
// the embedded contract with one line changed (the test build's TEGO_TEST_SELFTEST_CONTRACT), reports the one check
// that line reaches in its row, on the screen and in --json, and exits 1, while the other three stay refused. Listing
// the unlisted program lets it run: allowed. Denying the port file stops the connect check before it connects, so
// the run records a refused read of that file and nothing of a connection: unrecorded, since a refusal of another
// target with another reason is not the check's own. The engine is the product's; only the contract is wider. A
// template that cannot be read or filled is exit 125, never a run under the embedded contract.
func TestSelftestExitsOneOnAWeakenedContract(t *testing.T) {
	bin := buildTego(t)
	doctorEnv, _ := isolated(t)
	doctor := exec.Command(bin, "doctor", "--require", "landlock")
	doctor.Env = doctorEnv
	testutil.RequireTier(t, doctor, "landlock")

	cases := []struct {
		name     string
		from, to string // the line of the embedded contract the case changes, and what it becomes
		check    string // the check the change reaches
		result   string // that check's under-Tego result
		detail   string // the end of that row's detail, on the screen as in --json
	}{
		{"allowed", "exec:\n  allow: []", "exec:\n  allow: [{{.Program}}]", CheckRunUnlisted, ResultAllowed, "ran true"},
		{"unrecorded", "deny_read: [{{.SSH}}, {{.Env}}]", "deny_read: [{{.SSH}}, {{.Env}}, {{.PortFile}}]",
			CheckConnect, ResultUnrecorded, "/work/port: permission denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, tmp := isolated(t)
			tmpl := filepath.Join(t.TempDir(), "contract.yaml.tmpl")
			if err := os.WriteFile(tmpl, []byte(changed(t, tc.from, tc.to)), 0o600); err != nil {
				t.Fatal(err)
			}
			env = append(env, envTestContract+"="+tmpl)

			out, code := runSelftest(t, bin, env, "--json")
			if code != identity.ExitFinding {
				t.Fatalf("tego test --json: exit %d, want %d: %s", code, identity.ExitFinding, out)
			}
			var rep Report
			if err := json.Unmarshal(out, &rep); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			if rep.Schema != Schema || rep.Tier != "landlock" || rep.Verdict != VerdictFail || rep.Actions != 4 || rep.Refused != 3 {
				t.Fatalf("report %s", out)
			}
			for _, row := range rep.Checks {
				if row.Baseline.Result != ResultSucceeded {
					t.Errorf("%s: baseline %+v", row.Name, row.Baseline)
				}
				u := row.UnderTego
				if row.Name != tc.check {
					if u.Result != ResultRefused {
						t.Errorf("%s: under tego %+v, want refused", row.Name, u)
					}
					continue
				}
				if u.Result != tc.result || !strings.HasPrefix(u.Run, "r-") || !strings.HasSuffix(u.Detail, tc.detail) ||
					u.Rule != "" || u.Reason != "" || u.Target != "" || u.Match != "" {
					t.Errorf("%s: under tego %+v, want %s, a run, the detail ...%s and no refusal", row.Name, u, tc.result, tc.detail)
				}
			}

			text, code := runSelftest(t, bin, env)
			if code != identity.ExitFinding {
				t.Fatalf("tego test: exit %d, want %d: %s", code, identity.ExitFinding, text)
			}
			lines := strings.Split(string(text), "\n")
			if lines[0] != "Tego self-check: 4 actions, 3 refused at tier landlock" {
				t.Errorf("headline %q", lines[0])
			}
			c, _ := checkByName(tc.check)
			var row string
			for _, l := range lines {
				if strings.HasPrefix(l, "  "+c.action+" ") {
					row = l
				}
			}
			if f := strings.Fields(strings.TrimPrefix(row, "  "+c.action)); len(f) < 3 || f[0] != ResultSucceeded ||
				f[1] != tc.result || !strings.HasSuffix(row, tc.detail) {
				t.Errorf("the %s row reads %q, want succeeded, %s and ...%s:\n%s", tc.check, row, tc.result, tc.detail, text)
			}
			if !strings.Contains(string(text), "\nTego did not refuse every action: ") {
				t.Errorf("the screen does not say Tego did not refuse every action:\n%s", text)
			}
			if left, _ := os.ReadDir(tmp); len(left) != 0 {
				t.Errorf("tego test left %d entries in TMPDIR, the first %s", len(left), left[0].Name())
			}
		})
	}

	for _, bad := range []struct{ name, text, says string }{
		{"absent template", "", envTestContract + ": "}, // no file is written
		{"a name the data does not hold", "version: 0\ncommand: [{{.Tego}}, {{.Nope}}]\n", `"Nope"`},
	} {
		t.Run(bad.name, func(t *testing.T) {
			env, tmp := isolated(t)
			tmpl := filepath.Join(t.TempDir(), "contract.yaml.tmpl")
			if bad.text != "" {
				if err := os.WriteFile(tmpl, []byte(bad.text), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(bin, "test", "--tier", "landlock")
			cmd.Env = append(env, envTestContract+"="+tmpl)
			out, err := cmd.CombinedOutput()
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != identity.ExitError || !strings.Contains(string(out), bad.says) {
				t.Errorf("tego test: %v, want exit %d saying %s: %s", err, identity.ExitError, bad.says, out)
			}
			if left, _ := os.ReadDir(tmp); len(left) != 0 {
				t.Errorf("tego test left %d entries in TMPDIR, the first %s", len(left), left[0].Name())
			}
		})
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
