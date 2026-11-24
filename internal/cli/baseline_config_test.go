// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestDecisionCommandsDoNotRefuseMissingPasswdHome(t *testing.T) {
	gcRoot(t)
	old := machineSources
	machineSources = func(int, bool) (config.Sources, string, []config.Diagnostic) {
		src, home, ds := config.Resolve(2147483000, false)
		src.Etc = ""
		return src, home, ds
	}
	t.Cleanup(func() { machineSources = old })
	for _, command := range []string{"compile", "run"} {
		_, _, errs := run(t, command, "missing-contract.yaml")
		if !strings.Contains(errs, "missing-contract.yaml") || strings.Contains(errs, "baseline UNKNOWN") || strings.Contains(errs, "passwd") || strings.Contains(errs, "[config-untrusted]") {
			t.Fatalf("%s refused home-independent config: %q", command, errs)
		}
	}
}

func TestDoctorJSONCarriesBaselineStateAndReasons(t *testing.T) {
	gcRoot(t)
	user := filepath.Join(t.TempDir(), "user.yaml")
	if err := os.Chmod(filepath.Dir(user), 0o700); err != nil {
		t.Fatal(err)
	}
	old := machineSources
	machineSources = func(uid int, secure bool) (config.Sources, string, []config.Diagnostic) {
		src, home, ds := old(uid, secure)
		src.User = user
		return src, home, ds
	}
	t.Cleanup(func() { machineSources = old })
	for _, bad := range []bool{true, false} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			body := "{}\n"
			if bad {
				body = "retention: invalid\n"
			}
			if err := os.WriteFile(user, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			code, out, errs := run(t, "doctor", "--json")
			var rep struct {
				Baseline *struct {
					Known   *bool    `json:"known"`
					Reasons []string `json:"reasons"`
				} `json:"baseline"`
			}
			if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.Baseline == nil || rep.Baseline.Known == nil {
				t.Fatalf("doctor JSON omits baseline state: exit %d out %q stderr %q error %v", code, out, errs, err)
			}
			if code == identity.ExitError || *rep.Baseline.Known == bad {
				t.Fatalf("doctor did not preserve observation state: exit %d out %q stderr %q", code, out, errs)
			}
			if bad {
				if len(rep.Baseline.Reasons) != 1 {
					t.Fatalf("missing cause: %s", out)
				}
				for _, want := range []string{"user layer", user, "invalid"} {
					if !strings.Contains(rep.Baseline.Reasons[0], want) {
						t.Errorf("reason omits %q: %s", want, out)
					}
				}
			} else if len(rep.Baseline.Reasons) != 0 {
				t.Fatalf("known baseline has causes: %s", out)
			}
		})
	}
}

// There is no CLI replacement layer or baseline opt-out. Check every noun's actual flags;
// this neither loads the real config nor runs a command or launcher.
func TestBaselineConfigHasNoReplacementFlag(t *testing.T) {
	for _, command := range commands() {
		fs := flag.NewFlagSet(command.Name, flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		if command.Flags != nil {
			command.Flags(fs)
		}
		for _, name := range []string{"config", "config-file", "no-config", "no-baseline", "force-break"} {
			if fs.Lookup(name) != nil {
				t.Errorf("%s admits --%s", command.Name, name)
			}
			if err := fs.Parse([]string{"--" + name}); err == nil {
				t.Errorf("%s accepted --%s", command.Name, name)
			}
		}
	}
}

// A changed user-layer mode must never prevent stop, and must still prevent compile.
func TestStopSurvivesUnreadableAndWritableUserConfig(t *testing.T) {
	for _, mode := range []os.FileMode{0, 0o666} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			root := gcRoot(t)
			id := endedRun(t, root, time.Now())
			path := filepath.Join(t.TempDir(), "user.yaml")
			if err := os.WriteFile(path, []byte("baseline: {env: {deny: [SECRET]}}"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
			old := machineSources
			machineSources = func(uid int, secure bool) (config.Sources, string, []config.Diagnostic) {
				src, home, ds := old(uid, secure)
				src.User = path
				return src, home, ds
			}
			t.Cleanup(func() { machineSources = old })
			code, out, errs := run(t, "stop", id)
			unknown := mode != 0 || os.Geteuid() != 0 // root can read mode 000 through DAC override
			if code != identity.ExitOK || !strings.Contains(out, "not running") || (unknown && (!strings.Contains(errs, "baseline UNKNOWN") || !strings.Contains(errs, path))) {
				t.Fatalf("stop: %d %q %q", code, out, errs)
			}
			code, _, errs = run(t, "compile", "missing.yaml")
			if unknown && (code != identity.ExitError || !strings.Contains(errs, path)) {
				t.Fatalf("compile accepted layer: %d %q", code, errs)
			}
			if !unknown && strings.Contains(errs, "[config-untrusted]") {
				t.Fatalf("root-readable layer was refused: %q", errs)
			}
		})
	}
}

func TestDecisionCommandDoesNotPrintObsoleteBaselineNotice(t *testing.T) {
	gcRoot(t)
	path := os.Getenv("TEGO_CONFIG")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("baseline: {exec: {deny: ['git push']}}\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"compile", "missing.yaml"}, {"run", "missing.yaml"}} {
		_, _, errs := run(t, args...)
		if strings.Contains(errs, "[config-baseline-not-applied]") || strings.Contains(errs, "NOT YET APPLIED to any run") {
			t.Fatalf("%v: %q", args, errs)
		}
	}
}

func TestUnknownConfigCannotAuthorizeLiveChanges(t *testing.T) {
	root := gcRoot(t)
	id := endedRun(t, root, time.Now())
	file := os.Getenv("TEGO_CONFIG")
	if err := os.Chmod(file, 0o666); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"approve", id, "q-0123456789abcdef0123456789abcdef"},
		{"resume", filepath.Join(root, id)},
		{"unblock", filepath.Join(root, id), "path", "/srv/secret"},
	} {
		code, _, errs := run(t, args...)
		if code != identity.ExitError || !strings.Contains(errs, "machine config untrusted:") {
			t.Errorf("%v reached a live change with bad config: %d %q", args, code, errs)
		}
	}
}

// TestDoctorJSONNeverPrintsAnUnplacedConfigValue: a $TEGO_CONFIG value that is not a place (here a relative one, and one
// with a "..") is named by the variable in doctor's baseline reasons, never echoed.
func TestDoctorJSONNeverPrintsAnUnplacedConfigValue(t *testing.T) {
	old := machineSources
	t.Cleanup(func() { machineSources = old })
	for _, value := range []string{"qzmark/c.yaml", filepath.Join(t.TempDir(), "qzmark-x") + "/../c.yaml"} {
		machineSources = func(uid int, secure bool) (config.Sources, string, []config.Diagnostic) {
			src, home, ds := old(uid, secure)
			src.EnvFile = value
			return src, home, ds
		}
		code, out, errs := run(t, "doctor", "--json")
		if code == identity.ExitError || strings.Contains(out+errs, "qzmark") || !strings.Contains(out, "$TEGO_CONFIG") {
			t.Errorf("value %q: exit %d, the value is echoed or the variable is not named: %s %s", value, code, out, errs)
		}
	}
}
