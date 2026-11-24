// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
	"github.com/attention-span-ai/tego/internal/setup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

type parityInput struct {
	State serviceState
	CC    CheckContext
	Text  []byte
}
type parityOutput struct {
	Error       string
	Table       string
	Diagnostics string
	OK          bool
}

func init() {
	pathcheck.Register("test.caller-parity", func(ctx context.Context, data []byte) ([]byte, error) {
		var in parityInput
		if err := pathcheck.Decode(data, &in); err != nil {
			return nil, err
		}
		s, err := serviceFromState(ctx, in.State)
		if err != nil {
			return nil, err
		}
		return pathcheck.Encode(checkParity(ctx, s, in.CC, in.Text))
	})
}

// This in-process path lives only in tests. Compare full diagnostics and table
// bytes with the same compiler/check reached through the production transport.
func checkParity(ctx context.Context, s *Service, cc CheckContext, text []byte) parityOutput {
	var out parityOutput
	rt, err := s.compile(ctx, cc, text)
	if err != nil {
		out.Error = err.Error()
	} else {
		var b bytes.Buffer
		if err := agent.PrintRuleTable(&b, rt); err != nil {
			out.Error = err.Error()
		}
		out.Table = b.String()
	}
	ds, ok := setup.CheckFile(text, cc.Contract, cc.Cwd, *s.newEnv())
	var diag bytes.Buffer
	if err := agent.WriteDiagnostics(&diag, ds); err != nil {
		panic(err)
	}
	out.Diagnostics, out.OK = diag.String(), ok
	return out
}

func TestHelperCallerContextParity(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"project", "profiles", "home", "alternate-home", "runtime/tego", "registry", "ledger", "ipc"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TMUX_TMPDIR", filepath.Join(root, "ipc"))
	t.Setenv("SCREENDIR", filepath.Join(root, "ipc"))
	cfg := filepath.Join(root, "selected-config.yaml")
	writeFile(t, cfg, "version: 0\nprofiles: "+filepath.Join(root, "profiles")+"\nregistry: "+filepath.Join(root, "registry")+"\nledger_root: "+filepath.Join(root, "ledger")+"\n")
	writeFile(t, filepath.Join(root, "profiles/base.yaml"), "fs:\n  read: [\"./\"]\n")
	for _, name := range []string{"default", "runtime", "TEGO_CONFIG", "another-home", "sudo-delegate"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("XDG_RUNTIME_DIR", "")
			if name == "runtime" {
				t.Setenv("XDG_RUNTIME_DIR", filepath.Join(root, "runtime"))
			}
			t.Setenv("TEGO_CONFIG", "")
			if name == "TEGO_CONFIG" {
				t.Setenv("TEGO_CONFIG", cfg)
			}
			home := filepath.Join(root, "home")
			if name == "another-home" {
				home = filepath.Join(root, "alternate-home")
				t.Setenv("HOME", home)
			}
			caller := config.CaptureCaller()
			m, ds, err := config.LoadSources(config.Sources{EnvFile: os.Getenv("TEGO_CONFIG")}, home, caller.UID, config.TrustAbort)
			if err != nil {
				t.Fatalf("config: %v %v", err, ds)
			}
			if name != "TEGO_CONFIG" {
				m.Profiles.Value = filepath.Join(root, "profiles")
				m.Registry.Value = filepath.Join(root, "registry")
				m.LedgerRoot.Value = filepath.Join(root, "ledger")
			}
			if name == "sudo-delegate" { // Framed selected delegate facts; actual sudo is owed in a guest.
				caller.UID = 65534
				caller.Username = "nobody"
				caller.Home = home
				caller.RuntimeDirs = []string{"/run/user/65534"}
			}
			ctx, closeSession := contracts.WithHelperSession(context.Background())
			defer closeSession()
			// Explicit selected identity must be carried, even when it differs from the worker.
			ctx = contracts.ContextWithCaller(ctx, caller)
			s := &Service{Machine: m, Ledger: filepath.Join(root, "ledger"), Home: home, PATH: "/usr/bin:/bin", caller: &caller}
			state := serviceState{Caller: &caller, Machine: mustSnapshot(t, m), Ledger: s.Ledger, Home: s.Home, PATH: s.PATH}
			cc := CheckContext{Contract: filepath.Join(root, "project/agent.yaml"), Cwd: filepath.Join(root, "project"), Tier: "landlock"}
			head := "version: 0\nname: parity\ncommand: [/bin/true]\ntier: landlock\n"
			corpus := []string{head, head + "extends: base\n", head + "fs:\n  write: [\"" + filepath.Join(root, "runtime/tego") + "/\"]\n", head + "fs:\n  write: [\"" + root + "/\"]\n", head + "exec:\n  allow: [no-such-parity-program]\n"}
			for i, text := range corpus {
				want := checkParity(ctx, s, cc, []byte(text))
				if i == 0 && (want.Error != "" || !want.OK) {
					t.Fatalf("healthy control did not compile: %+v", want)
				}
				var got parityOutput
				if err := pathcheck.Call(ctx, "test.caller-parity", parityInput{state, cc, []byte(text)}, &got); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("corpus %d helper differs from in-process:\ngot %+v\nwant %+v", i, got, want)
				}
				if name == "runtime" && i == 2 && (!strings.Contains(got.Error, "runtime directory") || got.OK) {
					t.Fatalf("runtime parent protection missing: %+v", got)
				}
			}
		})
	}
}

func mustSnapshot(t *testing.T, m *config.Machine) []byte {
	t.Helper()
	b, err := json.Marshal(m.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHelperPlanNewRuntimeRefusal(t *testing.T) {
	root := t.TempDir()
	runtime := filepath.Join(root, "runtime")
	project := filepath.Join(root, "project")
	for _, d := range []string{filepath.Join(runtime, "tego"), project} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XDG_RUNTIME_DIR", runtime)
	s := &Service{Machine: config.Builtin(), Ledger: filepath.Join(root, "ledger"), PATH: "/usr/bin:/bin"}
	plan, err := s.PlanNew(context.Background(), NewReq{Dir: project, Presets: []string{"no-secrets"}, Command: "/bin/true", Writes: []string{filepath.Join(runtime, "tego")}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.OK || !strings.Contains(strings.Join(plan.Diagnostics, "\n"), "runtime directory") {
		t.Fatalf("helper accepted caller runtime write: %+v", plan)
	}
}
