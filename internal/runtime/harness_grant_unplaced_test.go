// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/adapters"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestHarnessUnplacedBackingDoesNotRefuseRun replays captured tables through Run and the product's provisioner
// registry for every harness kind. Claude Code (also detected from auto) needs an exact-argv hook grant, reaches
// hookScan.under, and loses only the provision with its warning. This build has no Codex or generic provisioner;
// none skips provisioning altogether. The backend stops before any child or kernel enforcement starts.
func TestHarnessUnplacedBackingDoesNotRefuseRun(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher makes no runtime directory")
	}
	for _, layout := range []struct{ name, unplaced string }{
		{"docker-many-layers", "overlay (layers named relative to a folder the mount table does not record)"},
		{"podman-fuse-overlayfs", "fuse.fuse-overlayfs"},
	} {
		t.Run(layout.name, func(t *testing.T) {
			input, err := os.ReadFile(filepath.Join("..", "..", "pkg", "spec", "agent", "testdata", "container-mountinfo", layout.name+".mountinfo"))
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range harness.Names() {
				t.Run(string(name), func(t *testing.T) {
					t.Setenv("XDG_RUNTIME_DIR", privateTempDir(t))
					m, _, root := startupFixture(t)
					commandName := map[harness.Name]string{harness.Auto: "claude", harness.ClaudeCode: "claude", harness.Codex: "codex", harness.Generic: "agent", harness.None: "sh"}[name]
					out, command := filepath.Join(root, "out"), filepath.Join(root, commandName)
					if err := os.Mkdir(out, 0o700); err != nil {
						t.Fatal(err)
					}
					copyFile(t, "/bin/sh", command)
					exe := testExe(t)
					table, err := agent.ParseMountTableStrict(input)
					if err != nil {
						t.Fatalf("the captured table must parse strictly: %v", err)
					}
					if fm := table.Of(exe); !fm.Held || fm.Unmapped != layout.unplaced {
						t.Fatalf("the actual hook executable must lie on the captured unplaced root: %+v", fm)
					}
					mountinfo := filepath.Join(root, "mountinfo")
					if err := os.WriteFile(mountinfo, input, 0o600); err != nil {
						t.Fatal(err)
					}
					body := fmt.Sprintf("version: 0\nname: unplaced-hook\ncommand: [%q]\nharness: %s\ntier: landlock\ncapture: off\nexec: {allow: [%q]}\nfs: {write: [%q]}\n", command, name, command, out)
					ct, ds, err := agent.LoadBytes(filepath.Join(root, "agent.yaml"), []byte(body), nil)
					if err != nil {
						t.Fatalf("load: %v %v", err, ds)
					}
					rt, ds, err := agent.Compile(ct, m, agent.WithCwd(root), agent.WithHome(root), agent.WithPATH("/usr/bin:/bin"),
						agent.WithOwnBinaries(exe), agent.WithMountInfo(mountinfo), agent.Offline())
					if err != nil {
						t.Fatalf("compile: %v %v", err, ds)
					}
					var scans, lookups, provisions int
					var warned []string
					h := hookHost{block: fakeBlock(t), mounts: func() ([]byte, error) {
						scans++
						return input, nil
					}}
					b := &preparedTable{}
					_, err = Run(context.Background(), rt, []string{command}, Deps{
						Config: m, Cgroups: &fakeCgroups{root: t.TempDir()}, Enforce: b, Cwd: root, Environ: []string{}, hookHost: &h,
						Harness: func(resolved harness.Name) Provisioner {
							lookups++
							if want := name.Resolve(command); resolved != want {
								t.Fatalf("provisioner lookup %s, want %s", resolved, want)
							}
							p := adapters.For(resolved)
							if p == nil {
								return nil
							}
							return observedProductProvisioner{actual: p, provisioned: func() { provisions++ }}
						},
						Warn: func(code, what string) { warned = append(warned, code+": "+what) },
					})
					if !errors.Is(err, errStopAtPrepare) || b.got == nil {
						t.Fatalf("Run did not reach enforcement after harness provisioning: %v", err)
					}
					needsHook := name == harness.Auto || name == harness.ClaudeCode
					if needsHook {
						if lookups != 1 || provisions != 1 || scans != 1 {
							t.Fatalf("product hook scan not reached: lookups=%d provisions=%d mount reads=%d, want 1 each", lookups, provisions, scans)
						}
						if len(warned) != 1 || !strings.HasPrefix(warned[0], WarnHarnessHookRefused+": harness claude-code is not provisioned:") ||
							!strings.Contains(warned[0], "harness-hook-writable, rule exec.harness-hook:") ||
							!strings.Contains(warned[0], exe+" lies on "+layout.unplaced+", which shows another tree's files by names the mount table does not give") ||
							!strings.HasSuffix(warned[0], "the agent learns of refusals through TEGO_REASON only") {
							t.Fatalf("hook-scan warning = %q, want one naming the captured unplaced backing", warned)
						}
					} else {
						wantLookups := 1
						if name == harness.None {
							wantLookups = 0
						}
						if lookups != wantLookups || provisions != 0 || scans != 0 || len(warned) != 0 {
							t.Fatalf("no product hook: lookups=%d provisions=%d mount reads=%d warnings=%q", lookups, provisions, scans, warned)
						}
					}
					if b.got.HarnessHookRule() != "" {
						t.Fatal("Prepare received an automatic hook grant despite unplaced backing")
					}
					for _, rule := range b.got.FS {
						if rule.Runtime == agent.HarnessStateGrant {
							t.Fatal("Prepare received a hook-state grant despite dropped provision")
						}
					}
				})
			}
		})
	}
}

// observedProductProvisioner counts calls while preserving the product provisioner's bytes and decisions.
type observedProductProvisioner struct {
	actual      Provisioner
	provisioned func()
}

func (p observedProductProvisioner) Provision(run harness.Run) (harness.Provision, error) {
	p.provisioned()
	return p.actual.Provision(run)
}

// TestHarnessUnplacedBackingOnlyDropsNeededGrant pins the scope of the separate ADR 0064 scan. Its strict backing
// rule declines a new exact-argv hook grant; a nil hook or a hook admitted by the contract never invokes the scan.
// provisionHarness records such a declined grant and returns nil (TestHarnessHookWritableIsNotGranted).
func TestHarnessUnplacedBackingOnlyDropsNeededGrant(t *testing.T) {
	for _, kind := range []string{"relative-overlay", "fuse.bindfs", "ecryptfs"} {
		t.Run(kind, func(t *testing.T) {
			exe, out, table := unplacedHookLayout(t, t.TempDir(), kind)
			ct := harnessContract(harness.ClaudeCode, &agent.ExecSection{Allow: []string{"/bin/sh"}})
			ct.FS = &agent.FSSection{Write: []string{out}}
			rt := compileTable(t, ct)
			hook := &harness.Hook{Argv: []string{exe, "hook", "claude-code", "--reason", "/run/r/last-refusal.json"}}
			h := onTable(fakeBlock(t), table)
			d := admitHook(rt, backend.TierLandlock, exe, hook, h)
			if d.Granted || d.Why != record.HarnessWhyHookWritable || d.Table != rt || !strings.Contains(d.Detail, "mount table does not give") {
				t.Fatalf("needed hook grant: %+v, want only the automatic grant declined for unplaced backing", d)
			}
			h.mounts = func() ([]byte, error) {
				t.Fatal("ordinary run or already-admitted hook read the hook-grant mount table")
				return nil, os.ErrPermission
			}
			if d := admitHook(rt, backend.TierLandlock, exe, nil, h); d.Why != "" || d.Granted || d.Table != rt {
				t.Fatalf("no hook: %+v", d)
			}
			allowed := compileTable(t, harnessContract(harness.ClaudeCode, nil))
			if d := admitHook(allowed, backend.TierLandlock, exe, hook, h); d.Why != "" || d.Granted || d.Table != allowed {
				t.Fatalf("hook admitted by the contract: %+v", d)
			}
		})
	}
}

// unplacedHookLayout supplies a synthetic mount namespace whose binary lies on unplaced backing and whose write
// grant lies outside it. The source folders are real directories, as an encrypted home's lower or cipher folder is.
func unplacedHookLayout(t *testing.T, root, kind string) (exe, out, table string) {
	t.Helper()
	merged, backing := filepath.Join(root, "merged"), filepath.Join(root, "cipher")
	exe, out = filepath.Join(merged, "bin", "tego"), filepath.Join(root, "out")
	for _, dir := range []string{filepath.Dir(exe), backing, out} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(t, "/bin/true", exe)
	row := "3 1 0:51 / " + merged + " rw - " + kind + " " + backing + " rw\n"
	if kind == "relative-overlay" {
		row = "3 1 0:51 / " + merged + " rw - overlay overlay rw,lowerdir=l/first:l/second\n"
	}
	return exe, out, rootMount + row
}
