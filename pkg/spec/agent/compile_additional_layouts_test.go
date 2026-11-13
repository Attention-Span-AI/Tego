// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

// TestCompileAdditionalCapturedMountTables retains additional captures distinct from the seven chroot fixtures.
// Only the account name and the project bind's namespace mount point change; root fields and graph edges stay intact.
func TestCompileAdditionalCapturedMountTables(t *testing.T) {
	var layouts []mountLayout
	for _, name := range []string{"bwrap-user-tmpfs", "bwrap-user-wholeroot", "guest-host", "unshare", "nspawn-selfbind"} {
		data, err := os.ReadFile(filepath.Join("testdata", "additional-mountinfo", name+".mountinfo"))
		if err != nil {
			t.Fatal(err)
		}
		rows := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
		layouts = append(layouts, mountLayout{name: "captured " + name, accepted: 19, lines: func(_, cwd string) []string {
			out := make([]string, 0, len(rows))
			for _, row := range rows {
				fields := strings.Split(row, " ")
				if len(fields) > 4 && fields[4] == "/home/runner/proj" {
					fields[4] = cwd
				}
				out = append(out, strings.Join(fields, " "))
			}
			return out
		}})
	}
	checkMountLayoutsCompatibility(t, layouts, false)
}

// TestCompileBuiltinDenyReadHostLayouts replays the same six modeled layouts as the read-denial alias test through
// the 19 ordinary contracts. Home symlinks and project ancestry are real fixture paths; no extra mount is invented
// to move a project out of its modeled filesystem. The binary stays under the model's system root at usr/local/bin.
func TestCompileBuiltinDenyReadHostLayouts(t *testing.T) {
	var cases []struct {
		Name, Home, Project, HomeTarget string
	}
	data, err := os.ReadFile("testdata/mountcompat/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 6 {
		t.Fatalf("got %d host layouts, want six", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			root := fixtureTempDir(t)
			at := func(p string) string { return filepath.Join(root, p) }
			home, project, bin := at(tc.Home), at(tc.Project), at("/usr/local/bin")
			if tc.HomeTarget != "" {
				if err := os.MkdirAll(at(tc.HomeTarget), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(home), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(at(tc.HomeTarget), home); err != nil {
					t.Fatal(err)
				}
			}
			for _, dir := range []string{project, bin, filepath.Join(home, ".local/share"), filepath.Join(home, ".tego")} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			goldenBin(t, bin)
			contracts := liveOffContracts(t, project)
			for _, preset := range []string{"no-prod", "no-secrets", "repo-only-writes"} {
				contracts = append(contracts, additionalLayoutContract(t, project, "preset-"+preset, "preset__"+preset,
					"extends: [tego/"+preset+"]\nfs: {write: [./src/]}\n"))
			}
			for name, body := range mountCompatVariants {
				contracts = append(contracts, additionalLayoutContract(t, project, name, "variant__"+name, body))
			}
			byName := make(map[string]goldenContract, len(contracts))
			for _, c := range contracts {
				if _, exists := byName[c.name]; exists {
					t.Fatalf("duplicate input %s", c.name)
				}
				byName[c.name] = c
			}
			machine, mds, err := config.LoadSources(config.Sources{}, home, 1000, config.TrustAbort)
			if err != nil {
				t.Fatalf("machine: %v %v", err, mds)
			}
			data, err := os.ReadFile(filepath.Join("testdata/mountcompat", tc.Name+".mountinfo"))
			if err != nil {
				t.Fatal(err)
			}
			mi := filepath.Join(root, "mountinfo")
			rows := strings.ReplaceAll(string(data), "{{ROOT}}", root)
			checkNoMountSiblings(t, tc.Name, strings.Split(strings.TrimSuffix(rows, "\n"), "\n"))
			if err := os.WriteFile(mi, []byte(rows), 0o600); err != nil {
				t.Fatal(err)
			}
			accepted, warnings, allWarnings := 0, 0, 0
			for _, name := range mountCompatBaseline[0].names {
				c, exists := byName[name]
				if !exists {
					t.Fatalf("expected input %s is missing", name)
				}
				// Repository contracts must also live on the modeled project filesystem. Copy their fixture
				// siblings so relative deny_read/watch paths retain their source behavior after relocation.
				if !isAncestorOrSelf(project, c.path) {
					dir := filepath.Join(project, name)
					if err := os.CopyFS(dir, os.DirFS(filepath.Dir(c.path))); err != nil {
						t.Fatal(err)
					}
					c.path = filepath.Join(dir, filepath.Base(c.path))
				}
				data, err := os.ReadFile(c.path)
				if err != nil {
					t.Fatal(err)
				}
				var ct *Contract
				var ds []Diagnostic
				for _, src := range []ProfileSource{dirSource{root: filepath.Join(repoRoot, "examples/profiles")}, testProfiles(),
					(&ProfileChain{}).WithBuiltin(presets.Source{})} {
					ct, ds, err = LoadBytes(c.path, data, src)
					if err == nil {
						break
					}
				}
				if err != nil {
					t.Fatalf("%s: load: %v %v", name, err, ds)
				}
				compile := func(mountinfo string) ([]Diagnostic, error) {
					_, diagnostics, err := Compile(ct, machine, WithCwd(filepath.Dir(c.path)), WithHome(home), WithPATH(bin), WithMountInfo(mountinfo),
						WithResolver(goldenResolver{}), WithTiers(backend.Tiers()...), WithChainAnchor(filepath.Join(home, ".tego/chain.log")),
						WithOwnBinaries(""), withInstallDirs(), withHostSocketProbe("", 4242),
						WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }))
					return diagnostics, err
				}
				if ds, err := compile(""); err != nil {
					t.Fatalf("%s: relocated probe-off baseline: %v %v", name, err, ds)
				}
				ds, err = compile(mi)
				if err != nil {
					t.Errorf("%s: compile: %v %v", name, err, ds)
					continue
				}
				accepted++
				count := 0
				for _, d := range ds {
					if d.Severity == SeverityWarning {
						allWarnings++
					}
					if d.Code == CodeOverlayBackingUnknown {
						count++
					}
				}
				wantWarnings := 0
				if (tc.Name == "docker" || tc.Name == "toolbox") && name != "testdata__good__minimal.yaml" &&
					name != "testdata__good__bom-crlf.yaml" && name != "variant__grant-tmp" && name != "variant__grant-devshm" {
					wantWarnings = 1
					if name == "examples__agents__claude-code.yaml" || name == "examples__agents__custom-agent.yaml" {
						wantWarnings = 2
					}
				}
				if count != wantWarnings {
					t.Errorf("%s: %d backing warnings, want %d", name, count, wantWarnings)
				}
				warnings += count
			}
			if accepted != 19 {
				t.Errorf("%d contracts compile, want 19", accepted)
			}
			t.Logf("mount-probe compatibility: modeled %s: %d/19 accepted; %d backing warnings; %d all warnings", tc.Name, accepted, warnings, allWarnings)
			t.Log("ambiguous sibling groups: 0")
		})
	}
}

func additionalLayoutContract(t *testing.T, project, dirName, name, body string) goldenContract {
	t.Helper()
	dir := filepath.Join(project, dirName)
	for _, child := range []string{"src", "work"} {
		if err := os.MkdirAll(filepath.Join(dir, child), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, fmt.Appendf(nil, "version: 0\nname: mount-layout\ncommand: [python3]\n%s", body), 0o600); err != nil {
		t.Fatal(err)
	}
	return goldenContract{name: name, path: path}
}

// TestCompileRemainingContainerMountTables completes the 19-contract replay of the runtime fixtures, including
// the complete host snapshots. A host binary stays on the captured host disk; unrelated runtime storage is moved
// as a whole, including /data's holding mount where the FUSE store is on the guest's second disk.
func TestCompileRemainingContainerMountTables(t *testing.T) {
	var layouts []mountLayout
	for _, name := range []string{"docker-many-layers-70", "containerd-ctr-many-layers", "containerd-ctr-many-layers-volume",
		"podman-rootless-native-rm", "synthetic-fuse-overlayfs", "overlay-mixed-relative"} {
		var warned []string
		if strings.HasSuffix(name, "-volume") {
			warned = append(warned, mountLayouts[5].warned...)
		}
		layouts = append(layouts, mountLayout{name: name, accepted: 19, warned: warned, lines: func(home, cwd string) []string {
			data := runtimeMountFixture(t, name, home, filepath.Join(home, "absent-host"))
			data = strings.ReplaceAll(data, " /work/out ", " "+cwd+"/out ")
			if strings.HasSuffix(name, "-volume") {
				root, ok := parseMountLine(strings.SplitN(data, "\n", 2)[0])
				if !ok {
					t.Fatal("missing runtime root mount")
				}
				// Match the original compatibility replay's additional relative-workspace bind.
				data += "9001 " + root.id + " 253:1 /workspace " + cwd + "/work rw - ext4 /dev/vda1 rw\n"
			}
			return strings.Split(strings.TrimSuffix(data, "\n"), "\n")
		}})
	}
	for _, name := range []string{"docker-small", "docker-containerd-store", "containerd-ctr", "podman-rootless-native", "podman-fuse-overlayfs"} {
		input, err := containerMountFixtures.ReadFile("testdata/container-mountinfo/" + name + ".hostfull.mountinfo")
		if err != nil {
			t.Fatal(err)
		}
		layouts = append(layouts, mountLayout{name: "captured host " + name, accepted: 19, lines: func(home, _ string) []string {
			storage := filepath.Join(filepath.Dir(home), "host-storage")
			data := strings.NewReplacer("/home/runner", home, "/var/lib/docker", storage+"/docker",
				"/var/lib/containerd", storage+"/containerd", "/data", storage+"/data").Replace(string(input))
			return strings.Split(strings.TrimSuffix(data, "\n"), "\n")
		}})
	}
	t.Run("runtime-and-host", func(t *testing.T) {
		checkMountLayoutsCompatibility(t, layouts, false)
	})
	t.Run("nonpath-fuse-home", func(t *testing.T) {
		var warned []string
		for _, name := range mountCompatBaseline[0].names {
			if name != "testdata__good__minimal.yaml" && name != "testdata__good__bom-crlf.yaml" &&
				name != "variant__grant-home" && name != "variant__grant-tmp" && name != "variant__grant-devshm" {
				warned = append(warned, name)
			}
		}
		checkMountLayoutsCompatibility(t, []mountLayout{{name: "home-fuse-nonpath", accepted: 19, warned: warned,
			lines: func(home, _ string) []string {
				data := runtimeMountFixture(t, "home-fuse-nonpath", home, filepath.Join(home, "absent-host"))
				// Keep the common ordinary host's kernel and memory mounts, as in the other encrypted-home rows.
				data = strings.Join(hostMounts, "\n") + "\n" + strings.Join(strings.Split(strings.TrimSuffix(data, "\n"), "\n")[1:], "\n") + "\n"
				return strings.Split(strings.TrimSuffix(data, "\n"), "\n")
			}}}, true)
	})
}
