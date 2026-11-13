// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

// hostMounts is an ordinary systemd host's mount table, as /proc/self/mountinfo spells it: the root on a disk, the
// kernel's filesystems at their usual places, and tmpfs at /run, /tmp and /dev/shm.
var hostMounts = []string{
	"1 0 8:1 / / rw - ext4 /dev/sda1 rw",
	"20 1 0:22 / /proc rw - proc proc rw",
	"21 1 0:21 / /sys rw - sysfs sysfs rw",
	"22 21 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw",
	"23 1 0:5 / /dev rw - devtmpfs udev rw",
	"24 23 0:24 / /dev/pts rw - devpts devpts rw",
	"25 23 0:26 / /dev/shm rw - tmpfs tmpfs rw",
	"26 23 0:19 / /dev/mqueue rw - mqueue mqueue rw",
	"27 1 0:25 / /run rw - tmpfs tmpfs rw",
	"28 1 0:30 / /tmp rw - tmpfs tmpfs rw",
}

// mountLayout holds a full mount table and the exact additional refusals it must cause, given the compile's home
// and the contract's directory. A disappearing refusal is a regression, as is a new one.
type mountLayout struct {
	name     string
	lines    func(home, cwd string) []string
	refused  []string
	warned   []string
	accepted int
}

var mountLayouts = []mountLayout{
	{"ordinary host", func(string, string) []string { return slices.Clone(hostMounts) }, nil, nil, 19},
	{"/tmp holding a container's private proc and sysfs", func(string, string) []string {
		return append(slices.Clone(hostMounts), "40 28 0:60 / /tmp/ctr/rootfs/proc rw - proc proc rw", "41 28 0:61 / /tmp/ctr/rootfs/sys rw - sysfs sysfs rw")
	}, []string{"variant__grant-tmp"}, nil, 18},
	{"home holding a container rootfs with its proc", func(home, _ string) []string {
		m := filepath.Join(home, ".local/share/containers/storage/overlay/x/merged")
		return append(slices.Clone(hostMounts), "40 1 0:70 / "+m+" rw - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w",
			"41 40 0:71 / "+m+"/proc rw - proc proc rw")
	}, []string{"variant__grant-home"}, nil, 18},
	{"project tree holding a chroot with its proc", func(_, cwd string) []string {
		return append(slices.Clone(hostMounts), "40 1 0:72 / "+cwd+"/work/rootfs/proc rw - proc proc rw")
	}, []string{"examples__agents__custom-agent.yaml", "variant__grant-project"}, nil, 17},
	{"CI container with overlay root and unplaced host layers", func(home, _ string) []string {
		return containerOverlayMounts(home)
	}, nil, nil, 19},
	{"CI overlay root with workspace volumes", func(home, cwd string) []string {
		return append(containerOverlayMounts(home), "40 1 8:2 /output "+cwd+"/out rw - ext4 /dev/sdb1 rw", "41 1 8:2 /work "+cwd+"/work rw - ext4 /dev/sdb1 rw")
	}, nil, []string{
		"examples__agents__anthropic-sdk-python.yaml", "examples__agents__claude-code.yaml", "examples__agents__custom-agent.yaml",
		"examples__tests__agent.yaml", "internal__cli__agent.starter.yaml",
		"variant__bpflsm-open", "variant__cgroup-all", "variant__deny-list-exec", "variant__landlock-unix", "variant__reads-direct", "variant__grant-project",
	}, 19},
	{"CI overlay root with binary directory on a plain mount", func(home, _ string) []string {
		// The test's PATH holds every discovered tego and the place beside it for tego-control. Model replacing
		// their image directory with a plain mount, rather than leaving another discovered copy on the overlay.
		bin := filepath.Join(filepath.Dir(home), "bin")
		return append(containerOverlayMounts(home), "40 1 8:2 /usr/local/bin "+bin+" rw - ext4 /dev/sdb1 rw")
	}, nil, nil, 19},
	{"partial chroot whose root is not a mount point", func(home, cwd string) []string {
		// The root filesystem is omitted. Binaries and writable data still have
		// visible binds, so binary discovery alone cannot establish R10's floor.
		bin := filepath.Join(filepath.Dir(home), "bin")
		return []string{
			"40 99 8:1 /host/bin " + bin + " rw - ext4 disk rw",
			"41 99 8:1 /host/out " + cwd + "/out rw - ext4 disk rw",
			"42 99 8:1 /host/work " + cwd + "/work rw - ext4 disk rw",
		}
	}, []string{
		"examples__agents__anthropic-sdk-python.yaml", "examples__agents__claude-code.yaml", "examples__agents__custom-agent.yaml",
		"examples__tests__agent.yaml", "internal__cli__agent.starter.yaml",
		"preset__no-prod", "preset__no-secrets", "preset__repo-only-writes",
		"variant__bpflsm-open", "variant__cgroup-all", "variant__deny-list-exec", "variant__landlock-unix", "variant__reads-direct",
		"variant__grant-devshm", "variant__grant-home", "variant__grant-project", "variant__grant-tmp",
	}, nil, 2},
}

func containerOverlayMounts(home string) []string {
	// Docker does not mount /tmp separately by default. The fixture binary must be on the overlay root even
	// when this test's TMPDIR is /tmp; an unrelated overlay elsewhere does not exercise container compilation.
	lines := slices.Clone(hostMounts[:len(hostMounts)-1])
	layers := filepath.Join(home, "unplaced-host-overlay-layers")
	lines[0] = "1 0 0:73 / / rw - overlay overlay rw,lowerdir=" + layers + "/lower,upperdir=" + layers + "/upper,workdir=" + layers + "/work"
	return lines
}

// mountCompatBaseline fixes the input inventory and its probe-off outcomes. These are source/golden-derived
// exclusions, not failures the test may silently drop. Each class checks the stage and diagnostic as well as names.
var mountCompatBaseline = []struct {
	class, stage, code string
	names              []string
}{
	{"compiles", "", "", []string{
		"examples__agents__anthropic-sdk-python.yaml", "examples__agents__claude-code.yaml", "examples__agents__custom-agent.yaml",
		"examples__tests__agent.yaml", "internal__cli__agent.starter.yaml",
		"testdata__good__bom-crlf.yaml", "testdata__good__minimal.yaml",
		"preset__no-prod", "preset__no-secrets", "preset__repo-only-writes",
		"variant__bpflsm-open", "variant__cgroup-all", "variant__deny-list-exec", "variant__landlock-unix", "variant__reads-direct",
		"variant__grant-devshm", "variant__grant-home", "variant__grant-project", "variant__grant-tmp",
	}},
	{"non-contract YAML", "load", CodeSchema, []string{
		"examples__container__compose.yaml", "examples__container__config.yaml", "examples__lima__tego.yaml",
		"examples__prices.example.yaml", "examples__tests__verdicts.yaml",
	}},
	{"unfilled templates", "load", CodeSchema, []string{
		"examples__demo__contracts__claude-standin.yaml",
		"examples__supply-chain-demo__contracts__claude-code.yaml", "examples__supply-chain-demo__contracts__codex-chatgpt.yaml",
	}},
	{"missing paths", "compile", CodePathMissing, []string{
		"examples__agents__claude-agent-sdk.yaml", "examples__agents__codex-chatgpt.yaml", "examples__agents__codex.yaml",
		"examples__agents__retriever.yaml", "examples__container__hello.yaml",
		"examples__demo__contracts__always-on.yaml", "examples__demo__contracts__codex-chatgpt.yaml",
		"examples__demo__contracts__codex.yaml", "examples__demo__contracts__guarded.yaml",
		"testdata__good__aliases.yaml", "testdata__good__warnings-only.yaml",
	}},
	{"write grant contains contract", "compile", CodeContradiction, []string{
		"examples__agents__claude-code-interactive.yaml", "examples__demo__contracts__claude-code.yaml",
	}},
}

type mountCompatResult struct {
	stage, code, why string
	backingWarnings  int
	warnings         []Diagnostic
}

// mountCompatVariants are grants people write that the layouts meet: /tmp, the home, the project and /dev/shm.
var mountCompatVariants = map[string]string{
	"grant-tmp":     "fs: {write: [/tmp/]}\n",
	"grant-home":    "fs: {write: [\"~/.local/share/\"]}\n",
	"grant-project": "fs: {write: [./work/]}\n",
	"grant-devshm":  "fs: {write: [/dev/shm/]}\n",
}

// TestCompileMountLayoutsCompatibility asserts the repository contracts' probe-off baseline and every layout's
// exact additional refusals (ADR 0059). The table it logs (go test -v) is the report's compatibility measurement.
func TestCompileMountLayoutsCompatibility(t *testing.T) {
	checkMountLayoutsCompatibility(t, mountLayouts, false)
}

func checkMountLayoutsCompatibility(t *testing.T, layouts []mountLayout, binaryInHome bool) {
	dir := fixtureTempDir(t)
	home := filepath.Join(dir, "home")
	bin := filepath.Join(dir, "bin")
	if binaryInHome {
		bin = filepath.Join(home, ".local", "bin")
	}
	for _, d := range []string{filepath.Join(home, ".local", "share"), filepath.Join(home, ".tego"), bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	goldenBin(t, bin)
	contracts := liveOffContracts(t, dir)
	for _, p := range []string{"no-secrets", "no-prod", "repo-only-writes"} {
		vd := filepath.Join(dir, "preset-"+p)
		if err := os.MkdirAll(filepath.Join(vd, "src"), 0o755); err != nil {
			t.Fatal(err)
		}
		vp := filepath.Join(vd, "agent.yaml")
		if err := os.WriteFile(vp, []byte("version: 0\nname: p\ncommand: [python3]\nextends: [tego/"+p+"]\nfs: {write: [./src/]}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		contracts = append(contracts, goldenContract{name: "preset__" + p, path: vp})
	}
	for name, body := range mountCompatVariants {
		vd := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Join(vd, "work"), 0o755); err != nil {
			t.Fatal(err)
		}
		vp := filepath.Join(vd, "agent.yaml")
		if err := os.WriteFile(vp, []byte("version: 0\nname: v\ncommand: [python3]\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		contracts = append(contracts, goldenContract{name: "variant__" + name, path: vp})
	}
	machine, mds, err := config.LoadSources(config.Sources{}, home, 1000, config.TrustAbort)
	if err != nil {
		t.Fatalf("machine: %v %v", err, mds)
	}
	compile := func(c goldenContract, mi string) mountCompatResult {
		data, err := os.ReadFile(c.path)
		if err != nil {
			t.Fatal(err)
		}
		var ct *Contract
		var ds []Diagnostic
		for _, src := range []ProfileSource{dirSource{root: filepath.Join(repoRoot, "examples", "profiles")}, testProfiles(),
			(&ProfileChain{}).WithBuiltin(presets.Source{})} {
			if ct, ds, err = LoadBytes(c.path, data, src); err == nil {
				break
			}
		}
		stage := "load"
		if err == nil {
			stage = "compile"
			_, ds, err = Compile(ct, machine, WithCwd(filepath.Dir(c.path)), WithHome(home), WithPATH(bin), WithMountInfo(mi),
				WithResolver(goldenResolver{}), WithTiers(backend.Tiers()...), WithChainAnchor(filepath.Join(home, ".tego", "chain.log")),
				WithOwnBinaries(""), withInstallDirs(), withHostSocketProbe("", 4242), WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }))
		}
		if err == nil {
			n := 0
			for _, d := range ds {
				if d.Code == "overlay-backing-unknown" {
					n++
				}
			}
			return mountCompatResult{backingWarnings: n, warnings: ds}
		}
		for _, d := range ds {
			if d.Severity == SeverityError {
				return mountCompatResult{stage: stage, code: d.Code, why: d.Message}
			}
		}
		return mountCompatResult{stage: stage, why: err.Error()}
	}
	byName := make(map[string]goldenContract, len(contracts))
	for _, c := range contracts {
		if _, exists := byName[c.name]; exists {
			t.Fatalf("duplicate input %s", c.name)
		}
		byName[c.name] = c
	}
	var baseline []goldenContract
	for _, want := range mountCompatBaseline {
		t.Run("baseline/"+want.class, func(t *testing.T) {
			for _, name := range want.names {
				c, exists := byName[name]
				if !exists {
					t.Errorf("expected input %s is missing", name)
					continue
				}
				delete(byName, name)
				got := compile(c, "")
				if got.stage != want.stage || got.code != want.code {
					t.Errorf("%s: got %s [%s] %s; want %s [%s] (%s)", name, got.stage, got.code, got.why, want.stage, want.code, want.class)
				}
				if want.stage == "" {
					baseline = append(baseline, c)
				}
			}
		})
	}
	for name := range byName {
		t.Errorf("input %s has no expected probe-off outcome", name)
	}
	var table strings.Builder
	fmt.Fprintf(&table, "%d inputs: 19 compile without probing; 5 non-contract YAML files, 3 unfilled templates, 11 missing-path cases, 2 contradictions\n", len(contracts))
	fmt.Fprintf(&table, "%-52s %8s %8s %s\n", "layout", "baseline", "probe-on", "refused by the probe")
	for _, l := range layouts {
		on := 0
		totalWarnings := 0
		allWarnings := 0
		var refused, reasons, warned []string
		for _, c := range baseline {
			mi := filepath.Join(dir, "mountinfo")
			lines := l.lines(home, filepath.Dir(c.path))
			checkNoMountSiblings(t, l.name, lines)
			if err := os.WriteFile(mi, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := compile(c, mi); got.stage == "" {
				on++
				for _, d := range got.warnings {
					if d.Severity == SeverityWarning {
						allWarnings++
					}
				}
				if strings.Contains(l.name, "nspawn") && l.accepted == 19 {
					// Restoring ordinary compilation must add no warning beyond the
					// same table with only the unlinked-root rows removed.
					var warnings, baselineWarnings []string
					for _, d := range got.warnings {
						if d.Severity == SeverityWarning {
							warnings = append(warnings, d.Code+": "+d.Message)
							t.Logf("%s warning for %s [%s]: %s", l.name, c.name, d.Code, d.Message)
						}
					}
					var withoutUnlinked []string
					for _, row := range lines {
						m, ok := parseMountRecord(row)
						if ok && !strings.HasSuffix(m.root, "//deleted") {
							withoutUnlinked = append(withoutUnlinked, row)
						}
					}
					withoutPath := filepath.Join(dir, "without-unlinked")
					if err := os.WriteFile(withoutPath, []byte(strings.Join(withoutUnlinked, "\n")+"\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					for _, d := range compile(c, withoutPath).warnings {
						if d.Severity == SeverityWarning {
							baselineWarnings = append(baselineWarnings, d.Code+": "+d.Message)
						}
					}
					if !slices.Equal(warnings, baselineWarnings) {
						t.Errorf("%s: %s warning changes: %v; baseline %v", l.name, c.name, warnings, baselineWarnings)
					}
				}
				totalWarnings += got.backingWarnings
				wantCount := 0
				if slices.Contains(l.warned, c.name) {
					wantCount = 1
				}
				if binaryInHome && strings.HasPrefix(l.name, "home-") && (c.name == "examples__agents__claude-code.yaml" || c.name == "examples__agents__custom-agent.yaml") {
					wantCount = 2
				}
				if got.backingWarnings != wantCount {
					t.Errorf("%s: %s got %d backing warnings, want exactly %d", l.name, c.name, got.backingWarnings, wantCount)
				}
				if got.backingWarnings != 0 {
					warned = append(warned, c.name)
				}
			} else {
				if got.stage != "compile" || got.code != CodeContradiction {
					t.Errorf("%s: %s failed for %s [%s] %s; want a compile contradiction", l.name, c.name, got.stage, got.code, got.why)
				}
				refused = append(refused, c.name)
				reasons = append(reasons, c.name+" ("+shortWhy(got.why)+")")
			}
		}
		sort.Strings(warned)
		expectedWarnings := slices.Clone(l.warned)
		sort.Strings(expectedWarnings)
		if !slices.Equal(warned, expectedWarnings) {
			t.Errorf("%s: backing warnings for %v; want exactly %v", l.name, warned, expectedWarnings)
		}
		sort.Strings(refused)
		sort.Strings(reasons)
		want := slices.Clone(l.refused)
		sort.Strings(want)
		fmt.Fprintf(&table, "%-52s %8d %8d %s\n", l.name, len(baseline), on, strings.Join(reasons, "; "))
		fmt.Fprintf(&table, "  backing warnings (%d entries, %d contracts): %s\n", totalWarnings, len(warned), strings.Join(warned, ", "))
		fmt.Fprintf(&table, "  all warnings: %d\n", allWarnings)
		fmt.Fprintln(&table, "  ambiguous sibling groups: 0")
		if !slices.Equal(refused, want) {
			t.Errorf("%s: mount probe refused %v; want exactly %v", l.name, refused, want)
		}
		if on != l.accepted {
			t.Errorf("%s: %d compile; want exactly %d", l.name, on, l.accepted)
		}
	}
	t.Logf("mount-probe compatibility:\n%s", table.String())
}

// shortWhy is the part of a refusal that names what it reaches.
func shortWhy(why string) string {
	if i := strings.Index(why, " reaches "); i >= 0 {
		why = why[i+1:]
	}
	if i := strings.Index(why, ", a kernel control filesystem"); i >= 0 {
		why = why[:i]
	}
	if len(why) > 90 {
		why = why[:90] + "..."
	}
	return why
}

func TestCompileRuntimeMountLayoutsCompatibility(t *testing.T) {
	var layouts []mountLayout
	for _, name := range []string{"docker-small", "docker-many-layers", "podman-rootless-native", "containerd-ctr", "docker-containerd-store", "docker-containerd-store-many-layers", "podman-fuse-overlayfs", "home-gocryptfs", "home-ecryptfs"} {
		for _, volume := range []bool{false, true} {
			var warned []string
			if volume {
				warned = slices.Clone(mountLayouts[5].warned)
			}
			if strings.HasPrefix(name, "home-") {
				// Plain disk grants reach another mount from the encrypted home;
				// read-only, home and memory-filesystem grants do not warn (GAPS C65).
				warned = nil
				for _, c := range mountCompatBaseline[0].names {
					if c != "testdata__good__minimal.yaml" && c != "testdata__good__bom-crlf.yaml" && c != "variant__grant-home" && c != "variant__grant-tmp" && c != "variant__grant-devshm" {
						warned = append(warned, c)
					}
				}
			}
			layouts = append(layouts, mountLayout{name: fmt.Sprintf("%s volume=%v", name, volume), accepted: 19, warned: warned, lines: func(home, cwd string) []string {
				fixture := name
				if volume && !strings.HasPrefix(name, "home-") {
					fixture += "-volume"
				}
				host := filepath.Join(home, "absent-host")
				if strings.HasPrefix(name, "home-") {
					host = filepath.Join(filepath.Dir(home), "encrypted-backing")
					if err := os.MkdirAll(filepath.Join(host, map[string]string{"home-gocryptfs": "gocryptfs/cipher", "home-ecryptfs": "ecryptfs/.Private"}[name]), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				data := runtimeMountFixture(t, fixture, home, host)
				data = strings.ReplaceAll(data, " /work/out ", " "+cwd+"/out ")
				if strings.HasPrefix(name, "home-") {
					data = strings.Join(hostMounts, "\n") + "\n" + strings.Join(strings.Split(strings.TrimSuffix(data, "\n"), "\n")[1:], "\n") + "\n"
				}
				if volume {
					root, _ := parseMountLine(strings.SplitN(data, "\n", 2)[0])
					if strings.HasPrefix(name, "home-") {
						data += "9000 1 8:2 /output " + cwd + "/out rw - ext4 disk rw\n"
					}
					// Also put a workspace volume under the contract's relative work
					// grant. The actual capture's output bind is preserved above.
					data += "9001 " + root.id + " 253:1 /workspace " + cwd + "/work rw - ext4 /dev/vda1 rw\n"
				}
				return strings.Split(strings.TrimSuffix(data, "\n"), "\n")
			}})
		}
	}
	checkMountLayoutsCompatibility(t, layouts, true)
}
