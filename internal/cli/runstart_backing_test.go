// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// These checks stop at the real run-start compilation. The injected compiler
// appends only a mount snapshot; anchorCompileOptions still supplies the binary.
type runMountFixture struct {
	root, home, bin, exe, out, alias, contract, mountinfo string
	machine                                               *config.Machine
	diagnostics                                           []agent.Diagnostic
}

func newRunMountFixture(t *testing.T) *runMountFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &runMountFixture{root: root, home: filepath.Join(root, "home"), out: filepath.Join(root, "output"),
		alias: filepath.Join(root, "protected-alias"), contract: filepath.Join(root, "agent.yaml"), mountinfo: filepath.Join(root, "mountinfo")}
	f.bin = filepath.Join(f.home, ".local", "bin")
	f.exe = filepath.Join(f.bin, "tego")
	for _, path := range []string{f.bin, f.alias, filepath.Join(f.out, "a"), filepath.Join(f.out, "b")} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.exe, []byte("not run\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", f.bin)
	f.machine = config.Builtin()
	f.machine.Home = f.home
	f.machine.LedgerRoot = config.Setting[string]{Value: filepath.Join(f.home, ".tego", "runs")}
	useAnchor(t, filepath.Join(f.home, ".tego", "chain.log"))
	oldCompile, oldExecutable := compileRunContract, executable
	compileRunContract = func(c *agent.Contract, m *config.Machine, opts ...agent.CompileOption) (*agent.RuleTable, []agent.Diagnostic, error) {
		rt, ds, err := agent.Compile(c, m, append(opts, agent.WithMountInfo(f.mountinfo))...)
		f.diagnostics = ds
		return rt, ds, err
	}
	executable = func() (string, error) { return f.exe, nil }
	t.Cleanup(func() { compileRunContract, executable = oldCompile, oldExecutable })
	return f
}

func (f *runMountFixture) compile(t *testing.T, field string, grants []string, table string) (int, string) {
	t.Helper()
	var quoted []string
	for _, p := range grants {
		quoted = append(quoted, fmt.Sprintf("%q", p))
	}
	body := "version: 0\nname: run-mount\ncommand: [/usr/bin/true]\nfs: {" + field + ": [" + strings.Join(quoted, ", ") + "]}\nenv: {pass: []}\n"
	if err := os.WriteFile(f.contract, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// Attach only the auxiliary tests' synthetic child rows to the captured
	// root; their old parent 1 was specific to the former synthetic tables.
	if root := strings.SplitN(table, " ", 2)[0]; root != "1" {
		for _, id := range []string{"40", "41"} {
			table = strings.ReplaceAll(table, "\n"+id+" 1 ", "\n"+id+" "+root+" ")
		}
	}
	if err := os.WriteFile(f.mountinfo, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	f.diagnostics = nil
	var stderr bytes.Buffer
	rt, _, _, code := compileForRun(t.Context(), runOptions{contract: f.contract, offline: true}, f.machine, &stderr)
	if (rt != nil) != (code == identity.ExitOK) {
		t.Fatalf("run-start exit %d and table presence disagree: %s", code, stderr.String())
	}
	return code, stderr.String()
}

func runMountWarning(field, raw, mount, reason string) string {
	advice := "do not mount the runtime's storage or the whole host filesystem at a place a contract may write"
	if reason != "" && reason != ", because the layers are named relative to a folder the mount table does not record" {
		advice = "keep the folder that stores the encrypted or mirrored files out of every write grant"
	}
	return fmt.Sprintf("fs.%s %q reaches mount %s and Tego cannot tell whether that mount shows the folders holding its protected files%s; %s", field, raw, mount, reason, advice)
}

func (f *runMountFixture) wantWarnings(t *testing.T, output string, want []string) {
	t.Helper()
	var got []string
	for _, d := range f.diagnostics {
		if d.Code == agent.CodeOverlayBackingUnknown {
			// TestCompileBackingWarningNamesProtectedFile pins the affected file names.
			// These run-start cases pin the full grant, mount, reason and advice prefix.
			prefix, _, _ := strings.Cut(d.Message, "; protected files: ")
			got = append(got, prefix)
			if d.Severity != agent.SeverityWarning || !strings.Contains(output, d.Message+" ["+agent.CodeOverlayBackingUnknown+"]") {
				t.Errorf("run-start did not print its backing warning: %+v\n%s", d, output)
			}
		}
	}
	if !slices.Equal(got, want) || strings.Count(output, "["+agent.CodeOverlayBackingUnknown+"]") != len(want) {
		t.Errorf("run-start backing warnings = %q; want exactly %q\n%s", got, want, output)
	}
}

// Mount is a shared diagnostic code. Compare each advisory kind's complete
// subjects and words, including notes that a quiet run must leave out.
func (f *runMountFixture) wantMountAdvisories(t *testing.T, output, kind string, want []string, informational bool) {
	t.Helper()
	var got []string
	for _, d := range f.diagnostics {
		if d.Code != agent.CodeMountWarning {
			continue
		}
		gotKind := "grant filesystem"
		switch {
		case strings.Contains(d.Message, " reaches FUSE mount "):
			gotKind = "FUSE reach"
		case strings.HasPrefix(d.Message, "name entries are scoped to "):
			gotKind = "name scope"
		}
		if gotKind != kind {
			continue
		}
		got = append(got, d.Message)
		if d.Severity != agent.SeverityWarning || d.Informational() != informational {
			t.Errorf("%s advisory has wrong severity or note status: %+v", kind, d)
		}
		wantPrinted := 1
		if informational {
			wantPrinted = 0
		}
		if n := strings.Count(output, d.Message+" ["+agent.CodeMountWarning+"]"); n != wantPrinted {
			t.Errorf("%s advisory %q printed %d times, want %d\n%s", kind, d.Message, n, wantPrinted, output)
		}
	}
	want = slices.Clone(want)
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("%s advisories = %q; want exactly %q\n%s", kind, got, want, output)
	}
}

func (f *runMountFixture) wantRefused(t *testing.T, field, grant, table, why string) {
	t.Helper()
	code, out := f.compile(t, field, []string{grant}, table)
	if code != identity.ExitLauncher || !strings.Contains(out, "["+agent.CodeContradiction+"]") || !strings.Contains(out, why) {
		t.Fatalf("run-start admitted fs.%s %q or lost refusal %q: exit %d\n%s", field, grant, why, code, out)
	}
}

func runMountRuntimeTable(t *testing.T, f *runMountFixture, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "pkg", "spec", "agent", "testdata", "container-mountinfo", name+".mountinfo"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, row := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if !strings.HasPrefix(row, "#") {
			rows = append(rows, row)
		}
	}
	return strings.NewReplacer("@HOST@", filepath.Join(f.root, "absent-host"), "@HOME@", f.home,
		"/var/lib/docker", filepath.Join(f.root, "absent-host", "docker"),
		"/var/lib/containerd", filepath.Join(f.root, "absent-host", "containerd"),
		"/home/runner/.local/share/containers/storage", filepath.Join(f.root, "absent-host", "podman")).Replace(strings.Join(rows, "\n") + "\n")
}

func TestRunStartContainerRuntimeMountTables(t *testing.T) {
	// Keep the native auto reach: the host is non-root at landlock, while the
	// root suites' tagged builds reach cgroup or bpflsm according to the boot.
	native := builtTiers()
	for _, tc := range []struct {
		name       string
		tiers      []backend.Tier
		nameScopes bool
	}{
		{"native", native, slices.Contains(native, backend.TierCgroup) || slices.Contains(native, backend.TierBPFLSM)},
		{"non-root-landlock", []backend.Tier{backend.TierLandlock}, false},
		{"root-cgroup", []backend.Tier{backend.TierLandlock, backend.TierCgroup}, true},
		{"root-bpflsm", []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Describe AutoTiers' compiler input for each environment, without a
			// contract or CLI tier pin. Native still reads the real build and uid.
			if tc.name != "native" {
				buildsTiers(t, tc.tiers...)
			}
			t.Logf("uid=%d auto tiers=%v; FUSE name-scope advisories=%v", os.Geteuid(), builtTiers(), tc.nameScopes)
			testRunStartContainerRuntimeMountTables(t, tc.nameScopes)
		})
	}
}

func testRunStartContainerRuntimeMountTables(t *testing.T, nameScopes bool) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"docker-small", "docker-small-volume", "docker-many-layers-70", "docker-many-layers", "docker-many-layers-volume",
		"docker-containerd-store", "docker-containerd-store-volume", "docker-containerd-store-many-layers", "docker-containerd-store-many-layers-volume",
		"containerd-ctr", "containerd-ctr-volume", "containerd-ctr-many-layers", "containerd-ctr-many-layers-volume",
		"podman-rootless-native", "podman-rootless-native-volume", "podman-rootless-native-rm",
		"podman-fuse-overlayfs", "podman-fuse-overlayfs-volume", "synthetic-fuse-overlayfs",
	} {
		t.Run(name, func(t *testing.T) {
			f := newRunMountFixture(t)
			table := strings.ReplaceAll(runMountRuntimeTable(t, f, name), " /work/out ", " "+f.out+" ")
			root := strings.Split(strings.SplitN(table, "\n", 2)[0], " ")
			reason := ""
			if strings.Contains(name, "many-layers") {
				reason = ", because the layers are named relative to a folder the mount table does not record"
			}
			if strings.Contains(name, "fuse-overlayfs") {
				reason = ", because fuse.fuse-overlayfs does not establish which folder holds the files it shows"
			}
			if name == "synthetic-fuse-overlayfs" {
				reason = ", because fuse.overlayfs does not establish which folder holds the files it shows"
			}
			for _, field := range []string{"write", "ask"} {
				t.Run(field, func(t *testing.T) {
					grant := f.out + "/"
					code, out := f.compile(t, field, []string{grant}, table)
					if code != identity.ExitOK {
						t.Fatalf("ordinary run-start grant refused: exit %d\n%s", code, out)
					}
					var want []string
					if strings.HasSuffix(name, "-volume") {
						want = []string{runMountWarning(field, grant, f.out, reason)}
					}
					f.wantWarnings(t, out, want)
					volume := strings.HasSuffix(name, "-volume")
					fstype := root[len(root)-3]
					fuse := strings.HasPrefix(fstype, "fuse.")
					var metadata, reach, scopes []string
					switch {
					case volume:
						metadata = []string{f.out + " is a mount point (ext4): the rule applies to the mounted filesystem's root"}
					case fuse:
						reach = []string{fmt.Sprintf("fs.%s %q reaches FUSE mount /: compile cannot tell whether a different filesystem exposes protected data here", field, grant)}
					default:
						metadata = []string{f.out + " is on an overlay filesystem: rules on its upper or lower layers never apply to the merged tree"}
					}
					if fuse && nameScopes {
						for _, scope := range []string{cwd, f.root} {
							scopes = append(scopes, fmt.Sprintf("name entries are scoped to %s, on %s, which gives one file other spellings than ASCII case: a file reached by another spelling of a covered name is not covered", scope, fstype))
						}
					}
					f.wantMountAdvisories(t, out, "grant filesystem", metadata, volume)
					f.wantMountAdvisories(t, out, "FUSE reach", reach, false)
					f.wantMountAdvisories(t, out, "name scope", scopes, false)
					f.wantRefused(t, field, f.bin+"/", table, "the tego binary")
					alias := table + fmt.Sprintf("9000 %s %s %s %s rw - %s %s %s\n", root[0], root[2], f.bin, f.alias, root[len(root)-3], root[len(root)-2], root[len(root)-1])
					f.wantRefused(t, field, f.alias+"/", alias, "the tego binary")
				})
			}
		})
	}
}

func TestRunStartCapturedHostFileBinds(t *testing.T) {
	for _, name := range []string{"docker-small", "docker-many-layers", "docker-containerd-store-many-layers", "podman-rootless-native", "podman-fuse-overlayfs"} {
		t.Run(name, func(t *testing.T) {
			f := newRunMountFixture(t)
			etc := filepath.Join(f.out, "etc")
			if err := os.Mkdir(etc, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, file := range []string{"hosts", "resolv.conf", "hostname"} {
				if err := os.WriteFile(filepath.Join(etc, file), []byte("config"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			table := strings.ReplaceAll(runMountRuntimeTable(t, f, name), " /etc/", " "+etc+"/")
			reason := ""
			if strings.Contains(name, "many-layers") {
				reason = ", because the layers are named relative to a folder the mount table does not record"
			}
			if name == "podman-fuse-overlayfs" {
				reason = ", because fuse.fuse-overlayfs does not establish which folder holds the files it shows"
			}
			for _, field := range []string{"write", "ask"} {
				for _, grant := range []string{etc + "/", filepath.Join(etc, "hosts")} {
					code, out := f.compile(t, field, []string{grant}, table)
					if code != identity.ExitOK {
						t.Fatalf("ordinary file-bind grant refused: exit %d\n%s", code, out)
					}
					// Captured tables cannot establish live mount IDs for these fixture files.
					// Docker's ext4 binds keep one warning until statx proves identity; Podman's
					// tmpfs binds stay quiet under C65's memory rule. Agent tests replay statx IDs;
					// verification of the real file binds is owed in a guest.
					mount := filepath.Join(etc, "resolv.conf")
					if grant == filepath.Join(etc, "hosts") {
						mount = grant
					}
					var want []string
					if !strings.HasPrefix(name, "podman-") {
						want = []string{runMountWarning(field, grant, mount, reason)}
					}
					f.wantWarnings(t, out, want)
				}
				layers := f.machine.Layers
				f.machine.Layers = append([]string{filepath.Join(etc, "tego", "config.yaml")}, layers...)
				f.wantRefused(t, field, etc+"/", table, "the machine config")
				f.machine.Layers = layers
				var rows []string
				for row := range strings.SplitSeq(strings.TrimSuffix(table, "\n"), "\n") {
					if strings.Split(row, " ")[4] != filepath.Join(etc, "hosts") {
						rows = append(rows, row)
					}
				}
				root := strings.Split(rows[0], " ")
				alias := strings.Join(rows, "\n") + fmt.Sprintf("\n9000 %s %s %s %s rw - %s %s %s\n", root[0], root[2], f.exe, filepath.Join(etc, "hosts"), root[len(root)-3], root[len(root)-2], root[len(root)-1])
				f.wantRefused(t, field, etc+"/", alias, "the tego binary")
				f.wantRefused(t, field, filepath.Join(etc, "hosts"), alias, "the tego binary")
			}
		})
	}
}

func TestRunStartEncryptedHomeMountTables(t *testing.T) {
	for _, tc := range []struct{ fixture, fstype string }{{"home-gocryptfs", "fuse.gocryptfs"}, {"home-ecryptfs", "ecryptfs"}} {
		t.Run(tc.fixture, func(t *testing.T) {
			f := newRunMountFixture(t)
			homeOut := filepath.Join(f.home, "work")
			if err := os.MkdirAll(homeOut, 0o755); err != nil {
				t.Fatal(err)
			}
			table := runMountRuntimeTable(t, f, tc.fixture) + "3 1 8:2 /data " + f.out + " rw - ext4 /dev/vdb rw\n"
			for _, field := range []string{"write", "ask"} {
				t.Run(field, func(t *testing.T) {
					for _, grant := range []string{homeOut + "/", f.out + "/"} {
						code, out := f.compile(t, field, []string{grant}, table)
						if code != identity.ExitOK {
							t.Fatalf("ordinary encrypted-home grant refused: exit %d\n%s", code, out)
						}
						var want []string
						if grant == f.out+"/" {
							want = []string{runMountWarning(field, grant, f.out, ", because "+tc.fstype+" does not establish which folder holds the files it shows")}
						}
						f.wantWarnings(t, out, want)
					}
					for _, grant := range []string{f.bin + "/", filepath.Dir(f.bin) + "/"} {
						f.wantRefused(t, field, grant, table, "the tego binary")
					}
				})
			}
		})
	}
}

func TestRunStartUnplacedLayersKeepVisibleAndMalformedRefusals(t *testing.T) {
	f := newRunMountFixture(t)
	layer := filepath.Join(f.root, "layers", "visible")
	if err := os.MkdirAll(layer, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"write", "ask"} {
		t.Run(field, func(t *testing.T) {
			for _, option := range []string{
				"lowerdir=relative/lower:@HOST@/visible",
				"lowerdir=@HOST@/visible:relative/lower",
				"lowerdir+=relative/lower,lowerdir+=@HOST@/visible",
				"lowerdir=relative/lower,upperdir=@HOST@/visible,workdir=relative/work",
			} {
				t.Run(option, func(t *testing.T) {
					table := runMountRuntimeTable(t, f, "overlay-mixed-relative")
					first := strings.SplitN(table, "\n", 2)[0]
					table = strings.Replace(table, first, "1 0 0:73 / / rw - overlay overlay rw,"+strings.ReplaceAll(option, "@HOST@", filepath.Dir(layer)), 1)
					table += fmt.Sprintf("40 1 8:2 / %s rw - ext4 disk rw\n41 1 8:2 /visible %s rw - ext4 disk rw\n", filepath.Dir(layer), f.alias)
					code, out := f.compile(t, field, []string{f.out + "/"}, table)
					if code != identity.ExitOK {
						t.Fatalf("mixed absolute and relative layers refused ordinary run-start grant: exit %d\n%s", code, out)
					}
					f.wantWarnings(t, out, nil)
					for _, grant := range []string{layer + "/", f.alias + "/"} {
						f.wantRefused(t, field, grant, table, "a layer of the overlay holding tego's binaries")
					}
				})
			}
			for _, options := range []string{
				"lowerdir=relative/lower:../escape",
				"lowerdir=relative/lower:/data/link/../lower",
				"lowerdir+=relative/lower,datadir+=../escape",
				`lowerdir=relative/lower,upperdir=/data/up\134per`,
				`lowerdir=relative/lower,workdir=relative/work\134dir`,
				"lowerdir=relative/lower,upperdir=../upper",
				"lowerdir=relative/lower,workdir=../work",
			} {
				t.Run(options, func(t *testing.T) {
					malformed := "1 0 0:73 / / rw - overlay overlay rw," + options + "\n"
					why := "parent path component"
					if strings.Contains(options, `\134`) {
						why = "ambiguous overlay quoting"
					}
					f.wantRefused(t, field, f.out+"/", malformed, why)
				})
			}
		})
	}
}

// A device holding another protected binary says nothing about whether it backs
// this unplaced filesystem. Excluding both together would silently admit its backing.
func TestRunStartUnplacedBackingExcludesOnlyItsOwnDevice(t *testing.T) {
	for _, class := range []string{"encrypted home", "relative overlay"} {
		t.Run(class, func(t *testing.T) {
			f := newRunMountFixture(t)
			f.exe = filepath.Join(f.root, "image", "bin", "tego")
			homeOut := filepath.Join(f.home, "work")
			for _, dir := range []string{filepath.Dir(f.exe), homeOut} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(f.exe, []byte("not run\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			volume := filepath.Join(f.out, "b")
			table := runMountRuntimeTable(t, f, "docker-small") +
				"40 1 0:80 / " + f.home + " rw - fuse.gocryptfs encrypted rw\n"
			reason := ", because fuse.gocryptfs does not establish which folder holds the files it shows"
			ordinaryGrant, ordinaryMount := filepath.Join(f.out, "a")+"/", "/"
			if class == "relative overlay" {
				absent := filepath.Join(f.root, "absent-home")
				table = runMountRuntimeTable(t, f, "docker-many-layers") +
					"40 1 0:80 / " + f.home + " rw - overlay overlay rw,lowerdir=" + absent + "/lower,upperdir=" + absent + "/upper,workdir=" + absent + "/work\n"
				reason = ", because the layers are named relative to a folder the mount table does not record"
				ordinaryGrant, ordinaryMount = homeOut+"/", f.home
			}
			table += "41 1 8:2 /data " + volume + " rw - ext4 disk rw\n"
			for _, field := range []string{"write", "ask"} {
				t.Run(field, func(t *testing.T) {
					for _, tc := range []struct{ grant, mount string }{{ordinaryGrant, ordinaryMount}, {volume + "/", volume}} {
						code, out := f.compile(t, field, []string{tc.grant}, table)
						if code != identity.ExitOK {
							t.Fatalf("ordinary multi-binary grant refused: exit %d\n%s", code, out)
						}
						f.wantWarnings(t, out, []string{runMountWarning(field, tc.grant, tc.mount, reason)})
					}
				})
			}
		})
	}
}

func TestRunStartUnplacedBackingOnMemoryFilesystem(t *testing.T) {
	// GAPS C65 states the limit: memory filesystems stay quiet even when they hold
	// runtime storage or an encrypted backing folder also exposed through a write grant.
	for _, fixture := range []string{"docker-small", "docker-many-layers", "podman-fuse-overlayfs", "home-gocryptfs", "home-ecryptfs"} {
		t.Run(fixture, func(t *testing.T) {
			f := newRunMountFixture(t)
			for _, fs := range []string{"tmpfs", "ramfs", "hugetlbfs", "devtmpfs"} {
				t.Run(fs, func(t *testing.T) {
					table := runMountRuntimeTable(t, f, fixture) +
						"40 1 0:90 /storage " + f.out + " rw - " + fs + " memory rw\n"
					for _, field := range []string{"write", "ask"} {
						t.Run(field, func(t *testing.T) {
							grant := f.out + "/"
							code, out := f.compile(t, field, []string{grant}, table)
							if code != identity.ExitOK {
								t.Fatalf("ordinary memory-backed grant refused: exit %d\n%s", code, out)
							}
							f.wantWarnings(t, out, nil)
						})
					}
				})
			}
		})
	}
}

func TestRunStartAbsentLayersWithSecondUnplacedBinaryWarns(t *testing.T) {
	for _, fstype := range []string{"ext4", "fuse.bindfs", "fuse.gocryptfs", "ecryptfs"} {
		t.Run(fstype, func(t *testing.T) {
			f := newRunMountFixture(t)
			// The launcher is on the root overlay; the PATH binary is on the home mount.
			// Having a protected binary there does not prove the mount cannot expose the absent layers.
			f.exe = filepath.Join(f.root, "image", "bin", "tego")
			homeOut := filepath.Join(f.home, "work")
			for _, dir := range []string{filepath.Dir(f.exe), homeOut} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(f.exe, []byte("not run\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			table := runMountRuntimeTable(t, f, "docker-small") +
				"40 1 0:80 / " + f.home + " rw - " + fstype + " synthetic-source rw\n"
			reason := ""
			if fstype != "ext4" {
				reason = ", because " + fstype + " does not establish which folder holds the files it shows"
			}
			for _, field := range []string{"write", "ask"} {
				t.Run(field, func(t *testing.T) {
					grant := homeOut + "/"
					code, out := f.compile(t, field, []string{grant}, table)
					if code != identity.ExitOK {
						t.Fatalf("ordinary home grant refused: exit %d\n%s", code, out)
					}
					f.wantWarnings(t, out, []string{runMountWarning(field, grant, f.home, reason)})
				})
			}
		})
	}
}

func TestRunStartUnplacedBackingDoesNotWarnForNullDevice(t *testing.T) {
	for _, name := range []string{"docker-many-layers", "podman-fuse-overlayfs"} {
		t.Run(name, func(t *testing.T) {
			f := newRunMountFixture(t)
			table := runMountRuntimeTable(t, f, name)
			for _, field := range []string{"write", "ask"} {
				code, out := f.compile(t, field, []string{"/dev/null"}, table)
				if code != identity.ExitOK {
					t.Fatalf("null-device run-start grant refused: exit %d\n%s", code, out)
				}
				f.wantWarnings(t, out, nil)
			}
		})
	}
}
