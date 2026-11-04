// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The static test binary is also the agent: an attached profile must not prevent a
// dynamic loader from starting before the open under test can be attempted.
func init() {
	if len(os.Args) != 3 || (os.Args[1] != "--held-label-agent" && os.Args[1] != "--held-label-selinux-agent") {
		return
	}
	if os.Args[1] == "--held-label-selinux-agent" {
		runtime.LockOSThread()
		if err := os.WriteFile(fmt.Sprintf("/proc/%d/attr/fscreate", unix.Gettid()), []byte("user_u:object_r:restricted_t"), 0); err != nil {
			fmt.Println("SETUP fscreate", err)
			os.Exit(2)
		}
	}

	path := os.Args[2]
	result := make(map[string]int)
	for name, flags := range map[string]int{"read": unix.O_RDONLY, "truncate": unix.O_WRONLY | unix.O_TRUNC,
		"create": unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL} {
		p := path
		if name == "create" {
			p += ".new"
		}
		fd, err := unix.Open(p, flags|unix.O_CLOEXEC, 0o600)
		result[name] = 0
		if err != nil {
			result[name] = -1
			if errno, ok := err.(unix.Errno); ok {
				result[name] = int(errno)
			}
		}
		if err == nil {
			_ = unix.Close(fd)
		}
	}
	b, _ := json.Marshal(result)
	fmt.Printf("LABEL-RESULT %s\n", b)
	os.Exit(0)
}

// An exec attachment confines only the agent, after its deputy was started. A
// direct open proves the profile denies the file; held opens must not acquire it
// with the deputy's authority, including destructive opens before ADDFD fails.
func TestIntegrationHeldOpenRespectsAppArmor(t *testing.T) { testHeldOpenAppArmor(t, false, false) }

func TestIntegrationHeldOpenRespectsAppArmorWithoutLSMList(t *testing.T) {
	testHeldOpenAppArmor(t, true, false)
}

func TestIntegrationHeldOpenSameAppArmorProfileWithoutLSMList(t *testing.T) {
	testHeldOpenAppArmor(t, true, true)
}

func testHeldOpenAppArmor(t *testing.T, maskLSM, shared bool) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root only: loads a disposable AppArmor profile")
	}
	lsms, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(","+strings.TrimSpace(string(lsms))+",", ",apparmor,") {
		t.Skip("AppArmor is not active")
	}
	if maskLSM {
		if _, err := sys.LSMListModules(); err != nil {
			t.Skip("masked-list control requires lsm_list_modules: " + err.Error())
		}
	}
	parser, err := exec.LookPath("apparmor_parser")
	if err != nil {
		t.Fatal("AppArmor regression needs apparmor_parser: ", err)
	}
	c := newCrossOwner(t, "ilabel")
	bin := filepath.Join(t.TempDir(), "tego")
	build := exec.Command("go", "build", "-tags", "tegobpf,tegotesthooks", "-o", bin, "github.com/attention-span-ai/tego/cmd/tego")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build tego: %v\n%s", err, out)
	}
	agentReaches(t, bin)
	c.bin = bin
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	actor := filepath.Join(c.f.out, "label-agent")
	plain := filepath.Join(c.f.out, "plain-agent")
	for _, p := range []string{actor, plain} {
		if err := os.WriteFile(p, body, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(c.f.out, "mac-secret")
	profile := fmt.Sprintf("tego-held-label-%d", os.Getpid())
	policy := filepath.Join(c.f.dir, "apparmor.policy")
	text := fmt.Sprintf("profile %s %q flags=(attach_disconnected) {\n /** rwmlkix,\n signal,\n ptrace,\n network,\n deny %q rw,\n deny %q rw,\n}\n", profile, actor, secret, secret+".new")
	sharedProfile := profile + "-shared"
	if shared {
		// Exec-attach the supervisor itself: its deputy and plain agent inherit this
		// same named profile. The root-path exec rule also covers sealed executable
		// FDs, which AppArmor with attach_disconnected can name "/".
		// No securityfs-list visibility is needed for discovery.
		text += fmt.Sprintf("profile %s %q flags=(attach_disconnected) {\n / rwmlkix,\n /** rwmlkix,\n capability,\n signal,\n ptrace,\n network,\n mount,\n umount,\n userns,\n}\n", sharedProfile, bin)
	}
	if err := os.WriteFile(policy, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(parser, "-a", policy).CombinedOutput(); err != nil {
		t.Fatalf("load AppArmor profile: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command(parser, "-R", policy).CombinedOutput(); err != nil {
			t.Errorf("remove AppArmor profile: %v\n%s", err, out)
		}
	})
	for _, tier := range []string{"landlock", "cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			testutil.RequireTier(t, c.doctorRequire(t, tier), tier)
			for _, mode := range []string{"direct", "held", "gate"} {
				for _, confined := range []bool{false, true} {
					if shared && confined {
						continue
					}
					t.Run(fmt.Sprintf("%s/confined=%t", mode, confined), func(t *testing.T) {
						if err := os.WriteFile(secret, []byte("preserve-me"), 0o644); err != nil {
							t.Fatal(err)
						}
						if err := os.Remove(secret + ".new"); err != nil && !os.IsNotExist(err) {
							t.Fatal(err)
						}
						agentOwns(t, secret)
						program := plain
						if confined {
							program = actor
						}
						contract := contractFor("ilabel", []string{program, "--held-label-agent", secret}, []string{program})
						reads := mode
						if reads == "gate" {
							reads = "direct"
							contract += "gate:\n  completion: held\n  rules:\n    - 'fs.read matches \"*.never\"': 90\n    - 'fs.write outside worktree': 90\n"
						}
						contract = strings.Replace(contract, "tier: landlock", "tier: "+tier, 1)
						contract = strings.Replace(contract, "fs:\n", "fs:\n  deny_read: []\n  deny_write: []\n  reads: "+reads+"\n", 1)
						if err := os.WriteFile(filepath.Join(c.f.dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
							t.Fatal(err)
						}
						cmd := c.command(t, false, "run", filepath.Join(c.f.dir, "agent.yaml"))
						if maskLSM {
							unshare, err := exec.LookPath("unshare")
							if err != nil {
								t.Fatal(err)
							}
							// Mask only the active-list file, as containers can do. Namespace depth
							// remains available: hiding that too cannot prove a complete AA stack.
							cmd.Args = append([]string{unshare, "--mount", "--", "/bin/sh", "-c", `mount --make-rprivate / && mount --bind /dev/null /sys/kernel/security/lsm && exec "$@"`, "mask-lsm"}, cmd.Args...)
							cmd.Path = unshare
						}

						if shared {
							if err := cmd.Start(); err != nil {
								t.Fatal(err)
							}
							// Observe the supervisor's actual kernel label from the root namespace.
							// Its helper and plain agent inherit it through ix, with no transition rule.
							seen := false
							deadline := time.Now().Add(5 * time.Second)
							for time.Now().Before(deadline) {
								label, err := os.ReadFile(fmt.Sprintf("/proc/%d/attr/apparmor/current", cmd.Process.Pid))
								if err == nil && strings.TrimSpace(string(label)) == sharedProfile+" (enforce)" {
									seen = true
									break
								}
								time.Sleep(time.Millisecond)
							}
							err := cmd.Wait()
							if !seen || err != nil || strings.Contains(output(cmd), "[held-unavailable]") {
								t.Fatalf("shared supervisor label seen=%t, run=%v\n%s", seen, err, output(cmd))
							}
						} else if err := cmd.Run(); err != nil {
							t.Fatalf("run: %v\n%s", err, output(cmd))
						}
						_, report, ok := strings.Cut(output(cmd), "LABEL-RESULT ")
						if !ok {
							t.Fatalf("agent did not report:\n%s", output(cmd))
						}
						var got map[string]int
						if err := json.Unmarshal([]byte(strings.SplitN(report, "\n", 2)[0]), &got); err != nil {
							t.Fatal(err)
						}
						if len(got) != 3 {
							t.Fatalf("incomplete agent report: %v", got)
						}
						want := 0
						if confined {
							want = int(unix.EACCES)
						}
						for op, errno := range got {
							if errno != want {
								t.Errorf("%s errno=%d, want %d\n%s", op, errno, want, output(cmd))
							}
						}
						if confined {
							if b, err := os.ReadFile(secret); err != nil || string(b) != "preserve-me" {
								t.Errorf("confined truncate changed file: %q, %v", b, err)
							}
							if _, err := os.Stat(secret + ".new"); !os.IsNotExist(err) {
								t.Errorf("confined create happened: %v", err)
							}
							if mode != "direct" {
								seen := false
								dirs := runDirs(t, c.f.root)
								for _, ev := range events(t, dirs[len(dirs)-1]) {
									if ev.Kind == record.KindFS && ev.Verdict == record.VerdictRefused && ev.Rule == "held-label-differs" {
										var p struct{ Path string }
										if err := json.Unmarshal(ev.Payload, &p); err != nil {
											t.Fatal(err)
										}
										seen = seen || p.Path == secret
									}
								}
								if !seen {
									t.Error("no held-label-differs refusal in ledger")
								}
							}
						}
					})
				}
			}
		})
	}
}

// Unlike an exec domain transition, fscreate changes without changing current.
// Exercise an actual held create, not only the authority reader, under enforcing
// SELinux. The disposable policy permits the default context and denies creation
// with restricted_t; a deputy retaining its default must never create the leaf.
func TestIntegrationHeldCreateRespectsSELinux(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root only: disposable SELinux policy guest")
	}
	current, err := os.ReadFile("/proc/self/attr/current")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSuffix(string(current), "\x00") != "user_u:base_r:base_t" {
		t.Skip("needs the disposable SEC08 SELinux policy guest")
	}
	enforcing, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil || string(enforcing) != "1" {
		t.Fatalf("SELinux must enforce: %q %v", enforcing, err)
	}
	c := newCrossOwner(t, "icreatelabel")
	bin := filepath.Join(t.TempDir(), "tego")
	build := exec.Command("go", "build", "-tags", "tegobpf,tegotesthooks", "-o", bin, "github.com/attention-span-ai/tego/cmd/tego")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	agentReaches(t, bin)
	c.bin = bin
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	actor := filepath.Join(c.f.out, "create-agent")
	if err := os.WriteFile(actor, body, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tier := range []string{"landlock", "cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			testutil.RequireTier(t, c.doctorRequire(t, tier), tier)
			for _, held := range []bool{false, true} {
				t.Run(fmt.Sprintf("held=%t", held), func(t *testing.T) {
					secret := filepath.Join(c.f.out, fmt.Sprintf("create-%s-%t", tier, held))
					if err := os.WriteFile(secret, []byte("truncate permitted"), 0o644); err != nil {
						t.Fatal(err)
					}
					agentOwns(t, secret)
					contract := contractFor("icreatelabel", []string{actor, "--held-label-selinux-agent", secret}, []string{actor})
					contract = strings.Replace(contract, "tier: landlock", "tier: "+tier, 1)
					// Permit the task's own creation-attribute write. The regression exercises
					// a host security restriction independently of the contract's path floor.
					contract = strings.Replace(contract, `write: ["./out/"]`, fmt.Sprintf("write: [%q, \"/proc/\"]", c.f.out), 1)
					contract = strings.Replace(contract, "fs:\n", "fs:\n  deny_read: []\n  deny_write: []\n", 1)
					if held {
						contract += "gate:\n  completion: held\n  rules:\n    - 'fs.read matches \"*.never\"': 90\n    - 'fs.write outside worktree': 90\n"
					}
					if err := os.WriteFile(filepath.Join(c.f.dir, "agent.yaml"), []byte(contract), 0o644); err != nil {
						t.Fatal(err)
					}
					cmd := c.command(t, false, "run", filepath.Join(c.f.dir, "agent.yaml"))
					// A root worktree makes the write predicate false for both the proc
					// attribute and the test leaf, while its static kind still holds writes.
					cmd.Dir = "/"

					if err := cmd.Run(); err != nil {
						t.Fatalf("run: %v\n%s", err, output(cmd))
					}
					_, report, ok := strings.Cut(output(cmd), "LABEL-RESULT ")
					if !ok {
						t.Fatalf("no report: %s", output(cmd))
					}
					var got map[string]int
					if err := json.Unmarshal([]byte(strings.SplitN(report, "\n", 2)[0]), &got); err != nil {
						t.Fatal(err)
					}
					if len(got) != 3 || got["read"] != 0 || got["truncate"] != 0 || got["create"] != int(unix.EACCES) {
						t.Errorf("operations=%v\n%s", got, output(cmd))
					}
					if _, err := os.Stat(secret + ".new"); !os.IsNotExist(err) {
						t.Errorf("create happened: %v", err)
					}
					if held {
						seen := false
						dirs := runDirs(t, c.f.root)
						for _, ev := range events(t, dirs[len(dirs)-1]) {
							seen = seen || (ev.Kind == record.KindFS && ev.Rule == "held-label-differs" && ev.Verdict == record.VerdictRefused)
						}
						if !seen {
							t.Error("no creation-attribute refusal in ledger")
						}
					}
				})
			}
		})
	}
}
