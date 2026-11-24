// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
	"golang.org/x/sys/unix"
)

const testBoot = "01234567-89ab-cdef-0123-456789abcdef"

func TestCallerAuthorization(t *testing.T) {
	for _, tc := range []struct{ name, reason string }{
		{"ordinary", ""}, {"mismatched euid", "privilege"}, {"sudo", "privilege"}, {"capability", "privilege"},
		{"missing caps", "privilege"}, {"uid fields", "privilege"}, {"private cgroup namespace", "privilege"},
		{"unknown cgroup namespace", "privilege"}, {"governed", "governed"}, {"lookalike governed", "governed"}, {"unknown cgroup", "governed"},
		{"child pid namespace", ""}, {"unknown pid namespace", ""},
		// A nested namespace's own fresh /proc lists one NSpid entry per process, so the line proves nothing: the
		// caller's own PID namespace inode does (a root scan under unshare --pid --fork --mount-proc returned
		// "none observed" before it was read). Zero is an inode that could not be read.
		{"nested pid namespace, one NSpid entry", ""}, {"unreadable pid namespace inode", ""}, {"changed status", "privilege"}, {"missing passwd", "owner"}, {"missing boot", ""},
		// The caller's own answer to "outside every tego run?", handed in by the command line: only an outside answer
		// admits. Its zero value (inside) and unknown refuse in the kernel's first cgroup namespace too, and outside
		// it an outside answer is what admits a caller at all (a WSL distribution's shell with the rule's proof).
		{"private cgroup namespace, proven outside", ""}, {"the zero answer", "governed"}, {"an unknown answer", "governed"},
		{"an inside answer over a clean path", "governed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			home := unitFixtureRoot(t)
			if err := os.Chmod(home, 0755); err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Getuid())
			processFixture(t, root, 10, 1, 100, "/bin/test", []byte("test\x00"), 0)
			passwd := metadataFixture(t, home, "passwd", 0600)
			boot := metadataFixture(t, home, "boot", 0600)
			writeProcFile(t, home, "passwd", []byte(fmt.Sprintf("me:x:%d:42:%s:%s:/bin/sh\n", uid, markerSecret, home)))
			writeProcFile(t, home, "boot", []byte(testBoot+"\n"))
			c := Caller{UID: uid, EUID: uid, PID: 10, CgroupNamespace: runscope.InitCgroupNS, PIDNamespace: InitPIDNS, Membership: answertest.Outside()}
			status := statusFixture(uid)
			switch tc.name {
			case "mismatched euid":
				c.EUID++
			case "sudo":
				c.Sudo = true
			case "capability":
				status = bytes.Replace(status, []byte("CapEff:\t0000000000000000"), []byte("CapEff:\t0000000000000001"), 1)
			case "missing caps":
				status = []byte(fmt.Sprintf("Uid: %d %d %d %d\n", uid, uid, uid, uid))
			case "uid fields":
				status = bytes.Replace(status, []byte(fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d", uid, uid, uid, uid)), []byte(fmt.Sprintf("Uid: %d %d %d %d", uid, uid+1, uid, uid)), 1)
			case "private cgroup namespace":
				c.CgroupNamespace++
				c.Membership = runscope.Unproven(runscope.CauseUserNamespace, nil)
			case "unknown cgroup namespace":
				c.CgroupNamespace = 0
				c.Membership = runscope.Unproven(runscope.CauseNSUnreadable, nil)
			case "private cgroup namespace, proven outside":
				c.CgroupNamespace++
			case "the zero answer":
				c.Membership = runscope.Answer{}
			case "an unknown answer":
				c.Membership = runscope.Unproven(runscope.CauseProbeTimeout, nil)
			case "an inside answer over a clean path":
				c.Membership = answertest.Inside(runscope.CauseGoverned)
			case "governed":
				writeProcFile(t, root, "10/cgroup", []byte("0::/tego.slice/tego-agent.slice/run-r-0123abcd-0000000000000-abcdef.scope\n"))
			case "lookalike governed":
				writeProcFile(t, root, "10/cgroup", []byte("0::/tego.slice/tego-agent.slice/run-bad.scope\n"))
			case "unknown cgroup":
				writeProcFile(t, root, "10/cgroup", []byte("bad"))
			case "child pid namespace":
				status = bytes.Replace(status, []byte("NSpid:\t10"), []byte("NSpid:\t10 1"), 1)
			case "unknown pid namespace":
				status = bytes.Replace(status, []byte("NSpid:\t10\n"), nil, 1)
			case "nested pid namespace, one NSpid entry":
				c.PIDNamespace = InitPIDNS + 0x10000001
			case "unreadable pid namespace inode":
				c.PIDNamespace = 0
			case "missing passwd":
				passwd = filepath.Join(home, "missing")
			case "missing boot":
				boot = filepath.Join(home, "missing")
			}
			writeProcFile(t, root, "10/status", status)
			fs, err := openProc(root)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.close()
			spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}, hook: func(_ int, name string, n int, b []byte, e error) ([]byte, error) {
				if tc.name == "changed status" && name == "status" && n == 2 {
					return statusFixture(uid + 1), nil
				}
				return b, e
			}}
			got, reason := identifyCaller(context.WithValue(context.Background(), callerAccountReaderKey{}, (func(string) ([]byte, error))(fixtureCallerReader)), spy, root, passwd, boot, c)
			if reason != tc.reason {
				t.Fatalf("reason %q want %q", reason, tc.reason)
			}
			if reason == "" {
				if got.Home != home || got.GID != 42 || got.OuterNamespace != (tc.name == "child pid namespace" || tc.name == "nested pid namespace, one NSpid entry") || got.NamespaceUnknown != (tc.name == "unknown pid namespace" || tc.name == "unreadable pid namespace inode") {
					t.Fatal("identity mismatch")
				}
				if tc.name == "missing boot" {
					if got.Boot != "" || got.Sources[len(got.Sources)-1].State != "not-read" {
						t.Fatal("boot failure hidden")
					}
				} else if got.Boot != testBoot {
					t.Fatal("boot mismatch")
				}
			}
		})
	}
}

func TestParseLocalIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		ok         bool
	}{
		{"valid", "me:x:123:42:secret:/home/me:/bin/sh\n", true},
		{"missing", "me:x:456:42:secret:/home/me:/bin/sh\n", false},
		{"duplicate", "me:x:123:42::/home/me:/bin/sh\nme2:x:123:42::/home/other:/bin/sh\n", false},
		{"relative", "me:x:123:42::relative:/bin/sh\n", false},
		{"control", "me:x:123:42::/home/\x1b:/bin/sh\n", false},
		{"bad uid", "me:x:x:42::/home/me:/bin/sh\n", false},
		{"bad gid", "me:x:123:4294967295::/home/me:/bin/sh\n", false},
		{"truncated", "me:x:123:42::/home/me", false},
		{"oversized", strings.Repeat("x", (1<<20)+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parsePasswd([]byte(tc.text), 123)
			if (err == nil) != tc.ok {
				t.Fatalf("parse error %v", err)
			}
		})
	}
	for _, s := range []string{"", testBoot + "\nextra", strings.ToUpper(testBoot), strings.Repeat("a", 36), testBoot + "\r\n"} {
		if _, err := parseBoot([]byte(s)); err == nil {
			t.Fatal("bad boot accepted")
		}
	}
}

func TestLocalMetadataSpecialFiles(t *testing.T) {
	home := t.TempDir()
	path := metadataFixture(t, home, "file", 0600)
	for _, kind := range []string{"fifo", "link", "hardlink", "directory", "mode", "size"} {
		t.Run(kind, func(t *testing.T) {
			bad := filepath.Join(home, kind)
			switch kind {
			case "fifo":
				if err := unix.Mkfifo(bad, 0600); err != nil {
					t.Fatal(err)
				}
			case "link":
				if err := os.Symlink(path, bad); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, bad); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(bad)
			case "directory":
				if err := os.Mkdir(bad, 0700); err != nil {
					t.Fatal(err)
				}
			case "mode":
				metadataFixture(t, home, kind, 0600)
				if err := os.Chmod(bad, 0666); err != nil {
					t.Fatal(err)
				}
			case "size":
				metadataFixture(t, home, kind, 0600)
			}
			limit := maxProcText
			if kind == "size" {
				limit = 1
			}
			if _, err := readLocalMetadata(context.Background(), bad, limit, uint32(os.Getuid())); err == nil {
				t.Fatal("unsafe local metadata accepted")
			}
		})
	}
}

func TestDirectRootCaller(t *testing.T) {
	// Authorization can be exercised without acquiring privilege. This is not a
	// permission or initial-user-namespace proof; those checks remain guest work.
	c := Caller{UID: 0, EUID: 0, PID: 10, CgroupNamespace: runscope.InitCgroupNS, PIDNamespace: InitPIDNS, Membership: answertest.Outside()}
	st, err := parseStatus(bytes.ReplaceAll(statusFixture(0), []byte("CapEff:\t0000000000000000"), []byte("CapEff:\t0000000000000001")))
	if err != nil {
		t.Fatal(err)
	}
	if reason := callerPrivilege(c, st, 0); reason != "" {
		t.Fatal("direct root must remain scoped to uid zero")
	}
	c.Sudo = true
	if reason := callerPrivilege(c, st, 0); reason != "privilege" {
		t.Fatal("sudo not refused")
	}
}

func FuzzScanPasswd(f *testing.F) {
	f.Add([]byte("me:x:123:42:secret:/home/me:/bin/sh\n"))
	f.Add([]byte("me:x:123"))
	f.Fuzz(func(t *testing.T, b []byte) {
		home, _, err := parsePasswd(b, 123)
		if err == nil && !plainPath(home) {
			t.Fatal("invalid typed home")
		}
	})
}
func FuzzScanBoot(f *testing.F) {
	f.Add([]byte(testBoot + "\n"))
	f.Add([]byte("secret"))
	f.Fuzz(func(t *testing.T, b []byte) {
		id, err := parseBoot(b)
		if err == nil && len(id) != 36 {
			t.Fatal("invalid boot identity")
		}
	})
}

func TestCallerOwnershipRechecked(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	uid := uint32(os.Getuid())
	processFixture(t, root, 10, 1, 100, "/bin/test", []byte("test\x00"), 0)
	writeProcFile(t, home, "passwd", []byte(fmt.Sprintf("me:x:%d:42::%s:/bin/sh\n", uid, home)))
	writeProcFile(t, home, "boot", []byte(testBoot))
	fs, err := openProc(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.close()
	count := 0
	spy := &spyProc{procAccess: fs, t: t, opened: map[int]bool{}, ownerHook: func(_ int, id uint32, e error) (uint32, error) {
		count++
		if count > 1 {
			return id + 1, nil
		}
		return id, e
	}}
	c := Caller{UID: uid, EUID: uid, PID: 10, CgroupNamespace: runscope.InitCgroupNS, PIDNamespace: InitPIDNS, Membership: answertest.Outside()}
	_, reason := identifyCaller(context.Background(), spy, root, filepath.Join(home, "passwd"), filepath.Join(home, "boot"), c)
	if reason != "privilege" {
		t.Fatal("changed caller owner accepted")
	}
}

func TestCallerNamespaceHandle(t *testing.T) {
	root := t.TempDir()
	writeProcFile(t, root, "10/ns/cgroup", []byte(markerSecret))
	if _, err := CgroupNamespace(root, 10); err == nil {
		t.Fatal("ordinary file accepted as a kernel namespace handle")
	}
	if err := os.Remove(filepath.Join(root, "10/ns/cgroup")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/proc/self/ns/cgroup", filepath.Join(root, "10/ns/cgroup")); err != nil {
		t.Fatal(err)
	}
	var actual unix.Stat_t
	if err := unix.Stat("/proc/self/ns/cgroup", &actual); err != nil {
		t.Fatal(err)
	}
	got, err := CgroupNamespace(root, 10)
	if err != nil || got != actual.Ino {
		t.Fatalf("namespace metadata %d %v", got, err)
	}
}

func TestCallerPIDNamespaceHandle(t *testing.T) {
	root := t.TempDir()
	writeProcFile(t, root, "self/ns/pid", []byte(markerSecret))
	if _, err := PIDNamespace(root); err == nil {
		t.Fatal("ordinary file accepted as a kernel namespace handle")
	}
	if err := os.RemoveAll(filepath.Join(root, "self")); err != nil {
		t.Fatal(err)
	}
	if _, err := PIDNamespace(root); err == nil {
		t.Fatal("a /proc with no self (a namespace the caller is not in) answered")
	}
	if err := os.MkdirAll(filepath.Join(root, "self/ns"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/proc/self/ns/pid", filepath.Join(root, "self/ns/pid")); err != nil {
		t.Fatal(err)
	}
	var actual unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &actual); err != nil {
		t.Fatal(err)
	}
	got, err := PIDNamespace(root)
	if err != nil || got != actual.Ino {
		t.Fatalf("namespace metadata %d %v", got, err)
	}
}

// The scan command's own answer: a caller in a nested PID namespace (or one whose namespace could not be read)
// gets check unknown, exit 125 and the named exclusion, never "none observed", whatever its /proc lists. Basic and
// advanced scope share identifyCallerMode, so the basic path stands for both; the root-only advanced refusals are
// guest rows.
func TestCheckRefusesNegativeAnswerOutsideTheInitialPIDNamespace(t *testing.T) {
	for _, tc := range []struct {
		name string
		ns   uint64
		want int
	}{{"initial", InitPIDNS, 0}, {"nested", InitPIDNS + 0x10000001, 125}, {"unread", 0, 125}} {
		t.Run(tc.name, func(t *testing.T) {
			o := commandOptions(t)
			o.Check = true
			for _, outside := range []string{"20", "30"} { // no outside agent: only coverage decides
				if err := os.RemoveAll(filepath.Join(o.ProcRoot, outside)); err != nil {
					t.Fatal(err)
				}
			}
			o.Caller.PIDNamespace = tc.ns
			s := Collect(t.Context(), o).Snapshot
			if s.ExitCode() != tc.want {
				t.Fatalf("exit %d check %s status %s", s.ExitCode(), s.Check, s.Status)
			}
			if tc.want == 125 && (s.Check != "unknown" || !strings.Contains(strings.Join(s.Exclusions, ","), "outer-pid-namespace")) {
				t.Fatalf("no named reason: check %s exclusions %v", s.Check, s.Exclusions)
			}
		})
	}
}

func TestCancelledCallerDoesNoReads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fs := &generatedProc{}
	c := Caller{UID: uint32(os.Getuid()), EUID: uint32(os.Getuid()), PID: 10, CgroupNamespace: runscope.InitCgroupNS, PIDNamespace: InitPIDNS, Membership: answertest.Outside()}
	_, reason := identifyCaller(ctx, fs, "/proc", "/etc/passwd", "/proc/sys/kernel/random/boot_id", c)
	if fs.opens != 0 || reason != "deadline" {
		t.Fatal("cancelled caller still performed reads")
	}
}

// Caller identity must accept the same verified links as account evidence.
func TestCallerPasswdVerifiedLinks(t *testing.T) {
	for _, layout := range []string{"linked etc", "linked passwd", "two links"} {
		t.Run(layout, func(t *testing.T) {
			root := t.TempDir()
			home := unitFixtureRoot(t)
			if err := os.Chmod(home, 0755); err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Getuid())
			processFixture(t, root, 10, 1, 100, "/bin/test", []byte("test\x00"), 0)
			writeProcFile(t, root, "10/status", statusFixture(uid))
			fs, err := openProc(root)
			if err != nil {
				t.Fatal(err)
			}
			defer fs.close()
			if err := os.MkdirAll(filepath.Join(home, "etc"), 0755); err != nil {
				t.Fatal(err)
			}
			passwd := filepath.Join(home, "etc/passwd")
			if err := os.WriteFile(passwd, []byte(fmt.Sprintf("me:x:%d:42::%s:/bin/sh\n", uid, home)), 0644); err != nil {
				t.Fatal(err)
			}
			boot := metadataFixture(t, home, "boot", 0600)
			writeProcFile(t, home, "boot", []byte(testBoot+"\n"))
			switch layout {
			case "linked etc":
				if err := os.Rename(filepath.Join(home, "etc"), filepath.Join(home, "system-etc")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("system-etc", filepath.Join(home, "etc")); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.Rename(passwd, filepath.Join(home, "etc/target")); err != nil {
					t.Fatal(err)
				}
				target := "target"
				if layout == "two links" {
					if err := os.Symlink(target, filepath.Join(home, "etc/middle")); err != nil {
						t.Fatal(err)
					}
					target = "middle"
				}
				if err := os.Symlink(target, passwd); err != nil {
					t.Fatal(err)
				}
			}
			c := Caller{UID: uid, EUID: uid, PID: 10, CgroupNamespace: runscope.InitCgroupNS, PIDNamespace: InitPIDNS, Membership: answertest.Outside()}
			got, reason := identifyCaller(context.WithValue(context.Background(), callerAccountReaderKey{}, fixtureAccountReader(home)), fs, root, passwd, boot, c)
			if reason != "" || got.Home != home || got.GID != 42 {
				t.Fatalf("verified %s: reason %q, identity %+v", layout, reason, got)
			}
		})
	}
}

// TestOnlyAnOutsideAnswerPermits walks the one table of answers (answertest.Rows) over the scan's caller check: the
// answer the command line hands in admits the caller on outside alone, in the kernel's first cgroup namespace (where
// the caller's own path is clean here) and in any other.
func TestOnlyAnOutsideAnswerPermits(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	uid := uint32(os.Getuid())
	processFixture(t, root, 10, 1, 100, "/bin/test", []byte("test\x00"), 0)
	passwd := metadataFixture(t, home, "passwd", 0600)
	boot := metadataFixture(t, home, "boot", 0600)
	writeProcFile(t, home, "passwd", []byte(fmt.Sprintf("me:x:%d:42:x:%s:/bin/sh\n", uid, home)))
	writeProcFile(t, home, "boot", []byte(testBoot+"\n"))
	writeProcFile(t, root, "10/status", statusFixture(uid))
	fs, err := openProc(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.close()
	for _, row := range answertest.Rows() {
		for _, ns := range []uint64{runscope.InitCgroupNS, runscope.InitCgroupNS + 0x10000001, 0} {
			c := Caller{UID: uid, EUID: uid, PID: 10, CgroupNamespace: ns, PIDNamespace: InitPIDNS, Membership: row.Answer}
			_, reason := identifyCaller(context.WithValue(context.Background(), callerAccountReaderKey{}, (func(string) ([]byte, error))(fixtureCallerReader)), fs, root, passwd, boot, c)
			if admitted := reason == ""; admitted != row.Permits {
				t.Errorf("%s, cgroup namespace %d: reason %q; admitted %v", row.Name, ns, reason, admitted)
			}
			if st, err := parseStatus(statusFixture(uid)); err != nil {
				t.Fatal(err)
			} else if reason := callerPrivilege(c, st, uid); ns != runscope.InitCgroupNS && (reason == "") != row.Permits {
				t.Errorf("%s, cgroup namespace %d: callerPrivilege %q", row.Name, ns, reason)
			}
		}
	}
}
