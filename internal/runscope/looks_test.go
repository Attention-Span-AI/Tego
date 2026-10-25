// SPDX-License-Identifier: Apache-2.0

package runscope

import (
	"bytes"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestLooksGovernedRefusesLookAlike: the broad rule is true for every run GovernedBy names and for every look-alike
// of one, in anyone's subtree and at any depth, and false for the person's own cgroups, systemd-run's run-*.scope
// among them, and for tego's own helpers.
func TestLooksGovernedRefusesLookAlike(t *testing.T) {
	for cg, run := range governedByTable {
		if run != "" && !LooksGoverned(cg) {
			t.Errorf("LooksGoverned(%q) = false, but GovernedBy names run %s", cg, run)
		}
	}
	const user = "/user.slice/user-1000.slice/user@1000.service"
	for cg, want := range map[string]bool{
		// Look-alikes GovernedBy names no run in: refused all the same.
		user + "/app.slice/tego.slice/tego-a.slice/adopt-" + testRun + ".scope":              true, // an adoption's shape, not root's
		user + "/app.slice/tego.slice/run-x.scope":                                           true, // no agent slice, no run id
		user + "/tego.slice/tego-a.slice/adopt-" + testRun + ".scope":                        true,
		"/tego.slice/run-" + testRun + ".scope":                                              true,
		"/tego.slice/tego-.slice/run-" + testRun + ".scope":                                  true,
		"/tego.slice/tego-a.slice/adopt-notarunid.scope":                                     true,
		"/tego.slice/tego-a.slice/run-.scope":                                                true,
		"/tego.slice/x.slice/y/run-z.scope/sub":                                              true, // any depth below tego.slice
		"/tego.slice/tego-a.slice":                                                           true, // an agent's slice itself
		"/tego.slice/tego-a.slice/tego-a-r0a1b2c3d0123456789abcxyz123.slice/docker-c1.scope": true, // Docker, systemd driver
		"/tego.slice/tego-a.slice/anything.scope":                                            true,
		"/tego/a/notarunid":                                                                  true, // Docker, cgroupfs driver, a malformed id
		user + "/app.slice/tego/a/" + testRun + "/c1":                                        true, // a rootless daemon's cgroupfs parent
		"/../tego.slice/tego-a.slice/run-" + testRun + ".scope":                              true, // above the reader's namespace root
		"/tego.slice/../tego-a.slice/run-" + testRun + ".scope":                              true, // a ".." hides nothing
		"/tego.slice//tego-a.slice":                                                          true,
		"tego.slice/tego-a.slice/run-" + testRun + ".scope":                                  true, // relative, as a caller may hold it
		"/tego.slice/tego-a.slice/run-" + testRun + ".scope/x.scope":                         true, // a child an agent made in its scope
		// The person's own cgroups and tego's helpers: not a run's.
		"":                                    false,
		"/":                                   false,
		"/..":                                 false,
		user + "/app.slice/run-r3f2b1c.scope": false, // systemd-run --user --scope
		"/system.slice/run-u42.scope":         false, // systemd-run --scope
		user + "/app.slice/run-" + testRun + ".scope": false, // a run's scope name with no tego.slice above it
		user + "/app.slice/tego-a.slice/run-x.scope":  false,
		"/user.slice/user-1000.slice/session-2.scope": false,
		"/tego.slice":                           false,
		"/tego.slice/helpers.scope":             false, // tego's detached helpers (cgroup.HelperScope)
		"/tego/a":                               false, // a Docker parent needs its run below the agent
		"/tego.slicex/tego-a.slice/run-x.scope": false,
		"/system.slice/docker.service/" + testRun + "/c1":   false,
		"/system.slice/docker-" + testRun + ".scope":        false,
		user + "/app.slice/app-gnome-tego\\x2dui-123.scope": false,
	} {
		if got := LooksGoverned(cg); got != want {
			t.Errorf("LooksGoverned(%q) = %v, want %v", cg, got, want)
		}
	}
}

// fixture reads one of testdata/cgroup's /proc/<pid>/cgroup files.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "cgroup", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestUnifiedReadsOneV2Line: the reader takes the one "0::" line of a cgroup v2 or hybrid host and refuses every
// file that names none, several, a relative path or a removed cgroup.
func TestUnifiedReadsOneV2Line(t *testing.T) {
	for _, c := range []struct {
		file, want string
	}{
		{"v2.cgroup", "/user.slice/user-1000.slice/user@1000.service/app.slice/app-term.scope"},
		{"hybrid.cgroup", "/user.slice/user-1000.slice/session-2.scope"},
		{"run.cgroup", "/user.slice/user-1000.slice/user@1000.service/tego.slice/tego-a.slice/run-" + testRun + ".scope"},
		{"outside-ns.cgroup", "/../../user.slice/user-1000.slice/session-2.scope"},
		{"root.cgroup", "/"},
		{"v1only.cgroup", ""},
		{"two-unified.cgroup", ""},
		{"relative.cgroup", ""},
		{"deleted.cgroup", ""},
		{"empty.cgroup", ""},
	} {
		got, err := Unified(fixture(t, c.file))
		if got != c.want || (err == nil) != (c.want != "") || err != nil && !errors.Is(err, ErrCgroupFile) {
			t.Errorf("Unified(%s) = %q, %v; want %q", c.file, got, err, c.want)
		}
	}
}

// TestInRunFailsClosed: InRun is LooksGoverned of this process's cgroup, and true, with the error, whenever the file
// cannot be read or does not name one path inside this process's cgroup namespace, and whenever that namespace is
// not the initial one or cannot be read: there the path starts at the namespace's root, and a root inside a run reads
// "0::/" (root.cgroup) as the hierarchy's own root does.
func TestInRunFailsClosed(t *testing.T) {
	const otherNS = InitCgroupNS + 0x10000001 // a namespace made after boot: its inode is a dynamic one
	for _, c := range []struct {
		file    string
		in, err bool
	}{
		{"v2.cgroup", false, false},
		{"hybrid.cgroup", false, false},
		{"root.cgroup", false, false},
		{"run.cgroup", true, false},
		{"lookalike.cgroup", true, false},
		{"outside-ns.cgroup", true, true},
		{"v1only.cgroup", true, true},
		{"two-unified.cgroup", true, true},
		{"relative.cgroup", true, true},
		{"deleted.cgroup", true, true},
		{"empty.cgroup", true, true},
	} {
		in, err := inRun(fixture(t, c.file), nil, InitCgroupNS, nil)
		if in != c.in || (err != nil) != c.err {
			t.Errorf("inRun(%s) in the initial cgroup namespace = %v, %v; want %v, error %v", c.file, in, err, c.in, c.err)
		}
		if in, err := inRun(fixture(t, c.file), nil, otherNS, nil); !in || err == nil {
			t.Errorf("inRun(%s) in another cgroup namespace = %v, %v; want true with an error", c.file, in, err)
		}
		if in, err := inRun(fixture(t, c.file), nil, 0, os.ErrPermission); !in || !errors.Is(err, os.ErrPermission) {
			t.Errorf("inRun(%s) with its cgroup namespace unreadable = %v, %v; want true and the stat's error", c.file, in, err)
		}
	}
	if in, err := inRun(nil, os.ErrPermission, InitCgroupNS, nil); !in || !errors.Is(err, os.ErrPermission) {
		t.Errorf("inRun of an unreadable file = %v, %v; want true and the read's error", in, err)
	}
	// This test process is no run's; under `tego run` it is one, and InRun must say so either way without an error,
	// unless it runs in a cgroup namespace of its own (a container), where it is true with the error.
	b, err := os.ReadFile(selfCgroup)
	if err != nil {
		t.Skipf("no %s here: %v", selfCgroup, err)
	}
	ns, nsErr := cgroupNSInode(selfCgroupNS)
	cg, uerr := Unified(b)
	in, err := InRun()
	switch {
	case nsErr != nil || ns != InitCgroupNS:
		if !in || err == nil {
			t.Errorf("InRun() = %v, %v in cgroup namespace %d (%v), not the initial one", in, err, ns, nsErr)
		}
	case uerr == nil && (err != nil || in != LooksGoverned(cg)):
		t.Errorf("InRun() = %v, %v for this process's cgroup %q", in, err, cg)
	}
}

// FuzzUnified: the reader never panics, and what it returns is an absolute path on one line.
func FuzzUnified(f *testing.F) {
	for _, s := range []string{"0::/a\n", "0::/a\n0::/b\n", "1:name=systemd:/x\n0::/y", "0::", "0::/x (deleted)", ""} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := Unified(b)
		if err == nil && (!strings.HasPrefix(got, "/") || strings.Contains(got, "\n")) {
			t.Fatalf("Unified(%q) = %q", b, got)
		}
	})
}

// FuzzLooksGovernedCoversGovernedBy: whatever path GovernedBy names a run in, LooksGoverned refuses, so a
// refusal read from the broad rule never admits a run a strict one names.
func FuzzLooksGovernedCoversGovernedBy(f *testing.F) {
	for cg := range governedByTable {
		f.Add(cg)
	}
	f.Add("/x/../tego/a/" + testRun)
	f.Add("/tego.slice/b/../tego-a.slice/run-" + testRun + ".scope")
	f.Fuzz(func(t *testing.T, cg string) {
		if run := GovernedBy(cg); run != "" && !LooksGoverned(cg) {
			t.Fatalf("GovernedBy(%q) = %s, but LooksGoverned is false", cg, run)
		}
	})
}

// TestImportsOnlyTheLeafSet: the package's own files import the standard library and pkg/spec/identity, nothing
// else (depguard runscope-is-a-leaf says the same), so every socket of the engine and of the dashboard can link
// the one rule.
func TestImportsOnlyTheLeafSet(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") && p != "github.com/attention-span-ai/tego/pkg/spec/identity" {
				t.Errorf("%s imports %s", name, p)
			}
		}
	}
	if checked < 3 {
		t.Fatalf("checked %d files, want doc.go, governed.go and looks.go", checked)
	}
}

// inRunChildEnv makes this test binary TestInRunInACgroupNamespaceHelper's child, which prints what InRun says.
const inRunChildEnv = "TEGO_RUNSCOPE_INRUN_CHILD"

// TestInRunInACgroupNamespaceHelper is TestInRunInACgroupNamespace's child: it prints InRun's answer and error, and
// whether it could read its own cgroup namespace's inode.
func TestInRunInACgroupNamespaceHelper(t *testing.T) {
	if os.Getenv(inRunChildEnv) != "1" {
		t.Skip("helper process for TestInRunInACgroupNamespace")
	}
	b, _ := os.ReadFile(selfCgroup)
	_, nsErr := cgroupNSInode(selfCgroupNS)
	in, err := InRun()
	fmt.Printf("inrun-report in=%v nsread=%v err=%q cgroup=%q\n", in, nsErr == nil, fmt.Sprint(err), b)
}

// TestInRunInACgroupNamespace: a process in a cgroup namespace of its own reads its cgroup relative to that
// namespace's root ("0::/" at the root), so it cannot see whether a run's scope lies above it: an agent that
// unshares one inside its run's scope reads just that. InRun is true there, with the error, wherever the namespace's
// root is (here: this test's own cgroup, no run's). The child runs unmapped in its user namespace and as its root:
// where its own namespace file can be read (as root of it, unless an LSM denies the read), the error is the
// namespace's inode, and where it cannot, the stat's.
func TestInRunInACgroupNamespace(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self := []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
	selfGID := []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
	for _, c := range []struct {
		name string
		attr *syscall.SysProcAttr
	}{
		{"unmapped", &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWCGROUP}},
		{"root of its user namespace", &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWCGROUP,
			UidMappings: self, GidMappings: selfGID}},
	} {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(exe, "-test.run=^TestInRunInACgroupNamespaceHelper$", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), inRunChildEnv+"=1")
			cmd.SysProcAttr = c.attr
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			var ee *exec.ExitError
			if err != nil && !errors.As(err, &ee) {
				// The clone or the id maps were refused: no user namespace here, so the child never ran.
				t.Skipf("no user and cgroup namespace to start the child in: %v", err)
			}
			if err != nil {
				t.Fatalf("child: %v\n%s%s", err, out, stderr.Bytes())
			}
			for line := range strings.SplitSeq(string(out), "\n") {
				rest, ok := strings.CutPrefix(line, "inrun-report ")
				if !ok {
					continue
				}
				t.Log(rest)
				if !strings.HasPrefix(rest, "in=true ") || strings.Contains(rest, `err="<nil>"`) ||
					strings.Contains(rest, " nsread=true ") && !strings.Contains(rest, "not the initial one") {
					t.Errorf("InRun in a cgroup namespace of its own: %s; want true with an error, the namespace's when it was read", rest)
				}
				return
			}
			t.Fatalf("the child printed no report:\n%s%s", out, stderr.Bytes())
		})
	}
}
