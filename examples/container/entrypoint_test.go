// SPDX-License-Identifier: Apache-2.0

package container

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// entrypoint is the script under test, sourced as a library (TEGO_ENTRYPOINT_LIB=1) so each function runs alone.
const entrypoint = "tego-entrypoint.sh"

// fakeSelf stands for the entrypoint's own pid: the stand-in tree records what is written, it moves nothing.
const fakeSelf = "4242"

// lib runs body in bash after sourcing the entrypoint, with chown and mount replaced by functions that log their
// arguments to <dir>/calls (chown to another uid needs root; mount is the remount the test must not make). It
// returns stdout, stderr and the exit code.
func lib(t *testing.T, dir, body string, env ...string) (string, string, int) {
	t.Helper()
	script := `set -euo pipefail
TEGO_ENTRYPOINT_LIB=1 source "$ENTRYPOINT"
calls="$CALLS"
chown() { printf 'chown %s\n' "$*" >>"$calls"; }
mount() { printf 'mount %s\n' "$*" >>"$calls"; return "${FAKE_MOUNT_RC:-32}"; }
sleep() { :; }
` + body
	abs, err := filepath.Abs(entrypoint)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), append([]string{"ENTRYPOINT=" + abs, "CALLS=" + filepath.Join(dir, "calls")}, env...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("bash: %v", err)
	}
	return out.String(), errb.String(), code
}

// cgroupTree makes a stand-in for a container's cgroup2 mount as the kernel shows it after the entrypoint's mkdirs:
// each cgroup directory with the interface files a mkdir gives it, the root offering cpu, memory and pids. procs is
// the root's cgroup.procs. It returns the mount and the user@<uid>.service path.
func cgroupTree(t *testing.T, uid, procs string) (mount, svc string) {
	t.Helper()
	mount = filepath.Join(t.TempDir(), "cgroup")
	svc = filepath.Join(mount, "user.slice", "user-"+uid+".slice", "user@"+uid+".service")
	for _, d := range []string{mount, filepath.Join(mount, "init"), filepath.Dir(filepath.Dir(svc)), filepath.Dir(svc), svc,
		filepath.Join(svc, "init.scope")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{"cgroup.procs", "cgroup.subtree_control", "cgroup.threads", "cgroup.controllers"} {
			if err := os.WriteFile(filepath.Join(d, f), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(mount, "cgroup.controllers"), []byte("cpu memory pids io\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mount, "cgroup.procs"), []byte(procs), 0o644); err != nil {
		t.Fatal(err)
	}
	return mount, svc
}

// procFile writes a /proc/self/cgroup stand-in naming path in the unified hierarchy.
func procFile(t *testing.T, path string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(p, []byte("0::"+path+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestEntrypointDelegatesTheSystemdShape: on a container's first start (its own namespace root, "0::/") the subtree
// tego's Detect and CanPlace accept is built: the entrypoint goes into user@<uid>.service/init.scope, the service has
// cpu, memory and pids for its children, and exactly the directory and the three files systemd's Delegate= hands over
// are the user's, with the leaf the entrypoint sits in.
func TestEntrypointDelegatesTheSystemdShape(t *testing.T) {
	uid := "10001"
	mount, svc := cgroupTree(t, uid, "")
	dir := t.TempDir()
	_, stderr, code := lib(t, dir, `setup_cgroup "$MOUNT" "$PROCFILE" 10001 10002 `+fakeSelf+` yes`,
		"MOUNT="+mount, "PROCFILE="+procFile(t, "/"))
	if code != 0 {
		t.Fatalf("setup_cgroup: exit %d\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "cgroup subtree delegated to tego: "+svc) {
		t.Errorf("stderr does not name the delegated subtree %s:\n%s", svc, stderr)
	}
	if strings.Contains(stderr, "could not enable") {
		t.Errorf("a controller was not enabled:\n%s", stderr)
	}
	if got := strings.TrimSpace(readFile(t, filepath.Join(svc, "init.scope", "cgroup.procs"))); got != fakeSelf {
		t.Errorf("init.scope/cgroup.procs = %q, want the entrypoint's pid %s", got, fakeSelf)
	}
	// Each controller goes in by its own write; the stand-in keeps the last one, pids.
	for _, d := range []string{mount, filepath.Join(mount, "user.slice"), filepath.Dir(svc), svc} {
		if got := strings.TrimSpace(readFile(t, filepath.Join(d, "cgroup.subtree_control"))); got != "+pids" {
			t.Errorf("%s/cgroup.subtree_control = %q, want the controller writes to end with +pids", d, got)
		}
	}
	calls := readFile(t, filepath.Join(dir, "calls"))
	want := "chown 10001:10002 " + svc + " " + svc + "/cgroup.procs " + svc + "/cgroup.subtree_control " + svc + "/cgroup.threads\n" +
		"chown 10001:10002 " + svc + "/init.scope " + svc + "/init.scope/cgroup.procs\n"
	if calls != want {
		t.Errorf("chown calls:\n%s\nwant:\n%s", calls, want)
	}
}

// TestEntrypointSkipsControllersAlreadyOn: a controller the parent already offers its children is not written again.
func TestEntrypointSkipsControllersAlreadyOn(t *testing.T) {
	mount, _ := cgroupTree(t, "10001", "")
	if err := os.WriteFile(filepath.Join(mount, "cgroup.subtree_control"), []byte("cpu memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := lib(t, t.TempDir(), `enable_controllers "$MOUNT"`, "MOUNT="+mount)
	if code != 0 {
		t.Fatalf("enable_controllers: exit %d\n%s", code, stderr)
	}
	if got := readFile(t, filepath.Join(mount, "cgroup.subtree_control")); got != "cpu memory pids\n" {
		t.Errorf("cgroup.subtree_control rewritten to %q", got)
	}
}

// TestEntrypointJoinsOnExec: a later process of the same container, started where the first start moved PID 1
// (/init), joins the subtree that start built instead of building another.
func TestEntrypointJoinsOnExec(t *testing.T) {
	mount, svc := cgroupTree(t, "10001", "")
	_, stderr, code := lib(t, t.TempDir(), `setup_cgroup "$MOUNT" "$PROCFILE" 10001 10001 `+fakeSelf+` yes`,
		"MOUNT="+mount, "PROCFILE="+procFile(t, "/init"))
	if code != 0 || !strings.Contains(stderr, "joined the cgroup subtree") {
		t.Fatalf("setup_cgroup from /init: exit %d, want a join:\n%s", code, stderr)
	}
	if got := strings.TrimSpace(readFile(t, filepath.Join(svc, "init.scope", "cgroup.procs"))); got != fakeSelf {
		t.Errorf("init.scope/cgroup.procs = %q, want %s", got, fakeSelf)
	}
	if got := readFile(t, filepath.Join(mount, "cgroup.subtree_control")); got != "" {
		t.Errorf("a join wrote the root's cgroup.subtree_control: %q", got)
	}
}

// TestEntrypointRefuses: every case where the entrypoint must not build the subtree, with the reason it gives, its
// exit under TEGO_DELEGATE=yes (1) and auto (0), and the tree left as it was.
func TestEntrypointRefuses(t *testing.T) {
	cases := []struct {
		name, own, want string
		prep            func(t *testing.T, mount string)
		root            bool // the case relies on a file mode root ignores
	}{
		{name: "the host's cgroup namespace", own: "/system.slice/docker-0123.scope", want: "shares a cgroup namespace"},
		{name: "a cgroup outside the namespace", own: "/../../user.slice", want: "shares a cgroup namespace"},
		{name: "a /proc/self/cgroup with no unified line", own: "", want: "shares a cgroup namespace (it sits at an unnamed cgroup)"},
		{name: "a hierarchy that is not cgroup v2", own: "/", want: "is not a cgroup v2 hierarchy", prep: func(t *testing.T, mount string) {
			if err := os.Remove(filepath.Join(mount, "cgroup.controllers")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "a read-only mount that cannot be remounted", own: "/", want: "is read-only and could not be remounted", root: true,
			prep: func(t *testing.T, mount string) {
				if err := os.Chmod(filepath.Join(mount, "cgroup.subtree_control"), 0o444); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "processes that never leave the root", own: "/", want: "still in the namespace root after 5 passes: 1 7"},
	}
	for _, c := range cases {
		for _, mode := range []string{"yes", "auto"} {
			t.Run(c.name+"/"+mode, func(t *testing.T) {
				if c.root && os.Geteuid() == 0 {
					t.Skip("root writes a 0444 file, so the stand-in cannot be read-only")
				}
				procs := ""
				if strings.HasPrefix(c.name, "processes") {
					procs = "1\n7\n"
				}
				mount, svc := cgroupTree(t, "10001", procs)
				// The subtree is not there yet: only a first start or a join may find one.
				if err := os.RemoveAll(filepath.Join(mount, "user.slice")); err != nil {
					t.Fatal(err)
				}
				if c.prep != nil {
					c.prep(t, mount)
				}
				pf := filepath.Join(t.TempDir(), "cgroup")
				body := ""
				if c.own != "" {
					body = "0::" + c.own + "\n"
				}
				if err := os.WriteFile(pf, []byte("1:name=systemd:/x\n"+body), 0o644); err != nil {
					t.Fatal(err)
				}
				_, stderr, code := lib(t, t.TempDir(), `setup_cgroup "$MOUNT" "$PROCFILE" 10001 10001 `+fakeSelf+` `+mode,
					"MOUNT="+mount, "PROCFILE="+pf)
				wantCode := map[string]int{"yes": 1, "auto": 0}[mode]
				if code != wantCode {
					t.Errorf("exit %d, want %d", code, wantCode)
				}
				if !strings.Contains(stderr, c.want) || !strings.Contains(stderr, "tego run will refuse to start") {
					t.Errorf("stderr does not say %q and what it means:\n%s", c.want, stderr)
				}
				if _, err := os.Stat(svc); err == nil {
					t.Errorf("%s was made", svc)
				}
			})
		}
	}
}

// TestEntrypointRemountsTheMountOnly: a read-only cgroup mount is remounted with bind first, which changes only that
// mount's flag, then plainly; a writable one is left alone.
func TestEntrypointRemountsTheMountOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a 0444 file, so the stand-in cannot be read-only")
	}
	mount, _ := cgroupTree(t, "10001", "")
	dir := t.TempDir()
	if _, stderr, code := lib(t, dir, `make_writable "$MOUNT"`, "MOUNT="+mount); code != 0 {
		t.Fatalf("writable mount: exit %d\n%s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "calls")); err == nil {
		t.Errorf("a writable mount was remounted: %s", readFile(t, filepath.Join(dir, "calls")))
	}
	if err := os.Chmod(filepath.Join(mount, "cgroup.subtree_control"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, _, code := lib(t, dir, `make_writable "$MOUNT"`, "MOUNT="+mount); code == 0 {
		t.Error("make_writable succeeded on a mount that stayed read-only")
	}
	want := "mount -o remount,bind,rw " + mount + "\nmount -o remount,rw " + mount + "\n"
	if got := readFile(t, filepath.Join(dir, "calls")); got != want {
		t.Errorf("mount calls:\n%s\nwant:\n%s", got, want)
	}
}

// TestEntrypointRootLauncher: TEGO_LAUNCHER=root prepares only the namespace root (emptied, its controllers on),
// where a root tego makes tego.slice, builds no user subtree, and on a later exec from /init has nothing to do.
func TestEntrypointRootLauncher(t *testing.T) {
	mount, _ := cgroupTree(t, "10001", "")
	if err := os.RemoveAll(filepath.Join(mount, "user.slice")); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := lib(t, t.TempDir(), `setup_cgroup "$MOUNT" "$PROCFILE" 10001 10001 `+fakeSelf+` yes root`,
		"MOUNT="+mount, "PROCFILE="+procFile(t, "/"))
	if code != 0 || !strings.Contains(stderr, "emptied into "+mount+"/init for a root launcher") {
		t.Fatalf("root launcher: exit %d:\n%s", code, stderr)
	}
	if got := strings.TrimSpace(readFile(t, filepath.Join(mount, "cgroup.subtree_control"))); got != "+pids" {
		t.Errorf("root cgroup.subtree_control = %q, want the controller writes to end with +pids", got)
	}
	if _, err := os.Stat(filepath.Join(mount, "user.slice")); err == nil {
		t.Error("the root launcher built a user subtree")
	}
	if err := os.WriteFile(filepath.Join(mount, "cgroup.subtree_control"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, stderr, code = lib(t, t.TempDir(), `setup_cgroup "$MOUNT" "$PROCFILE" 10001 10001 `+fakeSelf+` yes root`,
		"MOUNT="+mount, "PROCFILE="+procFile(t, "/init"))
	if code != 0 || stderr != "" || readFile(t, filepath.Join(mount, "cgroup.subtree_control")) != "" {
		t.Errorf("root launcher from /init: exit %d, stderr %q; want 0, silence and nothing written", code, stderr)
	}
}

// TestEntrypointModes: TEGO_DELEGATE=no touches nothing, and a value it does not know is an error of its own.
func TestEntrypointModes(t *testing.T) {
	mount, _ := cgroupTree(t, "10001", "")
	if _, stderr, code := lib(t, t.TempDir(), `setup_cgroup "$MOUNT" /nonexistent 10001 10001 1 no`, "MOUNT="+mount); code != 0 || stderr != "" {
		t.Errorf("no: exit %d, stderr %q; want 0 and nothing said", code, stderr)
	}
	_, stderr, code := lib(t, t.TempDir(), `setup_cgroup "$MOUNT" /nonexistent 10001 10001 1 maybe`, "MOUNT="+mount)
	if code != 2 || !strings.Contains(stderr, "want auto, yes or no") {
		t.Errorf("maybe: exit %d, stderr %q; want 2 and the three values", code, stderr)
	}
}

// TestEntrypointAsAnotherUserRunsTheCommand: started as a user other than root (compose's `user:`, how tego-control
// serve runs), the entrypoint sets nothing up and runs the command as given.
func TestEntrypointAsAnotherUserRunsTheCommand(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the entrypoint sets the container up and drops to the tego user")
	}
	out, err := exec.Command("bash", entrypoint, "echo", "as given", strconv.Itoa(os.Geteuid())).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if want := "as given " + strconv.Itoa(os.Geteuid()) + "\n"; string(out) != want {
		t.Errorf("output %q, want %q", out, want)
	}
}

// TestEntrypointOwnCgroup: the unified line is read from a /proc/<pid>/cgroup with v1 lines before it.
func TestEntrypointOwnCgroup(t *testing.T) {
	pf := filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(pf, []byte("12:pids:/a\n1:name=systemd:/b\n0::/init\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, stderr, code := lib(t, t.TempDir(), `own_cgroup "$PROCFILE"`, "PROCFILE="+pf)
	if code != 0 || out != "/init\n" {
		t.Errorf("own_cgroup: %q, exit %d, %s; want /init", out, code, stderr)
	}
}
